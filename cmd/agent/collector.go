package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	log "github.com/cihub/seelog"

	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

type checkPayload struct {
	messages  []model.MessageBody
	endpoint  string
	timestamp time.Time
}

// Collector will collect metrics from the local system and ship to the backend.
type Collector struct {
	send          chan checkPayload
	rtIntervalCh  chan time.Duration
	cfg           *config.AgentConfig
	httpClient    http.Client
	groupID       int32
	runCounter    int32
	enabledChecks []checks.Check
	// Channel to send data to each running check, currently only to broadcast features
	featuresChs []chan features.Features

	// Controls the real-time interval, can change live.
	realTimeInterval time.Duration
	// Set to 1 if enabled 0 is not. We're using an integer
	// so we can use the sync/atomic for thread-safe access.
	realTimeEnabled int32
}

// NewCollector creates a new Collector
func NewCollector(cfg *config.AgentConfig) (Collector, error) {
	sysInfo, err := checks.CollectSystemInfo(cfg)
	if err != nil {
		return Collector{}, err
	}

	enabledChecks := make([]checks.Check, 0)
	for _, c := range checks.All {
		if cfg.CheckIsEnabled(c.Name()) {
			c.Init(cfg, sysInfo)
			enabledChecks = append(enabledChecks, c)
		}
	}

	return Collector{
		send:          make(chan checkPayload, cfg.QueueSize),
		rtIntervalCh:  make(chan time.Duration),
		cfg:           cfg,
		groupID:       rand.Int31(),
		httpClient:    http.Client{Timeout: HTTPTimeout, Transport: cfg.Transport},
		enabledChecks: enabledChecks,

		// Defaults for real-time on start
		realTimeInterval: 2 * time.Second,
		realTimeEnabled:  0,
	}, nil
}

func (l *Collector) runCheck(c checks.Check, features features.Features) {
	runCounter := atomic.AddInt32(&l.runCounter, 1)
	currentTime := time.Now()
	// update the last collected timestamp for info
	updateLastCollectTime(currentTime)
	messages, err := c.Run(l.cfg, features, atomic.AddInt32(&l.groupID, 1), currentTime)
	// defer commit to after check run
	defer c.Sender().Commit()

	if err != nil {
		log.Criticalf("Unable to run check '%s': %s", c.Name(), err)
	} else {
		l.send <- checkPayload{messages, c.Endpoint(), currentTime}
		// update proc and container count for info
		updateProcContainerCount(messages)
		if !c.RealTime() {
			d := time.Since(currentTime)
			switch {
			case runCounter < 5:
				log.Infof("Finished check #%d in %s", runCounter, d)
			case runCounter == 5:
				log.Infof("Finished check #%d in %s. First 5 check runs finished, next runs will be logged every 20 runs.", runCounter, d)
			case runCounter%20 == 0:
				log.Infof("Finish check #%d in %s", runCounter, d)
			}
		}
	}
}

func (l *Collector) run(exit chan bool) {
	eps := make([]string, 0, len(l.cfg.APIEndpoints))
	for _, e := range l.cfg.APIEndpoints {
		eps = append(eps, e.Endpoint.String())
	}
	log.Infof("Starting process-agent for host=%s, endpoints=%s, enabled checks=%v", l.cfg.HostName, eps, l.cfg.EnabledChecks)

	go handleSignals(exit)
	heartbeat := time.NewTicker(15 * time.Second)
	queueSizeTicker := time.NewTicker(10 * time.Second)
	featuresTicker := time.NewTicker(5 * time.Second)

	s, err := aggregator.GetSender("process-agent")
	if err != nil {
		_ = log.Error("No default sender available: ", err)

	}
	defer s.Commit()

	// Channel to announce new features detected
	featuresCh := make(chan features.Features, 1)

	// Channel per check to broadcast features
	featureChecksChs := make([]chan features.Features, 0)
	for range l.enabledChecks {
		featureChecksChs = append(featureChecksChs, make(chan features.Features, 1))
	}

	l.getFeatures(l.cfg.APIEndpoints[0], "/features", featuresCh)

	go func() {
		for {
			select {
			case payload := <-l.send:
				if len(l.send) >= l.cfg.QueueSize {
					log.Info("Expiring payload from in-memory queue.")
					// Limit number of items kept in memory while we wait.
					<-l.send
				}
				for _, m := range payload.messages {
					l.postMessage(payload.endpoint, m, payload.timestamp)
				}
			case <-heartbeat.C:
				log.Tracef("got heartbeat.C message. (Ignored)")
				s.Gauge("stackstate.process_agent.running", 1, l.cfg.HostName, []string{"version:" + versionString()})
			case <-queueSizeTicker.C:
				updateQueueSize(l.send)
			case <-featuresTicker.C:
				l.getFeatures(l.cfg.APIEndpoints[0], "/features", featuresCh)
			case featuresValue := <-featuresCh:
				// Broadcast to all checks
				for _, ch := range featureChecksChs {
					ch <- featuresValue
				}
				// Stop polling
				featuresTicker.Stop()
			case <-exit:
				return
			}
		}
	}()

	for checkInd, c := range l.enabledChecks {
		// Assignment here, because iterator value gets altered
		myInd := checkInd
		go func(c checks.Check) {
			var featuresSet features.Features = features.Empty()

			// Run the check the first time to prime the caches.
			if !c.RealTime() {
				l.runCheck(c, featuresSet)
			}

			ticker := time.NewTicker(l.cfg.CheckInterval(c.Name()))
			for {
				select {
				case <-ticker.C:
					realTimeEnabled := atomic.LoadInt32(&l.realTimeEnabled) == 1
					if !c.RealTime() || realTimeEnabled {
						l.runCheck(c, featuresSet)
					}
				case f := <-featureChecksChs[myInd]:
					featuresSet = f
				case d := <-l.rtIntervalCh:
					// Live-update the ticker.
					if c.RealTime() {
						ticker.Stop()
						ticker = time.NewTicker(d)
					}
				case _, ok := <-exit:
					if !ok {
						return
					}
				}
			}
		}(c)
	}
	<-exit
}

func (l *Collector) postMessage(checkPath string, m model.MessageBody, timestamp time.Time) {
	msgType, err := model.DetectMessageType(m)
	if err != nil {
		log.Errorf("Unable to detect message type: %s", err)
		return
	}

	body, err := model.EncodeMessage(model.Message{
		Header: model.MessageHeader{
			Version:   model.MessageV3,
			Encoding:  model.MessageEncodingZstdPB,
			Type:      msgType,
			Timestamp: timestamp.UnixNano() / int64(time.Millisecond),
		}, Body: m})

	if err != nil {
		log.Errorf("Unable to encode message: %s", err)
	}

	responses := make(chan errorResponse)
	for _, ep := range l.cfg.APIEndpoints {
		go l.postToAPI(ep, checkPath, body, responses)
	}

	// Wait for all responses to come back before moving on.
	statuses := make([]*model.CollectorStatus, 0, len(l.cfg.APIEndpoints))
	for i := 0; i < len(l.cfg.APIEndpoints); i++ {
		res := <-responses
		if res.err != nil {
			log.Error(res.err)
			continue
		}
	}

	if len(statuses) > 0 {
		l.updateStatus(statuses)
	}
}

func (l *Collector) updateStatus(statuses []*model.CollectorStatus) {
	curEnabled := atomic.LoadInt32(&l.realTimeEnabled) == 1

	// If any of the endpoints wants real-time we'll do that.
	// We will pick the maximum interval given since generally this is
	// only set if we're trying to limit load on the backend.
	shouldEnableRT := false
	maxInterval := 0 * time.Second
	for _, s := range statuses {
		shouldEnableRT = shouldEnableRT || (s.ActiveClients > 0 && l.cfg.AllowRealTime)
		interval := time.Duration(s.Interval) * time.Second
		if interval > maxInterval {
			maxInterval = interval
		}
	}

	if curEnabled && !shouldEnableRT {
		log.Info("Detected 0 clients, disabling real-time mode")
		atomic.StoreInt32(&l.realTimeEnabled, 0)
	} else if !curEnabled && shouldEnableRT {
		log.Info("Detected active clients, enabling real-time mode")
		atomic.StoreInt32(&l.realTimeEnabled, 1)
	}

	if maxInterval != l.realTimeInterval {
		l.realTimeInterval = maxInterval
		if l.realTimeInterval <= 0 {
			l.realTimeInterval = 2 * time.Second
		}
		// Pass along the real-time interval, one per check, so that every
		// check routine will see the new interval.
		for range l.enabledChecks {
			l.rtIntervalCh <- l.realTimeInterval
		}
		log.Infof("real time interval updated to %s", l.realTimeInterval)
	}
}

type errorResponse struct {
	err error
}

func (l *Collector) postToAPI(endpoint config.APIEndpoint, checkPath string, body []byte, responses chan errorResponse) {
	l.postToAPIwithEncoding(endpoint, checkPath, body, responses, "x-zip")
}

func (l *Collector) postToAPIwithEncoding(endpoint config.APIEndpoint, checkPath string, body []byte, responses chan errorResponse, contentEncoding string) {
	resp, err := l.accessAPIwithEncoding(endpoint, "POST", checkPath, body, contentEncoding)
	if err != nil {
		responses <- errorResponse{err: err}
		return
	}
	defer resp.Body.Close()
	responses <- errorResponse{nil}
}

func (l *Collector) getFeatures(endpoint config.APIEndpoint, checkPath string, report chan features.Features) {
	resp, accessErr := l.accessAPIwithEncoding(endpoint, "GET", checkPath, make([]byte, 0), "identity")

	// Handle error response
	if accessErr != nil {
		// Soo we got a 404, meaning we were able to contact stackstate, but it had no features path. We can publish a result
		if resp != nil {
			log.Info("Found StackState version which does not support feature detection yet")
			report <- features.Empty()
			return
		}
		// Log
		_ = log.Error(accessErr)
		return
	}

	defer resp.Body.Close()

	// Get byte array
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_ = log.Errorf("could not decode response body from features: %s", err)
		return
	}
	var data interface{}
	// Parse json
	err = json.Unmarshal(body, &data)
	if err != nil {
		_ = log.Errorf("error unmarshalling features json: %s of body %s", err, body)
		return
	}

	// Validate structure
	featureMap, ok := data.(map[string]interface{})
	if !ok {
		_ = log.Errorf("Json was wrongly formatted, expected map type, got: %s", reflect.TypeOf(data))
	}

	featuresParsed := make(map[string]bool)

	for k, v := range featureMap {
		featureValue, okV := v.(bool)
		if !okV {
			_ = log.Warnf("Json was wrongly formatted, expected boolean type, got: %s, skipping feature %s", reflect.TypeOf(v), k)
		}
		featuresParsed[k] = featureValue
	}

	log.Infof("Server supports features: %s", featuresParsed)
	report <- features.Make(featuresParsed)
}

func (l *Collector) accessAPIwithEncoding(endpoint config.APIEndpoint, method string, checkPath string, body []byte, contentEncoding string) (*http.Response, error) {
	url := endpoint.Endpoint.String() + checkPath // Add the checkPath in full Process Agent URL
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("could not create %s request to %s: %s", method, url, err)
	}

	req.Header.Add("content-encoding", contentEncoding)
	req.Header.Add("sts-api-key", endpoint.APIKey)
	req.Header.Add("sts-hostname", l.cfg.HostName)
	req.Header.Add("sts-processagentversion", Version)

	ctx, cancel := context.WithTimeout(context.Background(), ReqCtxTimeout)
	defer cancel()
	req.WithContext(ctx)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		if isHTTPTimeout(err) {
			return nil, fmt.Errorf("Timeout detected on %s, %s", url, err)
		}
		return nil, fmt.Errorf("Error submitting payload to %s: %s", url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		defer resp.Body.Close()
		io.Copy(ioutil.Discard, resp.Body)
		return resp, fmt.Errorf("unexpected response from %s. Status: %s, Body: %v", url, resp.Status, resp.Body)
	}

	return resp, nil

}
