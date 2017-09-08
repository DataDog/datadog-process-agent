package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/statsd"
)

type checkPayload struct {
	messages []model.MessageBody
	endpoint string
}

// Collector will collect metrics from the local system and ship to the backend.
type Collector struct {
	send          chan checkPayload
	rtIntervalCh  chan time.Duration
	cfg           *config.AgentConfig
	httpClient    http.Client
	groupID       int32
	enabledChecks []checks.Check

	// Controls the real-time interval, can change live.
	realTimeInterval time.Duration
	// Set to 1 if enabled 0 is not. We're using an integer
	// so we can use the sync/atomic for thread-safe access.
	realTimeEnabled int64
}

// NewCollector creates a new Collectr
func NewCollector(cfg *config.AgentConfig) (Collector, error) {
	transport := &http.Transport{
		MaxIdleConns:    5,
		IdleConnTimeout: 90 * time.Second,
		Dial: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if cfg.Proxy != nil {
		proxy := cfg.Proxy
		userInfo := ""
		if cfg.Proxy.User != nil {
			if _, isSet := proxy.User.Password(); isSet {
				userInfo = "*****:*****@"
			} else {
				userInfo = "*****@"
			}
		}
		log.Infof("Using proxy from configuration: %s://%s%s", proxy.Scheme, userInfo, proxy.Host)
		transport.Proxy = http.ProxyURL(proxy)
	}

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
		httpClient:    http.Client{Transport: transport},
		enabledChecks: enabledChecks,

		// Defaults for real-time on start
		realTimeInterval: 2 * time.Second,
		realTimeEnabled:  0,
	}, nil
}

func (l *Collector) runCheck(c checks.Check) {
	if messages, err := c.Run(l.cfg, atomic.AddInt32(&l.groupID, 1)); err != nil {
		log.Criticalf("Unable to run check '%s': %s", c.Name(), err)
	} else {
		l.send <- checkPayload{messages, c.Endpoint()}
	}
}

func (l *Collector) run() {
	log.Infof("Starting process-agent for host=%s, endpoint=%s", l.cfg.HostName, l.cfg.APIEndpoint)
	exit := make(chan bool)
	go handleSignals(exit)
	heartbeat := time.NewTicker(15 * time.Second)
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
					l.postMessage(payload.endpoint, m)
				}
			case <-heartbeat.C:
				statsd.Client.Gauge("datadog.process.agent", 1, []string{}, 1)
			case <-exit:
				return
			}
		}
	}()

	for _, c := range l.enabledChecks {
		go func(c checks.Check) {
			// Run the check the first time to prime the caches.
			if !c.RealTime() {
				l.runCheck(c)
			}

			ticker := time.NewTicker(l.cfg.CheckInterval(c.Name()))
			for {
				select {
				case <-ticker.C:
					realTimeEnabled := atomic.LoadInt64(&l.realTimeEnabled) == 1
					if !c.RealTime() || realTimeEnabled {
						l.runCheck(c)
					}
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

func (l *Collector) postMessage(endpoint string, m model.MessageBody) {
	msgType, err := model.DetectMessageType(m)
	if err != nil {
		log.Errorf("Unable to detect message type: %s", err)
		return
	}

	body, err := model.EncodeMessage(model.Message{
		Header: model.MessageHeader{
			Version:  model.MessageV3,
			Encoding: model.MessageEncodingZstdPB,
			Type:     msgType,
		}, Body: m})
	if err != nil {
		log.Errorf("Unable to encode message: %s", err)
	}
	l.cfg.APIEndpoint.Path = endpoint
	url := l.cfg.APIEndpoint.String()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Errorf("could not create request: %s", err)
		return
	}
	req.Header.Add("X-Dd-APIKey", l.cfg.APIKey)
	req.Header.Add("X-Dd-Hostname", l.cfg.HostName)
	req.Header.Add("X-Dd-Processagentversion", Version)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		if isHTTPTimeout(err) {
			log.Errorf("Timeout detected, %s", err)
		} else {
			log.Errorf("Error submitting payload: %s", err)
		}
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		log.Errorf("unexpected response from %s. Status: %s", url, resp.Status)
		io.Copy(ioutil.Discard, resp.Body)
		return
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("could not decode response body: %s", err)
		return
	}

	r, err := model.DecodeMessage(body)
	if err != nil {
		log.Errorf("could not decode response, invalid format: %s", err)
		return
	}
	switch r.Header.Type {
	case model.TypeResCollector:
		rm := r.Body.(*model.ResCollector)
		if len(rm.Message) > 0 {
			log.Error(rm.Message)
		} else {
			l.updateStatus(rm.Status)
		}
	default:
		log.Errorf("unexpected response type: %d", r.Header.Type)
	}
}

func (l *Collector) updateStatus(s *model.CollectorStatus) {
	curEnabled := atomic.LoadInt64(&l.realTimeEnabled) == 1
	if s.ActiveClients > 0 && !curEnabled && l.cfg.AllowRealTime {
		log.Infof("Detected %d clients, enabling real-time mode", s.ActiveClients)
		atomic.StoreInt64(&l.realTimeEnabled, 1)
	} else if s.ActiveClients == 0 && curEnabled {
		log.Info("Detected 0 clients, disabling real-time mode")
		atomic.StoreInt64(&l.realTimeEnabled, 0)
	}

	interval := time.Duration(s.Interval) * time.Second
	if interval != l.realTimeInterval {
		l.realTimeInterval = interval
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
