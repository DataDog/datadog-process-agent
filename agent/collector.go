package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
)

type collectorChecks struct {
	process     *checks.ProcessCheck
	realTime    *checks.RTProcessCheck
	connections *checks.ConnectionsCheck
}

// Collector will collect metrics from the local system and ship to the backend.
type Collector struct {
	send       chan []model.MessageBody
	cfg        *config.AgentConfig
	httpClient http.Client
	// flag for current collector's realTime status
	realTime bool
	groupID  int32
	interval time.Duration
	// switch to enable/disable real time mode, comes directly from the config file
	allowRealTime bool

	// Store check state - this is ugly and should be managed differently.
	checks collectorChecks
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

	return Collector{
		send:          make(chan []model.MessageBody, cfg.QueueSize),
		cfg:           cfg,
		groupID:       rand.Int31(),
		interval:      2 * time.Second,
		allowRealTime: cfg.AllowRealTime,
		httpClient:    http.Client{Transport: transport},

		// Each check should handle a empty state initialization.
		checks: collectorChecks{
			process:     checks.NewProcessCheck(cfg, sysInfo),
			realTime:    checks.NewRTProcessCheck(cfg, sysInfo),
			connections: checks.NewConnectionsCheck(cfg, sysInfo),
		},
	}, nil
}

func (l *Collector) runCheck(c checks.Check) {
	if messages, err := c.Run(l.cfg, l.groupID); err != nil {
		log.Criticalf("Unable to run check '%s': %s", c.Name(), err)
	} else {
		l.groupID++
		l.send <- messages
	}
}

func (l *Collector) run() {
	log.Infof("Starting process-agent for host=%s, endpoint=%s", l.cfg.HostName, l.cfg.APIEndpoint)
	exit := make(chan bool)
	go handleSignals(exit)
	go func() {
		for {
			select {
			case messages := <-l.send:
				if len(l.send) >= l.cfg.QueueSize {
					log.Info("Expiring payload from in-memory queue.")
					// Limit number of items kept in memory while we wait.
					<-l.send
				}
				for _, m := range messages {
					l.postMessage(m)
				}
			case <-exit:
				return
			}
		}
	}()

	// Perform an initial check to prime the process caches.
	// This are expected to return no messages.
	l.runCheck(l.checks.process)

	// Then perform initial checks to start sending data immediately.
	l.runCheck(l.checks.process)
	l.runCheck(l.checks.connections)

	for {
		select {
		case <-l.cfg.Timers.Process.C:
			l.runCheck(l.checks.process)
		case <-l.cfg.Timers.Connections.C:
			l.runCheck(l.checks.connections)
		case <-l.cfg.Timers.RealTime.C:
			if l.realTime && l.allowRealTime {
				l.runCheck(l.checks.realTime)
			}
		case _, ok := <-exit:
			if !ok {
				return
			}
		}
	}
}

func (l *Collector) postMessage(m model.MessageBody) {
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
	l.cfg.APIEndpoint.Path = "/api/v1/collector"
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
	if s.ActiveClients > 0 && !l.realTime && l.allowRealTime {
		log.Infof("Detected %d clients, enabling real-time mode", s.ActiveClients)
		l.realTime = true
	} else if s.ActiveClients == 0 && l.realTime {
		log.Info("Detected 0 clients, disabling real-time mode")
		l.realTime = false
	}

	interval := time.Duration(s.Interval) * time.Second
	if interval != l.interval {
		l.interval = interval
		if l.interval <= 0 {
			l.interval = 2 * time.Second
		}
		l.cfg.Timers.RealTime.Stop()
		l.cfg.Timers.RealTime = time.NewTicker(l.interval)
		log.Infof("real time interval updated: %s", l.interval)
	}
}
