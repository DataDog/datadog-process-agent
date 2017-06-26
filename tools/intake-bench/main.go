package main

import (
	"bytes"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/conn"
)

var opts struct {
	apiKey  string
	url     string
	posts   int
	workers int
	sleep   time.Duration
}

func main() {
	flag.StringVar(&opts.apiKey, "api_key", "XXXX", "dd api key")
	flag.StringVar(&opts.url, "url", "", "url to which data is POSTed")
	flag.IntVar(&opts.posts, "posts", 0, "number of POSTs to make")
	flag.IntVar(&opts.workers, "workers", 4, "number workers submitting data points")
	flag.DurationVar(&opts.sleep, "sleep", 10*time.Millisecond, "sleep between posts")
	flag.Parse()

	client := http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        5,
			IdleConnTimeout:     0,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: 2 * time.Second,
	}

	cfg := &config.AgentConfig{
		APIKey:     opts.apiKey,
		HostName:   "bench-collector",
		ServerURL:  opts.url,
		QueueSize:  10,
		Blacklist:  []*regexp.Regexp{},
		MaxProcFDs: 200,
		ProcLimit:  100,
		Version:    "0.99.3",
	}

	pms, err := checks.CollectProcesses(cfg, 0)
	if err != nil {
		panic("err collector")
	}
	rms, err := checks.CollectRealTime(cfg, 0)
	if err != nil {
		panic("err collector")
	}

	msgch := make(chan []conn.Message)
	for i := 0; i < opts.workers; i++ {
		go func() {
			for m := range msgch {
				postMessages(cfg, client, m)
			}
		}()
	}

	for i := 0; i < opts.posts; i++ {
		if i%10 == 0 {
			msgch <- pms
		} else {
			msgch <- rms
		}
	}

}

// IsTimeout returns true if the error is due to reaching the timeout limit on the http.client
func isHTTPTimeout(err error) bool {
	if netErr, ok := err.(interface {
		Timeout() bool
	}); ok && netErr.Timeout() {
		return true
	} else if strings.Contains(err.Error(), "use of closed network connection") { //To deprecate when using GO > 1.5
		return true
	}
	return false
}

func postMessages(cfg *config.AgentConfig, client http.Client, msgs []conn.Message) {
	for _, m := range msgs {
		postMessage(cfg, client, m)
	}
}

func postMessage(cfg *config.AgentConfig, client http.Client, m conn.Message) {
	body, err := conn.EncodeMessage(conn.MessageHeader{
		Version:  conn.MessageV2,
		Encoding: conn.MessageEncodingProtobuf,
		Type:     conn.MessageType(m.GetHeader().Type),
	}, m)
	if err != nil {
		log.Errorf("Unable to encode message: %s", err)
	}
	url := opts.url
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Errorf("could not create request: %s", err)
		return
	}
	req.Header.Set("X-Dd-Processagentversion", config.AgentVersion)
	req.Header.Set("X-Dd-Hostname", cfg.HostName)
	req.Header.Set("X-Dd-Apikey", cfg.APIKey)

	resp, err := client.Do(req)
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

	if _, err := conn.DecodeMessage(body); err != nil {
		log.Errorf("could not decode response, invalid format: %s", err)
		return
	}
}
