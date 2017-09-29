package main

import (
	"encoding/json"
	"expvar"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
)

var (
	infoMutex           sync.RWMutex
	infoOnce            sync.Once
	infoStart           = time.Now()
	infoNotRunningTmpl  *template.Template
	infoTmpl            *template.Template
	infoErrorTmpl       *template.Template
	infoDockerSocket    string
	infoLastCollectTime time.Time
	infoProcCount       int
	infoContainerCount  int
	infoQueueSize       int
)

const (
	infoTmplSrc = `{{.Banner}}
{{.Program}}
{{.Banner}}

  Pid: {{.Status.Pid}}
  Hostname: {{.Status.Config.HostName}}
  Uptime: {{.Status.Uptime}} seconds
  Mem alloc: {{.Status.MemStats.Alloc}} bytes

  Last collection time: {{.Status.LastCollectTime}}
  Docker socket: {{.Status.DockerSocket}}
  Number of processes: {{.Status.ProcessCount}}
  Number of containers: {{.Status.ContainerCount}}

  Logs: {{.Status.Config.LogFile}}{{if .Status.Config.Proxy}}
  HttpProxy: {{.Status.Config.Proxy}}{{end}}
  Queue length: {{.Status.QueueSize}}

`
	infoNotRunningTmplSrc = `{{.Banner}}
{{.Program}}
{{.Banner}}

  Not running

`
	infoErrorTmplSrc = `{{.Banner}}
{{.Program}}
{{.Banner}}

  Error: {{.Error}}

`
)

func publishUptime() interface{} {
	return int(time.Since(infoStart) / time.Second)
}

func publishVersion() interface{} {
	return infoVersion{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: GoVersion,
	}
}

func publishDockerSocket() interface{} {
	infoMutex.RLock()
	defer infoMutex.RUnlock()
	return infoDockerSocket
}

func updateDockerSocket(path string) {
	infoMutex.Lock()
	defer infoMutex.Unlock()
	infoDockerSocket = path
}

func publishLastCollectTime() interface{} {
	infoMutex.RLock()
	defer infoMutex.RUnlock()
	return infoLastCollectTime
}

func updateLastCollectTime(t time.Time) {
	infoMutex.Lock()
	defer infoMutex.Unlock()
	infoLastCollectTime = t
}

func publishProcCount() interface{} {
	infoMutex.RLock()
	defer infoMutex.RUnlock()
	return infoProcCount
}

func publishContainerCount() interface{} {
	infoMutex.RLock()
	defer infoMutex.RUnlock()
	return infoContainerCount
}

func updateProcContainerCount(msgs []model.MessageBody) {
	var count int
	// this is the flag to determine what type of collections are we dealing with
	var isProc bool
	for _, m := range msgs {
		switch msg := m.(type) {
		case *model.CollectorContainerRealTime:
			isProc = false
			count += len(msg.Stats)
		case *model.CollectorContainer:
			isProc = false
			count += len(msg.Containers)
		case *model.CollectorRealTime:
			isProc = true
			count += len(msg.Stats)
		case *model.CollectorProc:
			isProc = true
			count += len(msg.Processes)
		}
	}

	infoMutex.Lock()
	defer infoMutex.Unlock()
	if isProc {
		infoProcCount = count
	} else {
		infoContainerCount = count
	}
}

func updateQueueSize(c chan checkPayload) {
	infoMutex.Lock()
	defer infoMutex.Unlock()
	infoQueueSize = len(c)
}

func publishQueueSize() interface{} {
	infoMutex.RLock()
	defer infoMutex.RUnlock()
	return infoQueueSize
}

func getProgramBanner(version string) (string, string) {
	program := fmt.Sprintf("Processes and Containers Agent (v %s)", version)
	banner := strings.Repeat("=", len(program))
	return program, banner
}

type infoString string

func (s infoString) String() string { return string(s) }

type infoVersion struct {
	Version   string
	GitCommit string
	GitBranch string
	BuildDate string
	GoVersion string
}

type StatusInfo struct {
	Pid             int                    `json:"pid"`
	Uptime          int                    `json:"uptime"`
	MemStats        struct{ Alloc uint64 } `json:"memstats"`
	Version         infoVersion            `json:"version"`
	Config          config.AgentConfig     `json:"config"`
	DockerSocket    string                 `json:"docker_socket"`
	LastCollectTime time.Time              `json:"last_collect_time"`
	ProcessCount    int                    `json:"process_count"`
	ContainerCount  int                    `json:"container_count"`
	QueueSize       int                    `json:"queue_size"`
}

func initInfo(conf *config.AgentConfig) error {
	var err error

	funcMap := template.FuncMap{
		"add": func(a, b int64) int64 {
			return a + b
		},
		"percent": func(v float64) string {
			return fmt.Sprintf("%02.1f", v*100)
		},
	}
	infoOnce.Do(func() {
		expvar.NewInt("pid").Set(int64(os.Getpid()))
		expvar.Publish("uptime", expvar.Func(publishUptime))
		expvar.Publish("version", expvar.Func(publishVersion))
		expvar.Publish("docker_socket", expvar.Func(publishDockerSocket))
		expvar.Publish("last_collect_time", expvar.Func(publishLastCollectTime))
		expvar.Publish("process_count", expvar.Func(publishProcCount))
		expvar.Publish("container_count", expvar.Func(publishContainerCount))
		expvar.Publish("queue_size", expvar.Func(publishQueueSize))

		c := *conf
		var buf []byte
		buf, err = json.Marshal(&c)
		if err != nil {
			return
		}
		expvar.Publish("config", infoString(string(buf)))

		infoTmpl, err = template.New("info").Funcs(funcMap).Parse(infoTmplSrc)
		if err != nil {
			return
		}
		infoNotRunningTmpl, err = template.New("infoNotRunning").Parse(infoNotRunningTmplSrc)
		if err != nil {
			return
		}
		infoErrorTmpl, err = template.New("infoError").Parse(infoErrorTmplSrc)
		if err != nil {
			return
		}
	})

	return err
}

func Info(w io.Writer, conf *config.AgentConfig) error {
	var err error
	url := "http://localhost:6062/debug/vars"
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		program, banner := getProgramBanner(Version)
		_ = infoNotRunningTmpl.Execute(w, struct {
			Banner  string
			Program string
		}{
			Banner:  banner,
			Program: program,
		})
		return err
	}
	defer resp.Body.Close()

	var info StatusInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {

		fmt.Println("#################### error: ", err)

		program, banner := getProgramBanner(Version)
		_ = infoErrorTmpl.Execute(w, struct {
			Banner  string
			Program string
			Error   error
		}{
			Banner:  banner,
			Program: program,
			Error:   err,
		})
		return err
	}

	program, banner := getProgramBanner(info.Version.Version)
	err = infoTmpl.Execute(w, struct {
		Banner  string
		Program string
		Status  *StatusInfo
	}{
		Banner:  banner,
		Program: program,
		Status:  &info,
	})
	if err != nil {
		return err
	}
	return nil
}
