package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ddlog "github.com/DataDog/datadog-agent/pkg/util/log"
	log "github.com/cihub/seelog"
)

// Default logging constants.
const (
	DefaultLogLevel    = "info"
	DefaultSyslogHost  = "localhost:514"
	DefaultSyslogLevel = "error"
)

var (
	levelToSyslogSeverity = map[log.LogLevel]int{
		log.TraceLvl:    7,
		log.DebugLvl:    7,
		log.InfoLvl:     6,
		log.WarnLvl:     4,
		log.ErrorLvl:    3,
		log.CriticalLvl: 2,
		log.Off:         7,
	}

	errInvalidLogLevel = errors.New("invalid log level")
)

type seelogConfig struct {
	XMLName  xml.Name `xml:"seelog"`
	LogLevel string   `xml:"minlevel,attr"`
	*seelogOutputs
	*seelogFormats
}

type seelogOutputs struct {
	Filters []seelogFilter `xml:"outputs>filter"`
}

type seelogFilter struct {
	XMLName     xml.Name           `xml:"filter,omitempty"`
	Levels      string             `xml:"levels,attr,omitempty"`
	Syslog      *seelogFilterAttrs `xml:"conn"`
	Console     *seelogFilterAttrs `xml:"console"`
	RollingFile *seelogFilterAttrs `xml:"rollingfile"`
}

type seelogFilterAttrs struct {
	FormatID string `xml:"formatid,attr,omitempty"`

	// <conn>
	Net  string `xml:"net,attr,omitempty"`
	Addr string `xml:"addr,attr,omitempty"`

	// <rollingfile>
	Filename string `xml:"filename,attr,omitempty"`
	Type     string `xml:"type,attr,omitempty"`
	MaxSize  int    `xml:"maxsize,attr,omitempty"`
	MaxRolls int    `xml:"maxrolls,attr,omitempty"`
}

type seelogFormats struct {
	Formats []seelogFormat `xml:"formats>format"`
}

type seelogFormat struct {
	ID     string `xml:"id,attr"`
	Format string `xml:"format,attr"`
}

func newConsoleFormat() *seelogFormat {
	return &seelogFormat{
		ID:     "console",
		Format: "%Date %Time %LEVEL (%File:%Line) - %Msg%n",
	}
}

func newSyslogFormat() *seelogFormat {
	return &seelogFormat{
		ID:     "syslog",
		Format: "%CustomSyslogHeader(20) %Msg%n",
	}
}

func newFileFormat() *seelogFormat {
	return &seelogFormat{
		ID:     "file",
		Format: "%Date %Time %LEVEL (%File:%Line) - %Msg%n",
	}
}

var syslogFormatter log.FormatterFuncCreator

func registerSyslogFormatter(appName string) error {
	hostName := getSyslogHostname()
	pid := os.Getpid()

	if syslogFormatter == nil {
		err := log.RegisterCustomFormatter("CustomSyslogHeader", func(params string) log.FormatterFunc {
			return syslogFormatter(params)
		})
		if err != nil {
			return err
		}
	}

	syslogFormatter = func(params string) log.FormatterFunc {
		facility := 20
		i, err := strconv.Atoi(params)
		if err == nil && i >= 0 && i <= 23 {
			facility = i
		}
		return func(message string, level log.LogLevel, context log.LogContextInterface) interface{} {
			return fmt.Sprintf("<%d>1 %s %s %s %d - -", facility*8+levelToSyslogSeverity[level],
				time.Now().Format("2006-01-02T15:04:05Z07:00"), hostName, appName, pid)
		}
	}

	return nil
}

func newSyslogFilter(host, logLvl string) *seelogFilter {
	return &seelogFilter{
		Levels: filterLevels(logLvl),
		Syslog: &seelogFilterAttrs{
			FormatID: "syslog",
			Net:      "udp",
			Addr:     host,
		},
	}
}

func newConsoleFilter(logLvl string) *seelogFilter {
	return &seelogFilter{
		Levels: filterLevels(logLvl),
		Console: &seelogFilterAttrs{
			FormatID: "console",
		},
	}
}

func newFileFilter(logLvl, filename string) *seelogFilter {
	return &seelogFilter{
		Levels: filterLevels(logLvl),
		RollingFile: &seelogFilterAttrs{
			FormatID: "file",
			Filename: filename,
			Type:     "size",
			MaxSize:  10 * 1024 * 1024,
			MaxRolls: 1,
		},
	}
}

func newSeelog() *seelogConfig {
	return &seelogConfig{
		// Filters override this value
		LogLevel:      "debug",
		seelogOutputs: &seelogOutputs{},
		seelogFormats: &seelogFormats{},
	}
}

func (s *seelogConfig) addFormat(f *seelogFormat) {
	s.Formats = append(s.Formats, *f)
}

func (s *seelogConfig) addFilter(f *seelogFilter) {
	s.Filters = append(s.Filters, *f)
}

func (s *seelogConfig) addSyslog(appName, addr, logLvl string) error {
	if err := registerSyslogFormatter(appName); err != nil {
		return err
	}
	s.addFilter(newSyslogFilter(addr, logLvl))
	s.addFormat(newSyslogFormat())
	return nil
}

func (s *seelogConfig) addConsole(logLvl string) {
	s.addFilter(newConsoleFilter(logLvl))
	s.addFormat(newConsoleFormat())
}

func (s *seelogConfig) addFile(logLvl, filename string) {
	s.addFilter(newFileFilter(logLvl, filename))
	s.addFormat(newFileFormat())
}

func (cfg *LoggerConfig) seelogConfig() (*seelogConfig, error) {
	s := newSeelog()

	if cfg.Filename != "" {
		s.addFile(cfg.LogLevel, cfg.Filename)
	}
	if cfg.Console {
		s.addConsole(cfg.LogLevel)
	}
	if cfg.Syslog {
		if err := s.addSyslog("process-agent", cfg.SyslogHost, cfg.SyslogLevel); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// LoggerConfig defines the configuration of a logger
type LoggerConfig struct {
	AppName     string
	LogLevel    string
	Console     bool
	Syslog      bool
	SyslogLevel string
	SyslogHost  string
	Filename    string
}

// SeelogLogger returns a new seelog Logger
func (cfg *LoggerConfig) SeelogLogger() (log.LoggerInterface, error) {
	scfg, err := cfg.seelogConfig()
	if err != nil {
		return nil, err
	}

	xmlConfig, err := xml.MarshalIndent(scfg, "", "    ")
	if err != nil {
		return nil, err
	}

	return log.LoggerFromConfigAsString(string(xmlConfig))
}

func filterLevels(level string) string {
	// https://github.com/cihub/seelog/wiki/Log-levels
	if level == "off" {
		return "off"
	}
	levels := "trace,debug,info,warn,error,critical"
	return levels[strings.Index(levels, level):]
}

func getSyslogHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func validateLogLevels(levels ...string) error {
	logLevels := map[string]struct{}{
		"trace":    {},
		"debug":    {},
		"info":     {},
		"warn":     {},
		"error":    {},
		"critical": {},
		"off":      {},
	}

	for _, level := range levels {
		if _, ok := logLevels[level]; !ok {
			return errInvalidLogLevel
		}
	}
	return nil
}

func replaceLogger(cfg *LoggerConfig) error {
	if err := validateLogLevels(cfg.LogLevel); err == errInvalidLogLevel {
		log.Infof("log level %s is invalid, defaulting to INFO")
		cfg.LogLevel = "info"
	}
	if err := validateLogLevels(cfg.SyslogLevel); err == errInvalidLogLevel {
		log.Infof("log level %s is invalid, defaulting to INFO")
		cfg.LogLevel = "info"
	}
	logger, err := cfg.SeelogLogger()
	if err != nil {
		return err
	}

	// If the main agent has a logger, replace it with ours. If not, then set it up.
	if ddlog.ReplaceLogger(logger) == nil {
		ddlog.SetupDatadogLogger(logger, cfg.LogLevel)
	}

	return log.ReplaceLogger(logger)
}

// NewLoggerLevel sets the global logger to the given log level.
func NewLoggerLevel(logLevel, logFile string, logToConsole bool) error {
	return replaceLogger(&LoggerConfig{
		LogLevel:    strings.ToLower(logLevel),
		Filename:    logFile,
		SyslogLevel: "off",
		Console:     logToConsole,
	})
}
