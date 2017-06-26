// log.go is a copy of util/seelog.go without a dependency on the util package
// to avoid pulling in a world of dependencies. This should eventually go away
// when dd-process agent is part of the mainline Agent code.
package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/cihub/seelog"
)

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
	XMLName xml.Name           `xml:"filter,omitempty"`
	Levels  string             `xml:"levels,attr,omitempty"`
	Syslog  *seelogFilterAttrs `xml:"conn"`
	Console *seelogFilterAttrs `xml:"console"`
}

type seelogFilterAttrs struct {
	FormatID string `xml:"formatid,attr,omitempty"`
	Net      string `xml:"net,attr,omitempty"`
	Addr     string `xml:"addr,attr,omitempty"`
}

type seelogFormats struct {
	Formats []seelogFormat `xml:"formats>format"`
}

type seelogFormat struct {
	ID     string `xml:"id,attr"`
	Format string `xml:"format,attr"`
}

type LoggerConfig struct {
	AppName     string
	LogLevel    string
	Syslog      bool
	SyslogLevel string
	SyslogHost  string
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

var syslogFormatter log.FormatterFuncCreator

func registerSyslogFormatter(appName string) error {
	hostName := getHostname()
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

func (cfg *LoggerConfig) SeelogConfig() (*seelogConfig, error) {
	s := newSeelog()
	s.addConsole(cfg.LogLevel)

	if cfg.Syslog {
		appName := cfg.AppName
		if appName == "" {
			appName = "unknown-app"
		}

		if err := s.addSyslog(appName, cfg.SyslogHost, cfg.SyslogLevel); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// SeelogLogger returns a new seelog Logger
func (cfg *LoggerConfig) SeelogLogger() (log.LoggerInterface, error) {
	scfg, err := cfg.SeelogConfig()
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

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func validateLogLevels(levels ...string) error {
	logLevels := map[string]struct{}{
		"trace":    struct{}{},
		"debug":    struct{}{},
		"info":     struct{}{},
		"warn":     struct{}{},
		"error":    struct{}{},
		"critical": struct{}{},
		"off":      struct{}{},
	}

	for _, level := range levels {
		if _, ok := logLevels[level]; !ok {
			return errInvalidLogLevel
		}
	}
	return nil
}

func ReplaceLogger(cfg *LoggerConfig) error {
	if err := validateLogLevels(cfg.LogLevel, cfg.SyslogLevel); err != nil {
		return err
	}

	logger, err := cfg.SeelogLogger()
	if err != nil {
		return err
	}
	return log.ReplaceLogger(logger)
}

func NewLoggerLevelCustom(logLevel string) error {
	loggerConfig := &LoggerConfig{
		LogLevel:    logLevel,
		SyslogLevel: "off",
	}
	return ReplaceLogger(loggerConfig)
}

// NewLoggerLevel sets the global log level.
func NewLoggerLevel(debug bool) error {
	if debug {
		return NewLoggerLevelCustom("debug")
	}
	return NewLoggerLevelCustom("info")
}

// NewLoggerLevelFromEnv sets the log level based on the LOG_LEVEL environment variable.
func NewLoggerLevelFromEnv() error {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = DefaultLogLevel
	}
	return NewLoggerLevelCustom(logLevel)
}
