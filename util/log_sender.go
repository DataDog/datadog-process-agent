package util

import (
	"github.com/StackVista/stackstate-agent/pkg/metrics"
	log "github.com/cihub/seelog"
)

// Process is a singleton ProcessCheck.
var LogSender = &logSender{}

type logSender struct {
}

func (ls *logSender) Commit() {
	log.Debugf("Received Commit")
}
func (ls *logSender) Gauge(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Gauge: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) Rate(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Rate: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) Count(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Count: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) MonotonicCount(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received MonotonicCount: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) Counter(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Counter: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) Histogram(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Histogram: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) Historate(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Historate: [%s, %f, %s, %v]", metric, value, hostname, tags)
}
func (ls *logSender) ServiceCheck(checkName string, status metrics.ServiceCheckStatus, hostname string, tags []string, message string) {
	log.Debugf("Received ServiceCheck: [%s, %d, %s, %v, %s]", checkName, status, hostname, tags, message)
}
func (ls *logSender) HistogramBucket(metric string, value int64, lowerBound, upperBound float64, monotonic bool, hostname string, tags []string) {
	log.Debugf("Received HistogramBucket: [%s, %d, %f, %f, %b, %s, %v]", metric, value, lowerBound, upperBound, monotonic, hostname, tags)
}
func (ls *logSender) Event(e metrics.Event) {
	log.Debugf("Received Historate: [%s]", e.String())
}
func (ls *logSender) GetMetricStats() map[string]int64 {
	return nil
}
func (ls *logSender) DisableDefaultHostname(disable bool) {}
func (ls *logSender) SetCheckCustomTags(tags []string)    {}
func (ls *logSender) SetCheckService(service string)      {}
func (ls *logSender) FinalizeCheckServiceTag()            {}
