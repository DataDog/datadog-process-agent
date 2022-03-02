package util

import (
	"github.com/StackVista/stackstate-agent/pkg/metrics"
	log "github.com/cihub/seelog"
)

// LogSender is a singleton instance of the Sender interface logging the data produced.
var LogSender = &logSender{}

type logSender struct {
}

// Commit logs received commit
func (ls *logSender) Commit() {
	log.Debugf("Received Commit")
}

// Gauge logs gauge data
func (ls *logSender) Gauge(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Gauge: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// Rate logs rate data
func (ls *logSender) Rate(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Rate: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// Count logs count data
func (ls *logSender) Count(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Count: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// MonotonicCount logs monotonic count data
// MonotonicCount logs monotonic count data
func (ls *logSender) MonotonicCount(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received MonotonicCount: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// Counter logs counter data
func (ls *logSender) Counter(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Counter: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// Histogram logs histogram data
func (ls *logSender) Histogram(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Histogram: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// Historate logs historate data
func (ls *logSender) Historate(metric string, value float64, hostname string, tags []string) {
	log.Debugf("Received Historate: [%s, %f, %s, %v]", metric, value, hostname, tags)
}

// ServiceCheck logs service check data
func (ls *logSender) ServiceCheck(checkName string, status metrics.ServiceCheckStatus, hostname string, tags []string, message string) {
	log.Debugf("Received ServiceCheck: [%s, %d, %s, %v, %s]", checkName, status, hostname, tags, message)
}

// HistogramBucket logs histogram bucket data
func (ls *logSender) HistogramBucket(metric string, value int64, lowerBound, upperBound float64, monotonic bool, hostname string, tags []string) {
	log.Debugf("Received HistogramBucket: [%s, %d, %f, %f, %b, %s, %v]", metric, value, lowerBound, upperBound, monotonic, hostname, tags)
}

// Event logs event data
func (ls *logSender) Event(e metrics.Event) {
	log.Debugf("Received Event: [%s]", e.String())
}

// GetMetricStats returns nil
func (ls *logSender) GetMetricStats() map[string]int64 {
	return nil
}

// DisableDefaultHostname returns void
func (ls *logSender) DisableDefaultHostname(disable bool) {}

// SetCheckCustomTags returns void
func (ls *logSender) SetCheckCustomTags(tags []string) {}

// SetCheckService returns void
func (ls *logSender) SetCheckService(service string) {}

// FinalizeCheckServiceTag returns void
func (ls *logSender) FinalizeCheckServiceTag() {}
