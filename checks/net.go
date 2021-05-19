package checks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/DataDog/sketches-go/ddsketch/pb/sketchpb"
	"github.com/golang/protobuf/proto"
	"strconv"
	"strings"
	"time"

	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/net"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	log "github.com/cihub/seelog"
	"github.com/patrickmn/go-cache"
)

var (
	// Connections is a singleton ConnectionsCheck.
	Connections = &ConnectionsCheck{}

	// ErrTracerStillNotInitialized signals that the tracer is _still_ not ready, so we shouldn't log additional errors
	ErrTracerStillNotInitialized = errors.New("remote tracer is still not initialized")
)

const (
	// HTTPResponseTimeMetricName is for the metric that is sent with a connection
	HTTPResponseTimeMetricName = "http_response_time_seconds"

	// HTTPResponseCountMetricName is for the metric that is sent with a connection
	HTTPRequestsPerSecondMetricName = "http_requests_per_second"
)

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct {
	// Local network tracer
	useLocalTracer bool
	localTracer    tracer.Tracer

	prevCheckTime time.Time

	buf *bytes.Buffer // Internal buffer

	// Use this as the network relation cache to calculate rate metrics and drop short-lived network relations
	cache *cache.Cache
}

type statusCodeGroup struct {
	// Local network tracer
	tag      string
	inRange  func(int) bool
	ddSketch *ddsketch.DDSketch
}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/connections" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ConnectionsCheck) RealTime() bool { return false }

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. Currently only linux systems are supported as eBPF is used to gather
// this information. For each connection we'll return a `model.Connection`
// that will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32) ([]model.MessageBody, error) {
	// If local tracer failed to initialize, so we shouldn't be doing any checks
	if c.useLocalTracer && c.localTracer == nil {
		log.Errorf("failed to create network tracer. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting")
		return nil, nil
	}

	start := time.Now()

	conns, err := c.getConnections()
	if err != nil {
		// If the tracer is not initialized, or still not initialized, then we want to exit without error'ing
		if err == common.ErrNotImplemented || err == ErrTracerStillNotInitialized {
			return nil, nil
		}
		return nil, err
	}

	if c.prevCheckTime.IsZero() { // End check early if this is our first run.
		// fill in the relation cache
		for _, conn := range conns {
			relationID, err := CreateNetworkRelationIdentifier(cfg.HostName, conn)
			if err != nil {
				log.Warnf("invalid connection description - can't determine ID: %v", err)
			}
			PutNetworkRelationCache(c.cache, relationID, conn)
		}
		c.prevCheckTime = time.Now()
		return nil, nil
	}

	formattedConnections := c.formatConnections(cfg, conns, c.prevCheckTime)
	log.Debugf("collected connections in %s, connections found: %v", time.Since(start), formattedConnections)
	return batchConnections(cfg, groupID, formattedConnections), nil
}

func (c *ConnectionsCheck) getConnections() ([]common.ConnectionStats, error) {
	if c.useLocalTracer { // If local tracer is set up, use that
		if c.localTracer == nil {
			return nil, fmt.Errorf("using local network tracer, but no tracer was initialized")
		}
		cs, err := c.localTracer.GetConnections()
		return cs.Conns, err
	}

	tu, err := net.GetRemoteNetworkTracerUtil()
	if err != nil {
		if net.ShouldLogTracerUtilError() {
			return nil, err
		}
		return nil, ErrTracerStillNotInitialized
	}

	return tu.GetConnections()
}

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(cfg *config.AgentConfig, conns []common.ConnectionStats, lastCheckTime time.Time) []*model.Connection {
	// Process create-times required to construct unique process hash keys on the backend
	createTimeForPID := Process.createTimesForPIDs(connectionPIDs(conns))

	cxs := make([]*model.Connection, 0, len(conns))
	for _, conn := range conns {
		// Check to see if this is a process that we observed and that it's not short-lived / blacklisted in the Process check
		if pidCreateTime, ok := isProcessPresent(createTimeForPID, conn.Pid); ok {
			namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
			relationID, err := CreateNetworkRelationIdentifier(namespace, conn)
			if err != nil {
				log.Warnf("invalid connection description - can't determine ID: %v", err)
				continue
			}
			// Check to see if we have this relation cached and whether we have observed it for the configured time, otherwise skip
			if relationCache, ok := IsNetworkRelationCached(c.cache, relationID); ok {
				if !isRelationShortLived(relationID, relationCache.FirstObserved, cfg) {
					cxs = append(cxs, &model.Connection{
						Pid:           int32(conn.Pid),
						PidCreateTime: pidCreateTime,
						Family:        formatFamily(conn.Family),
						Type:          formatType(conn.Type),
						Laddr: &model.Addr{
							Ip:   conn.Local,
							Port: int32(conn.LocalPort),
						},
						Raddr: &model.Addr{
							Ip:   conn.Remote,
							Port: int32(conn.RemotePort),
						},
						BytesSentPerSecond:     calculateRate(conn.SendBytes, relationCache.ConnectionMetrics.SendBytes, lastCheckTime),
						BytesReceivedPerSecond: calculateRate(conn.RecvBytes, relationCache.ConnectionMetrics.RecvBytes, lastCheckTime),
						Direction:              calculateDirection(conn.Direction),
						Namespace:              namespace,
						ConnectionIdentifier:   relationID,
						ApplicationProtocol:    conn.ApplicationProtocol,
						Metrics:                formatMetrics(conn.HttpMetrics, time.Now().Sub(lastCheckTime)),
					})
				}
			}

			// put it in the cache for the next run
			PutNetworkRelationCache(c.cache, relationID, conn)
		}
	}
	c.prevCheckTime = time.Now()
	return cxs
}

func formatMetrics(httpMetrics []common.HttpMetric, duration time.Duration) []*model.ConnectionMetric {
	metrics := make([]*model.ConnectionMetric, 0, len(httpMetrics))

	groups := initialStatusCodeGroups()
	reqCounts := map[string]uint64{}
	for _, group := range groups {
		reqCounts[group.tag] = 0
	}
	for i := range httpMetrics {
		metric := httpMetrics[i]
		tag := strconv.Itoa(metric.StatusCode)
		metrics = append(metrics, newHTTPResponseTimeConnectionMetric(tag, metric.DDSketch))
		metricSketch, err := decodeDDSketch(metric.DDSketch)
		if err != nil {
			log.Warnf("can't decode ddsketch: %v", err)
			continue
		}
		statusCodeCount := metricSketch.GetCount()
		accumulatedCount := reqCounts[tag] + uint64(statusCodeCount)
		reqCounts[tag] = accumulatedCount
		for _, group := range groups {
			if group.inRange(metric.StatusCode) {
				group.ddSketch = mergeWithHistogram(metricSketch, group.ddSketch)
				reqCounts[group.tag] = reqCounts[group.tag] + uint64(statusCodeCount)
			}
		}
	}

	for _, group := range groups {
		metrics = appendMetric(group.ddSketch, group.tag, metrics)
	}
	for key, value := range reqCounts {
		metrics = append(metrics, newHTTPRequestsPerSecondConnectionMetric(key, float64(calculateNormalizedRate(value, duration))))
	}
	return metrics
}

func newHTTPResponseTimeConnectionMetric(tag string, ddSketch []byte) *model.ConnectionMetric {
	return &model.ConnectionMetric{
		Name: HTTPResponseTimeMetricName,
		Tags: []*model.ConnectionMetricTag{
			{Key: "code", Value: tag},
		},
		Value: &model.ConnectionMetricValue{
			Value: &model.ConnectionMetricValue_DdsketchHistogram{
				DdsketchHistogram: ddSketch,
			},
		},
	}
}

func newHTTPRequestsPerSecondConnectionMetric(tag string, number float64) *model.ConnectionMetric {
	return &model.ConnectionMetric{
		Name: HTTPRequestsPerSecondMetricName,
		Tags: []*model.ConnectionMetricTag{
			{Key: "code", Value: tag},
		},
		Value: &model.ConnectionMetricValue{
			Value: &model.ConnectionMetricValue_Number{
				Number: number,
			},
		},
	}
}

func initialStatusCodeGroups() []*statusCodeGroup {
	return []*statusCodeGroup{
		{
			tag: "any",
			inRange: func(statusCode int) bool {
				return true
			},
			ddSketch: nil,
		},
		{
			tag: "success",
			inRange: func(statusCode int) bool {
				return 100 <= statusCode && statusCode <= 399
			},
			ddSketch: nil,
		},
		{
			tag: "1xx",
			inRange: func(statusCode int) bool {
				return 100 <= statusCode && statusCode <= 199
			},
			ddSketch: nil,
		},
		{
			tag: "2xx",
			inRange: func(statusCode int) bool {
				return 200 <= statusCode && statusCode <= 299
			},
			ddSketch: nil,
		},
		{
			tag: "3xx",
			inRange: func(statusCode int) bool {
				return 300 <= statusCode && statusCode <= 399
			},
			ddSketch: nil,
		},
		{
			tag: "4xx",
			inRange: func(statusCode int) bool {
				return 400 <= statusCode && statusCode <= 499
			},
			ddSketch: nil,
		},
		{
			tag: "5xx",
			inRange: func(statusCode int) bool {
				return 500 <= statusCode && statusCode <= 599
			},
			ddSketch: nil,
		},
	}
}

func mergeWithHistogram(metricSketch *ddsketch.DDSketch, rtHist *ddsketch.DDSketch) *ddsketch.DDSketch {
	if rtHist == nil {
		rtHist = metricSketch.Copy()
	} else {
		err := rtHist.MergeWith(metricSketch)
		if err != nil {
			log.Warnf("can't merge ddsketch: %v", err)
		}
	}
	return rtHist
}

func appendMetric(rtHist *ddsketch.DDSketch, tag string, metrics []*model.ConnectionMetric) []*model.ConnectionMetric {
	if rtHist != nil {
		metricSketch, err := marshalDDSketch(rtHist)
		if err != nil {
			log.Warnf("can't encode ddsketch: %v", err)
		} else {

			metrics = append(metrics, &model.ConnectionMetric{
				Name: HTTPResponseTimeMetricName,
				Tags: []*model.ConnectionMetricTag{
					{Key: "code", Value: tag},
				},
				Value: &model.ConnectionMetricValue{
					Value: &model.ConnectionMetricValue_DdsketchHistogram{
						DdsketchHistogram: metricSketch,
					},
				},
			})
		}
	}
	return metrics
}

func marshalDDSketch(rtHist *ddsketch.DDSketch) ([]byte, error) {
	return proto.Marshal(rtHist.ToProto())
}

func batchConnections(cfg *config.AgentConfig, groupID int32, cxs []*model.Connection) []model.MessageBody {
	batches := make([]model.MessageBody, 0, 1)

	// STS: Disable batching for now
	batchSize := min(cfg.MaxPerMessage, len(cxs))
	batch := &model.CollectorConnections{
		HostName:    cfg.HostName,
		Connections: cxs[:batchSize],
		GroupId:     groupID,
		GroupSize:   1,
	}

	if strings.TrimSpace(cfg.ClusterName) != "" {
		batch.ClusterName = cfg.ClusterName
	}

	batches = append(batches, batch)

	return batches
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func connectionPIDs(conns []common.ConnectionStats) []uint32 {
	ps := make(map[uint32]struct{}) // Map used to represent a set
	for _, c := range conns {
		ps[c.Pid] = struct{}{}
	}

	pids := make([]uint32, 0, len(ps))
	for pid := range ps {
		pids = append(pids, pid)
	}
	return pids
}

// isProcessPresent checks to see if this process was present in the pidCreateTimes map created by the Process check,
// otherwise we don't report connections for this pid
func isProcessPresent(pidCreateTimes map[uint32]int64, pid uint32) (int64, bool) {
	pidCreateTime, ok := pidCreateTimes[pid]
	if !ok {
		log.Debugf("Filter connection: it's corresponding pid [%d] is not present in the last process state", pid)
		return pidCreateTime, false
	}

	return pidCreateTime, true
}

// isRelationShortLived checks to see whether a network connection is considered a short-lived network relation
func isRelationShortLived(relationID string, firstObserved int64, cfg *config.AgentConfig) bool {
	// short-lived filtering is disabled, return false
	if !cfg.EnableShortLivedNetworkRelationFilter {
		return false
	}

	// firstObserved is before ShortLivedTime. Relation is not short-lived, return false
	if time.Unix(firstObserved, 0).Before(time.Now().Add(-cfg.ShortLivedNetworkRelationQualifierSecs)) {
		return false
	}

	// connection / relation is filtered due to it's short-lived nature, let's log it on trace level
	log.Debugf("Filter relation: %s based on it's short-lived nature; "+
		"meaning we observed this / similar network relations less than %d seconds. If this behaviour is not desired set the "+
		"STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS environment variable to 0, disable it in agent.yaml "+
		"under process_config.filters.short_lived_network_relations.enabled or increase the qualifier seconds using"+
		"process_config.filters.short_lived_network_relations.qualifier_secs.",
		relationID, cfg.ShortLivedNetworkRelationQualifierSecs,
	)
	return true
}

func decodeDDSketch(sketch []byte) (*ddsketch.DDSketch, error) {
	var sketchPb sketchpb.DDSketch
	err := proto.Unmarshal(sketch, &sketchPb)
	if err != nil {
		return nil, err
	}
	ddSketch, err := ddsketch.FromProto(&sketchPb)
	return ddSketch, err
}
