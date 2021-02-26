package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	tracerConfig "github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	log "github.com/cihub/seelog"
	"net"
	"strings"
	"time"
)

type ip struct {
	Address string
	IsIPv6  bool
}

type endpoint struct {
	ip   *ip
	Port int32
}

type endpointID struct {
	Namespace string
	Endpoint  *endpoint
}

// endpointKey returns a endpointID as namespace:endpoint-ip-address:endpoint-port
func endpointKey(e *endpointID) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	if e.Endpoint != nil {
		values = append(values, string(e.Endpoint.Port))
	}

	return strings.Join(values, ":")
}

// endpointKeyNoPort returns a endpointID as scope:namespace:endpoint-ip-address
func endpointKeyNoPort(e *endpointID) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	return strings.Join(values, ":")
}

// CreateNetworkRelationIdentifier returns an identification for the relation this connection may contribute to
func CreateNetworkRelationIdentifier(namespace string, conn common.ConnectionStats) string {
	isV6 := conn.Family == common.AF_INET6
	localEndpoint := makeEndpointID(namespace, conn.Local, isV6, int32(conn.LocalPort))
	remoteEndpoint := makeEndpointID(namespace, conn.Remote, isV6, int32(conn.RemotePort))
	return createRelationIdentifier(localEndpoint, remoteEndpoint, calculateDirection(conn.Direction))
}

// connectionRelationIdentifier returns an identification for the relation this connection may contribute to
func createRelationIdentifier(localEndpoint, remoteEndpoint *endpointID, direction model.ConnectionDirection) string {

	// For directional relations, connections with the same source ip are grouped (port is ignored)
	// For non-directed relations ports are ignored on both sides
	switch direction {
	case model.ConnectionDirection_incoming:
		return fmt.Sprintf("in:%s:%s", endpointKey(localEndpoint), endpointKeyNoPort(localEndpoint))
	case model.ConnectionDirection_outgoing:
		return fmt.Sprintf("out:%s:%s", endpointKeyNoPort(localEndpoint), endpointKey(remoteEndpoint))
	default:
		return fmt.Sprintf("none:%s:%s", endpointKeyNoPort(localEndpoint), endpointKeyNoPort(remoteEndpoint))
	}
}

// makeEndpointID returns a endpointID if the ip is valid and the hostname as the scope for local ips
func makeEndpointID(namespace string, ipString string, isV6 bool, port int32) *endpointID {
	// We parse the ip here for normalization
	ipAddress := net.ParseIP(ipString)
	if ipAddress == nil {
		return nil
	}
	endpoint := &endpointID{
		Namespace: namespace,
		Endpoint: &endpoint{
			ip: &ip{
				Address: ipAddress.String(),
				IsIPv6:  isV6,
			},
			Port: port,
		},
	}

	return endpoint
}

// Represents the namespace part of connection identity. The connection namespace
// determines its locality (e.g. the scope in which the network resides)
type namespace struct {
	ClusterName      string
	HostName         string
	NetworkNamespace string
}

func (ns namespace) toString() string {
	var fragments []string
	if ns.ClusterName != "" {
		fragments = append(fragments, ns.ClusterName)
	}
	if ns.HostName != "" {
		fragments = append(fragments, ns.HostName)
	}
	if ns.NetworkNamespace != "" {
		fragments = append(fragments, ns.NetworkNamespace)
	}
	return strings.Join(fragments, ":")
}

func makeNamespace(clusterName string, hostname string, connection common.ConnectionStats) namespace {
	// check if we're running in kubernetes, prepend the namespace with the kubernetes / openshift cluster name
	var ns = namespace{"", "", ""}
	if clusterName != "" {
		ns.ClusterName = clusterName
	}

	// In order to tell different pod-local ip addresses from each other,
	// treat each loopback address as local to the network namespace
	// Reference implementation: https://github.com/weaveworks/scope/blob/master/report/id.go#L40
	// https://github.com/weaveworks/scope/blob/7163f42170d72702fd55d2324d203c5b7be5c5cc/probe/endpoint/ebpf.go#L34
	// We disregard local ip addresses for now, those might be interesting when doing docker setups,
	// which are not the highest priority atm
	if isLoopback(connection.Local) && isLoopback(connection.Remote) {
		// For sure this is scoped to the host
		ns.HostName = hostname
		// Maybe even to a namespace on the host in case of k8s/docker containers
		if connection.NetworkNamespace != "" {
			ns.NetworkNamespace = connection.NetworkNamespace
		}
	}

	return ns
}

func formatNamespace(clusterName string, hostname string, connection common.ConnectionStats) string {
	return makeNamespace(clusterName, hostname, connection).toString()
}

func isLoopback(ip string) bool {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return false
	}
	return ipAddress.IsLoopback()
}

func formatFamily(f common.ConnectionFamily) model.ConnectionFamily {
	switch f {
	case common.AF_INET:
		return model.ConnectionFamily_v4
	case common.AF_INET6:
		return model.ConnectionFamily_v6
	default:
		return -1
	}
}

func formatType(f common.ConnectionType) model.ConnectionType {
	switch f {
	case common.TCP:
		return model.ConnectionType_tcp
	case common.UDP:
		return model.ConnectionType_udp
	default:
		return -1
	}
}

func calculateDirection(d common.Direction) model.ConnectionDirection {
	switch d {
	case common.OUTGOING:
		return model.ConnectionDirection_outgoing
	case common.INCOMING:
		return model.ConnectionDirection_incoming
	default:
		return model.ConnectionDirection_none
	}
}

// retryTracerInit tries to create a network tracer with a given retry duration and retry amount
func retryTracerInit(retryDuration time.Duration, retryAmount int, config *tracerConfig.Config,
	makeTracer func(*tracerConfig.Config) (tracer.Tracer, error)) (tracer.Tracer, error) {

	retryTicker := time.NewTicker(retryDuration)
	retriesLeft := retryAmount

	var t tracer.Tracer
	var err error

retry:
	for {
		select {
		case <-retryTicker.C:
			t, err = makeTracer(config)
			if err == nil {
				break retry
			}
			log.Debugf("failed to create network tracer: %s. Retrying..", err)
			retriesLeft = retriesLeft - 1
			if retriesLeft == 0 {
				break retry
			}
		}
	}

	return t, err
}
