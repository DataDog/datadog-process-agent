package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"net"
	"strings"
)

type Ip struct {
	Address string
	IsIPv6  bool
}

type Endpoint struct {
	Ip   *Ip
	Port int32
}

type EndpointId struct {
	Namespace string
	Endpoint  *Endpoint
}

// endpointKey returns a EndpointId as namespace:endpoint-ip-address:endpoint-port
func endpointKey(e *EndpointId) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.Ip != nil {
		values = append(values, e.Endpoint.Ip.Address)
	}

	if e.Endpoint != nil {
		values = append(values, string(e.Endpoint.Port))
	}

	return strings.Join(values, ":")
}

// endpointKeyNoPort returns a EndpointId as scope:namespace:endpoint-ip-address
func endpointKeyNoPort(e *EndpointId) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.Ip != nil {
		values = append(values, e.Endpoint.Ip.Address)
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
func createRelationIdentifier(localEndpoint, remoteEndpoint *EndpointId, direction model.ConnectionDirection) string {

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


// makeEndpointID returns a EndpointId if the ip is valid and the hostname as the scope for local ips
func makeEndpointID(namespace string, ip string, isV6 bool, port int32) *EndpointId {
	// We parse the ip here for normalization
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return nil
	}
	endpoint := &EndpointId{
		Namespace: namespace,
		Endpoint: &Endpoint{
			Ip: &Ip{
				Address: ipAddress.String(),
				IsIPv6:  isV6,
			},
			Port: port,
		},
	}

	return endpoint
}

func formatNamespace(clusterName string, hostname string, connection common.ConnectionStats) string {
	// check if we're running in kubernetes, prepend the namespace with the kubernetes / openshift cluster name
	var fragments []string
	if clusterName != "" {
		fragments = append(fragments, clusterName)
	}

	// In order to tell different pod-local ip addresses from each other,
	// treat each loopback address as local to the network namespace
	// Reference implementation: https://github.com/weaveworks/scope/blob/master/report/id.go#L40
	// https://github.com/weaveworks/scope/blob/7163f42170d72702fd55d2324d203c5b7be5c5cc/probe/endpoint/ebpf.go#L34
	// We disregard local ip addresses for now, those might be interesting when doing docker setups,
	// which are not the highest priority atm
	if (isLoopback(connection.Local) || isLoopback(connection.Remote)) {
		// For sure this is scoped to the host
		fragments = append(fragments, hostname)
		// Maybe even to a namespace on the host in case of k8s
		if connection.NetworkNamespace != "" {
			fragments = append(fragments, connection.NetworkNamespace)
		}
	}
	return strings.Join(fragments, ":")
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
