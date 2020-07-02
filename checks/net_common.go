package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"net"
	"strings"
)

// endpointKey returns a EndpointId as scope:namespace:endpoint-ip-address:endpoint-port
func endpointKey(e *model.EndpointId) string {
	var values []string
	values = append(values, e.Scope)
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
func endpointKeyNoPort(e *model.EndpointId) string {
	var values []string
	values = append(values, e.Scope)
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.Ip != nil {
		values = append(values, e.Endpoint.Ip.Address)
	}

	return strings.Join(values, ":")
}

// CreateNetworkRelationIdentifier returns an identification for the relation this connection may contribute to
func CreateNetworkRelationIdentifier(hostname string, conn common.ConnectionStats) string {
	isV6 := conn.Family == common.AF_INET6
	localEndpoint := makeEndpointID(hostname, conn.Local, isV6, int32(conn.LocalPort), conn.NetworkNamespace)
	remoteEndpoint := makeEndpointID(hostname, conn.Remote, isV6, int32(conn.RemotePort), conn.NetworkNamespace)
	return createRelationIdentifier(localEndpoint, remoteEndpoint, calculateDirection(conn.Direction))
}

// connectionRelationIdentifier returns an identification for the relation this connection may contribute to
func createRelationIdentifier(localEndpoint, remoteEndpoint *model.EndpointId, direction model.ConnectionDirection) string {

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
func makeEndpointID(hostname, ip string, isV6 bool, port int32, namespace string) *model.EndpointId {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return nil
	}
	endpoint := &model.EndpointId{
		Namespace: namespace,
		Endpoint: &model.Endpoint{
			Ip: &model.Ip{
				Address: ipAddress.String(),
				IsIPv6:  isV6,
			},
			Port: port,
		},
	}
	// In order to tell different pod-local ip addresses from each other,
	// treat each loopback address as local to the network namespace
	// Reference implementation: https://github.com/weaveworks/scope/blob/master/report/id.go#L40
	if ipAddress.IsLoopback() {
		endpoint.Scope = hostname
	}

	return endpoint
}

func formatNamespace(clusterName string, n string) string {
	// check if we're running in kubernetes, prepend the namespace with the kubernetes / openshift cluster name
	var fragments []string
	if clusterName != "" {
		fragments = append(fragments, clusterName)
	}
	if n != "" {
		fragments = append(fragments, n)
	}
	return strings.Join(fragments, ":")
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
