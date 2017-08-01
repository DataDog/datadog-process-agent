package docker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/cihub/seelog"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"github.com/DataDog/datadog-process-agent/util"
)

var (
	ErrDockerNotAvailable = errors.New("docker not available")
	globalDockerUtil      *dockerUtil
	invalidationInterval  = 5 * time.Minute
)

type NetworkStat struct {
	BytesSent   uint64
	BytesRcvd   uint64
	PacketsSent uint64
	PacketsRcvd uint64
}

type Container struct {
	Type       string
	ID         string
	Name       string
	Image      string
	ImageID    string
	CPULimit   float64
	MemLimit   uint64
	Created    int64
	State      string
	Health     string
	ReadBytes  uint64
	WriteBytes uint64
	Network    *NetworkStat
}

type dockerNetwork struct {
	iface      string
	dockerName string
}

type dockerNetworks []dockerNetwork

func (a dockerNetworks) Len() int           { return len(a) }
func (a dockerNetworks) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a dockerNetworks) Less(i, j int) bool { return a[i].dockerName < a[j].dockerName }

// dockerUtil wraps interactions with a local docker API. It is not thread-safe.
type dockerUtil struct {
	cli *client.Client
	// tracks the last time we invalidate our internal caches
	lastInvalidate time.Time
	// networkMappings by container id
	networkMappings map[string][]dockerNetwork
}

//
// Expose module-level functions that will interact with a Singleton dockerUtil.

func ContainersForPIDs(pids []int32) (map[int32]*Container, error) {
	if globalDockerUtil != nil {
		return globalDockerUtil.containersForPIDs(pids)
	}
	return map[int32]*Container{}, nil
}

func GetHostname() (string, error) {
	if globalDockerUtil != nil {
		return "", ErrDockerNotAvailable
	}
	return globalDockerUtil.getHostname()
}

// InitDockerUtil initializes the global dockerUtil singleton. This _must_ be
// called before accessing any of the top-level docker calls.
func InitDockerUtil() error {
	// If we don't have a docker.sock then return a known error.
	sockPath := util.GetEnv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
	if !util.PathExists(sockPath) {
		return ErrDockerNotAvailable
	}

	serverVersion, err := detectServerAPIVersion()
	if err != nil {
		return err
	}
	os.Setenv("DOCKER_API_VERSION", serverVersion)

	// Connect again using the known server version.
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}

	globalDockerUtil = &dockerUtil{
		cli:             cli,
		networkMappings: make(map[string][]dockerNetwork),
		lastInvalidate:  time.Now(),
	}
	return nil
}

// getContainers returns a list of Docker info for active containers using the
// Docker API. This requires the running user to be in the "docker" user group
// or have access to /tmp/docker.sock.
func (d *dockerUtil) getContainers() ([]*Container, error) {
	containers, err := d.cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	ret := make([]*Container, 0, len(containers))
	for _, c := range containers {
		// We could have lost the container between list and inspect so ignore these errors.
		i, err := d.cli.ContainerInspect(context.Background(), c.ID)
		if err != nil && client.IsErrContainerNotFound(err) {
			return nil, err
		}

		// FIXME: We might need to invalidate this cache if a containers networks are changed live.
		if _, ok := d.networkMappings[c.ID]; !ok {
			d.networkMappings[c.ID] = findDockerNetworks(c.ID, i.State.Pid, c.NetworkSettings)
		}

		var health string
		// Healthcheck and status not available until >= 1.12
		if i.State.Health != nil {
			health = i.State.Health.Status
		}

		ret = append(ret, &Container{
			Type:    "Docker",
			ID:      c.ID,
			Name:    c.Names[0],
			Image:   c.Image,
			ImageID: c.ImageID,
			Created: c.Created,
			State:   c.State,
			Health:  health,
		})
	}

	if d.lastInvalidate.Add(invalidationInterval).After(time.Now()) {
		d.invalidateCaches(containers)
	}

	return ret, nil
}

// containersForPIDs Generates a mapping of PIDs to container metadata with
// filled stats. Calls are meant tolimit the number of syscalls for each PID for
// just enough to get the data we need.
func (d *dockerUtil) containersForPIDs(pids []int32) (map[int32]*Container, error) {
	cgByContainer, err := CgroupsForPids(pids)
	if err != nil {
		return nil, err
	}
	containers, err := d.getContainers()
	if err != nil {
		return nil, err
	}
	containerMap := make(map[int32]*Container)
	for _, containerStat := range containers {
		cgroup, ok := cgByContainer[containerStat.ID]
		if !ok {
			continue
		}
		memstat, err := cgroup.Mem()
		if err != nil {
			return nil, err
		}
		cpuLimit, err := cgroup.CPULimit()
		if err != nil {
			return nil, err
		}
		ioStat, err := cgroup.IO()
		if err != nil {
			return nil, err
		}

		networks, ok := d.networkMappings[cgroup.ContainerID]
		if ok && len(cgroup.Pids) > 0 {
			netStat, err := collectNetworkStats(cgroup.ContainerID, cgroup.Pids[0], networks)
			containerStat.Network = netStat
		}
		containerStat.MemLimit = memstat.MemLimitInBytes
		containerStat.CPULimit = cpuLimit
		containerStat.ReadBytes = ioStat.ReadBytes
		containerStat.WriteBytes = ioStat.WriteBytes

		for _, p := range cgroup.Pids {
			containerMap[p] = containerStat
		}
	}
	return containerMap, nil
}

func (d *dockerUtil) getHostname() (string, error) {
	info, err := d.cli.Info(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to get Docker info: %s", err)
	}
	return info.Name, nil
}

func (d *dockerUtil) invalidateCaches(containers []*types.ContainerJSON) {
	liveContainers := make(map[string]struct{})
	for _, c := range containers {
		c[c.ID] = struct{}{}
	}
	for cid := range d.networkMappings {
		if _, ok := liveContainers[cid]; !ok {
			delete(d.networkMappings, cid)
		}
	}
}

func detectServerAPIVersion() (string, error) {
	if os.Getenv("DOCKER_API_VERSION") != "" {
		return os.Getenv("DOCKER_API_VERSION"), nil
	}
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = client.DefaultDockerHost
	}
	cli, err := client.NewClient(host, "", nil, nil)
	if err != nil {
		return "", err
	}

	// Create the client using the server's API version
	v, err := cli.ServerVersion(context.Background())
	if err != nil {
		return "", err
	}
	return v.APIVersion, nil
}

var hostNetwork = dockerNetwork{"eth0", "bridge"}

func findDockerNetworks(containerID string, pid int, netSettings *types.SummaryNetworkSettings) []dockerNetwork {
	var err error
	dockerGateways := make(map[string]int64)
	for netName, netConf := range netSettings.Networks {
		gw := netConf.Gateway
		if netName == "host" || gw == "" {
			log.Debugf("Empty network gateway, container %s is in network host mode, its network metrics are for the whole host", containerID)
			return []dockerNetwork{hostNetwork}
		}

		// Check if this is a CIDR or just an IP
		var ip net.IP
		if strings.Contains(gw, "/") {
			ip, _, err = net.ParseCIDR(gw)
			if err != nil {
				log.Warnf("Invalid gateway %s for container id %s: %s, skipping", gw, containerID, err)
				continue
			}
		} else {
			ip = net.ParseIP(gw)
			if ip == nil {
				log.Warnf("Invalid gateway %s for container id %s: %s, skipping", gw, containerID, err)
				continue
			}
		}

		// Convert IP to int64 for comparison to network routes.
		dockerGateways[netName] = int64(binary.BigEndian.Uint32(ip.To4()))
	}

	// Read contents of file. Handle missing or unreadable file in case container was stopped.
	procNetFile := util.HostProc(strconv.Itoa(int(pid)), "net", "route")
	if !util.PathExists(procNetFile) {
		log.Debugf("Missing %s for container %s", procNetFile, containerID)
		return nil
	}
	lines, err := util.ReadLines(procNetFile)
	if err != nil {
		log.Debugf("Unable to read %s for container %s", procNetFile, containerID)
		return nil
	}
	if len(lines) < 1 {
		log.Errorf("empty network file, unable to get docker networks: %s", procNetFile)
		return nil
	}

	networks := make([]dockerNetwork, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[0] == "00000000" {
			continue
		}
		dest, _ := strconv.ParseInt(fields[1], 16, 32)
		mask, _ := strconv.ParseInt(fields[7], 16, 32)
		for net, gw := range dockerGateways {
			if gw&mask == dest {
				networks = append(networks, dockerNetwork{fields[0], net})
			}
		}
	}
	sort.Sort(dockerNetworks(networks))
	return networks
}

func collectNetworkStats(containerID string, pid int, networks []dockerNetwork) (*NetworkStat, error) {
	procNetFile := util.HostProc(strconv.Itoa(int(pid)), "net", "dev")
	if !util.PathExists(procNetFile) {
		log.Debugf("Unable to read %s for container %s", procNetFile, containerID)
		return &NetworkStat{}, nil
	}
	lines, err := util.ReadLines(procNetFile)
	if err != nil {
		log.Debugf("Unable to read %s for container %s", procNetFile, containerID)
		return &NetworkStat{}, nil
	}
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid format for %s", procNetFile)
	}

	nwByIface := make(map[string]dockerNetwork)
	for _, nw := range networks {
		nwByIface[nw.iface] = nw
	}

	// Format:
	//
	// Inter-|   Receive                                                |  Transmit
	// face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
	// eth0:    1296      16    0    0    0     0          0         0        0       0    0    0    0     0       0          0
	// lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
	//
	stat := &NetworkStat{}
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		iface := fields[0][:len(fields[0])-1]

		if _, ok := nwByIface[iface]; ok {
			rcvd, _ := strconv.Atoi(fields[1])
			stat.BytesRcvd += uint64(rcvd)
			pktRcvd, _ := strconv.Atoi(fields[2])
			stat.PacketsRcvd += uint64(pktRcvd)
			sent, _ := strconv.Atoi(fields[9])
			stat.BytesSent += uint64(sent)
			pktSent, _ := strconv.Atoi(fields[10])
			stat.PacketsSent += uint64(pktSent)
		}
	}
	return stat, nil
}
