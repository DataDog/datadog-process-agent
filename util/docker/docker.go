package docker

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"github.com/DataDog/datadog-process-agent/util"
)

var (
	ErrDockerNotAvailable = errors.New("docker not available")
	globalDockerUtil      *dockerUtil
)

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
}

type dockerUtil struct {
	cli *client.Client
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

	globalDockerUtil = &dockerUtil{cli}
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
