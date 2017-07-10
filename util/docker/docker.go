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
	ReadBytes  uint64
	WriteBytes uint64
}

func detectServerAPIVersion() (string, error) {
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

// GetDockerContainers returns a list of Docker info for
// active containers using the Docker API.
// This requires certain permission.
func GetDockerContainers() ([]*Container, error) {
	if os.Getenv("DOCKER_API_VERSION") == "" {
		version, err := detectServerAPIVersion()
		if err != nil {
			return nil, err
		}
		os.Setenv("DOCKER_API_VERSION", version)
	}
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	ret := make([]*Container, 0, len(containers))
	for _, c := range containers {
		ret = append(ret, &Container{
			Type:    "Docker",
			ID:      c.ID,
			Name:    c.Names[0],
			Image:   c.Image,
			ImageID: c.ImageID,
			Created: c.Created,
			State:   c.State,
		})
	}
	return ret, nil
}

// Generates a mapping of PIDs to container metadata. Optimized to limit the
// number of syscalls for each PID for just enough to get the data we need.
func ContainersByPID(pids []int32) (map[int32]*Container, error) {
	sockPath := util.GetEnv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
	if !util.PathExists(sockPath) {
		return nil, ErrDockerNotAvailable
	}
	cgByContainer, err := CgroupsForPids(pids)
	if err != nil {
		return nil, err
	}
	containers, err := GetDockerContainers()
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
		containerStat.WriteBytes = ioStat.ReadBytes
		for _, p := range cgroup.Pids {
			containerMap[p] = containerStat
		}
	}
	return containerMap, nil
}

func GetHostname() (string, error) {
	if os.Getenv("DOCKER_API_VERSION") == "" {
		version, err := detectServerAPIVersion()
		if err != nil {
			return "", err
		}
		os.Setenv("DOCKER_API_VERSION", version)
	}
	client, err := client.NewEnvClient()
	if err != nil {
		return "", err
	}
	info, err := client.Info(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to get Docker info: %s", err)
	}
	return info.Name, nil
}
