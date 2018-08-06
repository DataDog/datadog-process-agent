package util

import (
	"errors"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/collectors"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var detector *collectors.Detector
var containerCacheDuration = 10 * time.Second

func SetContainerSource(name string) {
	detector = collectors.NewDetector(name)
}

func GetContainers() ([]*containers.Container, error) {
	// Detect source
	if detector == nil {
		detector = collectors.NewDetector("")
	}
	l, name, err := detector.GetPreferred()
	if err != nil {
		return nil, err
	}

	// Get containers from cache and update metrics
	cacheKey := cache.BuildAgentKey("containers", name)
	cached, hit := cache.Cache.Get(cacheKey)
	if hit {
		containers, ok := cached.([]*containers.Container)
		if ok {
			err := l.UpdateMetrics(containers)
			log.Infof("Got %d containers from cache", len(containers))
			return containers, err
		} else {
			log.Errorf("Invalid container list cache format, forcing a cache miss")
			hit = false
		}
	}
	// If cache empty/expired, get a new container list
	if !hit {
		containers, err := l.List()
		if err != nil {
			return nil, err
		}
		cache.Cache.Set(cacheKey, containers, containerCacheDuration)
		log.Infof("Got %d containers from source %s", len(containers), name)
		return containers, nil
	}
	return nil, errors.New("")
}

type ContainerRateMetrics struct {
	CPU        *metrics.CgroupTimesStat
	IO         *metrics.CgroupIOStat
	NetworkSum *metrics.InterfaceNetStats
}

var NullContainerRates = ContainerRateMetrics{
	CPU:        &metrics.CgroupTimesStat{},
	IO:         &metrics.CgroupIOStat{},
	NetworkSum: &metrics.InterfaceNetStats{},
}

func KeepContainerRateMetrics(containers []*containers.Container) map[string]ContainerRateMetrics {
	out := make(map[string]ContainerRateMetrics)
	for _, c := range containers {
		m := ContainerRateMetrics{
			CPU:        c.CPU,
			IO:         c.IO,
			NetworkSum: c.Network.SumInterfaces(),
		}
		out[c.ID] = m
	}
	return out
}
