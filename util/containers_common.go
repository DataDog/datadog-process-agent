package util

import (
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
)

// NullContainer can be safely used for containers that have no
// previours values stored (new containers)
var NullContainer = &containers.Container{
	CPU:     &metrics.CgroupTimesStat{},
	Memory:  &metrics.CgroupMemStat{},
	IO:      &metrics.CgroupIOStat{},
	Network: metrics.ContainerNetStats{},
}
