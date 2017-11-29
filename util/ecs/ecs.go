package ecs

import (
	"errors"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	agentecs "github.com/DataDog/datadog-agent/pkg/metadata/ecs"
	"github.com/DataDog/datadog-agent/pkg/util/ecs"
	log "github.com/cihub/seelog"
)

var (
	// ErrECSNotAvailable is returned if ECS is not available on this machine.
	ErrECSNotAvailable = errors.New("ecs not available")

	lastErr       string
	globalECSUtil *ecsUtil
)

// InitECSUtil initializes a global ecsUtil used by later function calls.
func InitECSUtil() error {
	// If we have an ECS listener then we'll use the local API
	var listeners []ddconfig.Listeners
	if err := ddconfig.Datadog.UnmarshalKey("listeners", &listeners); err != nil {
		log.Warnf("unable to parse listeners from the datadog config: %s", err)
	} else {
		for _, l := range listeners {
			if l.Name == "ecs" {
				globalECSUtil = &ecsUtil{metadataSource: "api"}
				return nil
			}
		}
	}

	// Otherwise let's try to find a local ECS-agent
	_, err := agentecs.GetPayload()
	if err == nil {
		globalECSUtil = &ecsUtil{metadataSource: "agent"}
		return nil
	}

	if !ecs.IsAgentNotDetected(err) {
		log.Errorf("unable to configure ECS metada collection: %s", err)
	}

	// If we don't succeed in either case return a known error.
	return ErrECSNotAvailable
}

// GetMetadata returns the metadata from the local ECS agent if available.
func GetMetadata() *agentpayload.ECSMetadataPayload {
	if globalECSUtil != nil {
		return globalECSUtil.getMetadata()
	}

	return nil
}

type ecsUtil struct {
	metadataSource string
}

func (e *ecsUtil) getMetadata() *agentpayload.ECSMetadataPayload {
	switch e.metadataSource {
	case "agent":
		payload, err := agentecs.GetPayload()
		if err != nil && err.Error() != lastErr {
			// Don't bubble up the error, just log it.
			log.Errorf("error getting ECS metadata from agent: %s", err)
			lastErr = err.Error()
			return nil
		}
		return payload.(*agentpayload.ECSMetadataPayload)
	case "api":
		meta, err := ecs.GetTaskMetadata()
		if err != nil && err.Error() != lastErr {
			// Don't bubble up the error, just log it.
			log.Errorf("error getting ECS metadata from API: %s", err)
			lastErr = err.Error()
			return nil
		}
		return parseTaskMetadata(meta)
	}
	return nil
}

func parseTaskMetadata(meta ecs.TaskMetadata) *agentpayload.ECSMetadataPayload {
	containers := make([]*agentpayload.ECSMetadataPayload_Container, 0, len(meta.Containers))
	for _, c := range meta.Containers {
		containers = append(containers, &agentpayload.ECSMetadataPayload_Container{
			DockerId:   c.DockerID,
			DockerName: c.DockerName,
			Name:       c.Name,
		})
	}

	task := &agentpayload.ECSMetadataPayload_Task{
		Arn:           meta.TaskARN,
		DesiredStatus: meta.DesiredStatus,
		KnownStatus:   meta.KnownStatus,
		Family:        meta.Family,
		Version:       meta.Version,
		Containers:    containers,
	}

	return &agentpayload.ECSMetadataPayload{
		Tasks: []*agentpayload.ECSMetadataPayload_Task{task},
	}
}
