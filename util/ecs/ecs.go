package ecs

import (
	"errors"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	agentecs "github.com/DataDog/datadog-agent/pkg/metadata/ecs"
	log "github.com/cihub/seelog"
)

var (
	ErrECSNotAvailable = errors.New("ecs not available")
	lastErr            string
	globalECSUtil      *ecsUtil
)

// InitECSUtil initializes a global ecsUtil used by later function calls.
func InitECSUtil() error {
	_, err := agentecs.GetPayload()
	if err != nil {
		if !agentecs.IsAgentNotDetected(err) {
			log.Errorf("unable to configure ECS metada collection: %s", err)
		}
		return ErrECSNotAvailable
	}

	globalECSUtil = &ecsUtil{}
	return nil
}

// GetMetadata returns the metadata from the local ECS agent if available.
func GetMetadata() *agentpayload.ECSMetadataPayload {
	if globalECSUtil != nil {
		return globalECSUtil.getMetadata()
	}
	return nil
}

type ecsUtil struct{}

func (e *ecsUtil) getMetadata() *agentpayload.ECSMetadataPayload {
	payload, err := agentecs.GetPayload()
	if err != nil && err.Error() != lastErr {
		// Don't bubble up the error, just log it.
		log.Errorf("error getting ECS metadata: %s", err)
		lastErr = err.Error()
		return nil
	}
	return payload.(*agentpayload.ECSMetadataPayload)
}
