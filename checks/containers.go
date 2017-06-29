package checks

import (
	log "github.com/cihub/seelog"
	"os"
	"time"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	"github.com/DataDog/datadog-agent/pkg/metadata/kubernetes"
	"github.com/DataDog/datadog-process-agent/util/cache"
)

const (
	kubernetesMetaTTL = 3 * time.Minute
)

var lastKubeErr string

func GetKubernetesMeta() *agentpayload.KubeMetadataPayload {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		// If this is not defined then we're not running in a k8s cluster.
		return nil
	}

	var kubeMeta *agentpayload.KubeMetadataPayload
	cacheKey := "kubernetes_meta"
	payload, ok := cache.Get(cacheKey)
	if !ok {
		payload, err := kubernetes.GetPayload()
		if err != nil {
			if err.Error() != lastKubeErr {
				// Swallowing this error for now with an error as it shouldn't block collection.
				log.Errorf("Unable to get kubernetes metadata: %s", err)
				// Only log the same error once to prevent noisy logs.
				lastKubeErr = err.Error()
			}
			return nil
		}
		kubeMeta = payload.(*agentpayload.KubeMetadataPayload)
		cache.SetWithTTL(cacheKey, kubeMeta, kubernetesMetaTTL)
	} else if payload != nil {
		kubeMeta = payload.(*agentpayload.KubeMetadataPayload)
	}
	return kubeMeta
}
