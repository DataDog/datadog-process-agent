package kubernetes

import (
	"errors"
	"fmt"
	"time"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	agentkubernetes "github.com/DataDog/datadog-agent/pkg/metadata/kubernetes"
	agentkubelet "github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/util/cache"
)

const (
	cacheKey                   = "kubernetes_meta"
	kubernetesServiceTagPrefix = "kube_service:"
	kubernetesMetaTTL          = 3 * time.Minute
)

var (
	// ErrKubernetesNotAvailable if the machine is not running in Kubernetes.
	ErrKubernetesNotAvailable = errors.New("kubernetes not available")

	globalKubeUtil *agentkubelet.KubeUtil
	lastKubeErr    string
)

// InitKubeUtil initializes a global kubeUtil used by later function calls.
// We keep track of our own global kubeUtil even though the agentkubelet already does to prevent a noisy log
func InitKubeUtil() error {
	if ku, err := agentkubelet.GetKubeUtil(); err == nil {
		globalKubeUtil = ku
		return nil
	}
	return ErrKubernetesNotAvailable
}

// GetContainerServiceTags returns a map of container ID to list of kubernetes service names.
// Tags are prefixed with the identifier "kube_service:"
func GetContainerServiceTags() (containerServices map[string][]string) {
	containerServices = make(map[string][]string)
	if globalKubeUtil == nil {
		return
	}

	localPods, err := globalKubeUtil.GetLocalPodList()
	if kubeMeta := getKubernetesMeta(); kubeMeta != nil && err == nil {
		for _, p := range localPods {
			services := findServicesTagsForPod(p, kubeMeta)
			for _, c := range p.Status.Containers {
				if len(services) > 0 {
					containerServices[c.ID] = services
				}
			}
		}
	} else if err != nil {
		log.Errorf("Unable to get local pods from kubelet: %s", err)
	}
	return
}

func findServicesTagsForPod(pod *agentkubelet.Pod, kubeMeta *agentpayload.KubeMetadataPayload) []string {
	names := make([]string, 0)
	for _, s := range kubeMeta.Services {
		if s.Namespace != pod.Metadata.Namespace {
			continue
		}
		match := true
		for k, search := range s.Selector {
			if v, ok := pod.Metadata.Labels[k]; !ok || v != search {
				match = false
				break
			}
		}
		if match {
			names = append(names, fmt.Sprintf("%s%s", kubernetesServiceTagPrefix, s.Name))
		}
	}
	return names
}

func getKubernetesMeta() (kubeMeta *agentpayload.KubeMetadataPayload) {
	if payload, ok := cache.Get(cacheKey); ok {
		kubeMeta = payload.(*agentpayload.KubeMetadataPayload)
	} else {
		if p, err := agentkubernetes.GetPayload(); err == nil {
			kubeMeta = p.(*agentpayload.KubeMetadataPayload)
			cache.SetWithTTL(cacheKey, kubeMeta, kubernetesMetaTTL)
		} else if err.Error() != lastKubeErr {
			// Swallowing this error for now with an error as it shouldn't block collection.
			log.Errorf("Unable to get kubernetes metadata: %s", err)
			// Only log the same error once to prevent noisy logs.
			lastKubeErr = err.Error()
		}
	}
	return
}
