package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	agentkubernetes "github.com/DataDog/datadog-agent/pkg/metadata/kubernetes"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/util/cache"
	"github.com/DataDog/datadog-process-agent/util/docker"
)

var (
	ErrKubernetesNotAvailable = errors.New("kubernetes not available")
	globalKubeUtil            *kubeUtil
)

// InitKubeUtil initializes a global kubeUtil used by later function calls.
func InitKubeUtil(kubeletHost string, httpKubeletePort, httpsKubeletPort int) error {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return ErrKubernetesNotAvailable
	}

	kubeletURL, err := locateKubelet(kubeletHost, httpKubeletePort, httpsKubeletPort)
	if err != nil {
		return err
	}
	globalKubeUtil = &kubeUtil{kubeletAPIURL: kubeletURL}

	return nil
}

// Expose module-level functions that will interact with a Singleton KubeUtil.
func GetMetadata() *agentpayload.KubeMetadataPayload {
	if globalKubeUtil != nil {
		return globalKubeUtil.getKubernetesMeta()
	}
	return nil
}

// IsKubernetes returns true if we're running inside a Kubernetes container.
func IsKubernetes() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// Kubelet constants
const (
	authTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	kubernetesMetaTTL = 3 * time.Minute

	// Kube creator types, from owner reference.
	kindDaemonSet             = "DaemonSet"
	kindReplicaSet            = "ReplicaSet"
	kindReplicationController = "ReplicationController"
	kindDeployment            = "Deployment"
	kindJob                   = "Job"
)

// Pod contains fields for unmarshalling a Pod
type Pod struct {
	Metadata ObjectMeta `json:"metadata,omitempty"`
	Spec     PodSpec    `json:"spec,omitempty"`
	Status   PodStatus  `json:"status,omitempty"`
}

// PodList contains fields for unmarshalling a PodList
type PodList struct {
	Items []*Pod `json:"items,omitempty"`
}

// PodSpec contains fields for unmarshalling a PodSpec
type PodSpec struct {
	HostNetwork bool   `json:"hostNetwork,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

// PodStatus contains fields for unmarshalling a PodStatus
type PodStatus struct {
	HostIP            string             `json:"hostIP,omitempty"`
	PodIP             string             `json:"podIP,omitempty"`
	ContainerStatuses []*ContainerStatus `json:"containerStatuses,omitempty"`
}

// ContainerStatus contains fields for unmarshaling a ContainerStatus
type ContainerStatus struct {
	Name        string `json:"name,omitempty"`
	ContainerID string `json:"containerID,omitempty"`
	Image       string `json:"image,omitempty"`
	ImageID     string `json:"imageID,omitempty"`
}

// ObjectMetadata contains the fields for unmarshaling Kubernetes resource metadata
// limited to just those fields we use in our metadata collection.
type ObjectMeta struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Uid             string            `json:"uid,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	OwnerReferences []*OwnerReference `json:"ownerReferences,omitempty"`
}

// OwnerReference contains information to identify an owning object limited to
// what we need for metadata collection.
type OwnerReference struct {
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

// kubeUtil is a struct to hold Kubernetes config state. It is unexported because
// all calls should go through the module-level functions (e.g. GetMetadata)
// that interact with the globalKubeUtil.
type kubeUtil struct {
	kubeletAPIURL string
	lastKubeErr   string
}

// GetKubernetesMeta returns a Kubernetes metadata payload using a mix of state from the
// Kube master and local kubelet.
func (ku *kubeUtil) getKubernetesMeta() *agentpayload.KubeMetadataPayload {
	// The whole metadata payload is cached to limit load on the master server.
	var kubeMeta *agentpayload.KubeMetadataPayload
	cacheKey := "kubernetes_meta"
	payload, ok := cache.Get(cacheKey)
	if !ok {
		payload, err := agentkubernetes.GetPayload()
		if err != nil {
			if err.Error() != ku.lastKubeErr {
				// Swallowing this error for now with an error as it shouldn't block collection.
				log.Errorf("Unable to get kubernetes metadata: %s", err)
				// Only log the same error once to prevent noisy logs.
				ku.lastKubeErr = err.Error()
			}
			return nil
		}
		kubeMeta = payload.(*agentpayload.KubeMetadataPayload)
		cache.SetWithTTL(cacheKey, kubeMeta, kubernetesMetaTTL)
	} else if payload != nil {
		kubeMeta = payload.(*agentpayload.KubeMetadataPayload)
	}

	if kubeMeta != nil {
		// But we can fetch local state from the kubelet and merge.
		localPods, err := ku.getLocalPodList()
		if err != nil {
			log.Errorf("Unable to get local pods from kubelet: %s", err)
		}
		pods, containers := parseLocalPods(localPods, kubeMeta.Services)
		kubeMeta.Pods = pods
		kubeMeta.Containers = containers
	}

	return kubeMeta
}

// getLocalPodList returns the list of pods running on the node where this pod is running
func (ku *kubeUtil) getLocalPodList() ([]*Pod, error) {
	data, err := performKubeletQuery(fmt.Sprintf("%s/pods", ku.kubeletAPIURL))
	if err != nil {
		return nil, fmt.Errorf("Error performing kubelet query: %s", err)
	}

	var v PodList
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("Error unmarshalling json: %s", err)
	}

	return v.Items, nil
}

// parseLocalPods will parse pods returned from a local kubelet query. Note that much of this
// is duplication of logic in the datadog-agent Kubernetes metadata provider but with varying
// types. We may want to consolidate at some point.
func parseLocalPods(
	localPods []*Pod,
	services []*agentpayload.KubeMetadataPayload_Service,
) ([]*agentpayload.KubeMetadataPayload_Pod, []*agentpayload.KubeMetadataPayload_Container) {
	pods := make([]*agentpayload.KubeMetadataPayload_Pod, 0, len(localPods))
	containers := make([]*agentpayload.KubeMetadataPayload_Container, 0)
	for _, p := range localPods {
		cids := make([]string, 0, len(p.Status.ContainerStatuses))
		for _, c := range p.Status.ContainerStatuses {
			containers = append(containers, &agentpayload.KubeMetadataPayload_Container{
				Name:    c.Name,
				Id:      c.ContainerID,
				Image:   c.Image,
				ImageId: c.ImageID,
			})
			cids = append(cids, c.ContainerID)
		}

		pod := &agentpayload.KubeMetadataPayload_Pod{
			Uid:          p.Metadata.Uid,
			Name:         p.Metadata.Name,
			Namespace:    p.Metadata.Namespace,
			HostIp:       p.Status.HostIP,
			PodIp:        p.Status.PodIP,
			Labels:       p.Metadata.Labels,
			ServiceUids:  findPodServices(p.Metadata.Namespace, p.Metadata.Labels, services),
			ContainerIds: cids,
		}
		setPodCreator(pod, p.Metadata.OwnerReferences)
		pods = append(pods, pod)
	}
	return pods, containers
}

func findPodServices(
	namespace string,
	labels map[string]string,
	services []*agentpayload.KubeMetadataPayload_Service,
) []string {
	uids := make([]string, 0)
	for _, s := range services {
		if s.Namespace != namespace {
			continue
		}
		match := true
		for k, search := range s.Selector {
			if v, ok := labels[k]; !ok || v != search {
				match = false
				break
			}
		}
		if match {
			uids = append(uids, s.Uid)
		}
	}
	return uids
}

func setPodCreator(pod *agentpayload.KubeMetadataPayload_Pod, ownerRefs []*OwnerReference) {
	for _, o := range ownerRefs {
		switch o.Kind {
		case kindDaemonSet:
			pod.DaemonSet = o.Name
		case kindReplicaSet:
			pod.ReplicaSet = o.Name
		case kindReplicationController:
			pod.ReplicationController = o.Name
		case kindJob:
			pod.Job = o.Name
		}
	}
}

// Try and find the hostname to query the kubelet
func locateKubelet(kubeletHost string, httpKubeletePort, httpsKubeletPort int) (string, error) {
	var err error
	hostname := kubeletHost
	if kubeletHost == "" {
		hostname, err = docker.GetHostname()
		if err != nil {
			return "", fmt.Errorf("Unable to get hostname from docker: %s", err)
		}
	}

	url := fmt.Sprintf("http://%s:%d", hostname, httpKubeletePort)
	if _, err := performKubeletQuery(url); err == nil {
		return url, nil
	}
	log.Debugf("Couldn't query kubelet over HTTP, assuming it's not in no_auth mode.")

	url = fmt.Sprintf("https://%s:%d", hostname, httpsKubeletPort)
	if _, err := performKubeletQuery(url); err == nil {
		return url, nil
	}

	return "", fmt.Errorf("Could not find a method to connect to kubelet")
}

// performKubeletQuery performs a GET query against kubelet and return the response body
func performKubeletQuery(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create request: %s", err)
	}

	if strings.HasPrefix(url, "https") {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", getAuthToken()))
	}

	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error executing request to %s: %s", url, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response from %s: %s", url, err)
	}
	return body, nil
}

// Read the kubelet token
func getAuthToken() string {
	token, err := ioutil.ReadFile(authTokenPath)
	if err != nil {
		log.Errorf("Could not read token from %s: %s", authTokenPath, err)
		return ""
	}
	return string(token)
}
