module github.com/StackVista/stackstate-process-agent

go 1.13

replace (
	github.com/benesch/cgosymbolizer => github.com/benesch/cgosymbolizer v0.0.0-20190515212042-bec6fe6e597b
	// next line until pr https://github.com/ianlancetaylor/cgosymbolizer/pull/8 is merged
	github.com/ianlancetaylor/cgosymbolizer => github.com/ianlancetaylor/cgosymbolizer v0.0.0-20170921033129-f5072df9c550
)

// Internal deps fix version
replace (
	bitbucket.org/ww/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/DataDog/sketches-go v1.1.0 => github.com/StackVista/sketches-go v1.1.0
	github.com/cihub/seelog => github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf // v2.6
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190104202606-0ac367fd6bee+incompatible
	github.com/iovisor/gobpf => github.com/StackVista/gobpf v0.1.2
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
	github.com/spf13/viper => github.com/DataDog/viper v1.7.1
)

// Pinned to kubernetes-1.16.2
replace github.com/kubernetes-incubator/custom-metrics-apiserver => github.com/kubernetes-incubator/custom-metrics-apiserver v0.0.0-20190918110929-3d9be26a50eb

// Pinned to kubernetes-1.16.2
replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110408-35e52d86657a
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113550-5357c4baaf65
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115801-a2eda9f80ab8
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191016112112-5190913f932d
	k8s.io/autoscaler => k8s.io/autoscaler v0.0.0-20191115143342-4cf961056038
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20191016114015-74ad18325ed5
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016111102-bec269661e48
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20191016115326-20453efc2458
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20191016115129-c07a134afb42
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20191004115455-8e001e5d1894
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191016111319-039242c015a9
	k8s.io/cri-api => k8s.io/cri-api v0.0.0-20190828162817-608eb1dad4ac
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20191016115521-756ffa5af0bd
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191016112429-9587704a8ad4
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20191016114939-2b2b218dc1df
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20191016114407-2e83b6f20229
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20191016114748-65049c67a58b
	k8s.io/kube-state-metrics => k8s.io/kube-state-metrics v1.9.6-0.20200413182837-dbbe062e36a4
	k8s.io/kubectl => k8s.io/kubectl v0.0.0-20191016120415-2ed914427d51
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20191016114556-7841ed97f1b2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20191016115753-cf0698c3a16b
	k8s.io/metrics => k8s.io/metrics v0.0.0-20191016113814-3b1a734dba6e
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20191016112829-06bb3c9d77c9
)

// // Pinned so it includes fix for Windows Nano
// replace k8s.io/klog => k8s.io/klog v1.0.1-0.20200310124935-4ad0115ba9e4

require (
	github.com/DataDog/datadog-go v3.5.0+incompatible
	github.com/DataDog/gopsutil v0.0.0-20200624212600-1b53412ef321
	github.com/DataDog/sketches-go v1.1.0
	github.com/DataDog/zstd v0.0.0-20160706220725-2bf71ec48360
	github.com/StackExchange/wmi v0.0.0-20181212234831-e0a55b97c705
	github.com/StackVista/stackstate-agent v0.0.0-20220225140258-08ce097fa365
	github.com/StackVista/tcptracer-bpf v7.0.4+incompatible
	github.com/awalterschulze/goderive v0.0.0-20211221145202-5dcbfa700308 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/go-ini/ini v1.55.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/iovisor/gobpf v0.1.2 // indirect
	github.com/kubernetes-incubator/custom-metrics-apiserver v0.0.0-20190116221620-b7016fc85e1c // indirect
	github.com/mailru/easyjson v0.7.7
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pytimer/win-netstat v0.0.0-20180710031115-efa1aff6aafc // indirect
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/smartystreets/goconvey v1.7.2 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/sys v0.0.0-20220224120231-95c6836cb0e7
	golang.org/x/tools v0.1.9 // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/yaml.v2 v2.2.8
)
