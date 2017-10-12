package docker

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestParseCgroupMountPoints(t *testing.T) {
	for _, tc := range []struct {
		contents []string
		expected map[string]string
	}{
		{
			contents: []string{
				"",
				"foo bar",
				"cgroup /sys/fs/cgroup/cpuset cgroup rw,relatime,cpuset 0 0",
				"cgroup /sys/fs/cgroup/cpu,cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0",
				"cgroup /sys/fs/cgroup/devices cgroup rw,relatime,devices 0 0",
				"cgroup /sys/fs/cgroup/perf_event cgroup rw,relatime,perf_event 0 0",
				"cgroup /sys/fs/cgroup/hugetlb cgroup rw,relatime,hugetlb 0 0",
			},
			expected: map[string]string{
				"cpuset":     "/sys/fs/cgroup/cpuset",
				"cpu":        "/sys/fs/cgroup/cpu,cpuacct",
				"cpuacct":    "/sys/fs/cgroup/cpu,cpuacct",
				"devices":    "/sys/fs/cgroup/devices",
				"perf_event": "/sys/fs/cgroup/perf_event",
				"hugetlb":    "/sys/fs/cgroup/hugetlb",
			},
		},
		{
			contents: []string{
				"",
				"",
				"",
			},
			expected: map[string]string{},
		},
	} {
		contents := strings.NewReader(strings.Join(tc.contents, "\n"))
		assert.Equal(t, tc.expected, parseCgroupMountPoints(contents))
	}
}

// A variation on TestParseCgroupMountPoints using more realistic data.
func TestParseCgroupMountPointsAlt(t *testing.T) {
	for _, tc := range []struct {
		contents []string
		expected map[string]string
	}{
		{
			contents: []string{
				"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0 ",
				"tmpfs /dev tmpfs rw,nosuid,mode=755 0 0 ",
				"devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0 ",
				"sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0 ",
				"tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,relatime,mode=755 0 0 ",
				"openrc /sys/fs/cgroup/openrc cgroup ro,nosuid,nodev,noexec,relatime,release_agent=/lib/rc/sh/cgroup-release-agent.sh,name=openrc 0 0 ",
				"cpuset /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0 ",
				"cpu /sys/fs/cgroup/cpu cgroup ro,nosuid,nodev,noexec,relatime,cpu 0 0 ",
				"cpuacct /sys/fs/cgroup/cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpuacct 0 0 ",
				"blkio /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0 ",
				"memory /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0 ",
				"devices /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0 ",
				"freezer /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0 ",
				"net_cls /sys/fs/cgroup/net_cls cgroup ro,nosuid,nodev,noexec,relatime,net_cls 0 0 ",
				"perf_event /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0 ",
				"net_prio /sys/fs/cgroup/net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_prio 0 0 ",
				"hugetlb /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0 ",
				"pids /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0 ",
				"cgroup /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,name=systemd 0 0 ",
				"mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0 ",
				"/dev/xvdb1 /conf.d ext4 rw,relatime,data=ordered 0 0 ",
				"/dev/xvdb1 /checks.d ext4 rw,relatime,data=ordered 0 0 ",
				"proc /host/proc proc ro,relatime 0 0 ",
				"xenfs /host/proc/xen xenfs rw,nosuid,nodev,noexec,relatime 0 0 ",
				"binfmt_misc /host/proc/sys/fs/binfmt_misc binfmt_misc rw,nosuid,nodev,noexec,relatime 0 0 ",
				"/dev/xvdb1 /etc/resolv.conf ext4 rw,relatime,data=ordered 0 0 ",
				"/dev/xvdb1 /etc/hostname ext4 rw,relatime,data=ordered 0 0 ",
				"/dev/xvdb1 /etc/hosts ext4 rw,relatime,data=ordered 0 0 ",
				"shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0 ",
				"tmpfs /run/docker.sock tmpfs rw,nosuid,nodev,noexec,relatime,size=404072k,mode=755 0 0 ",
				"cgroup_root /host/sys/fs/cgroup tmpfs ro,relatime,size=10240k,mode=755 0 0 ",
				"openrc /host/sys/fs/cgroup/openrc cgroup rw,nosuid,nodev,noexec,relatime,release_agent=/lib/rc/sh/cgroup-release-agent.sh,name=openrc 0 0 ",
				"cpuset /host/sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0 ",
				"cpu /host/sys/fs/cgroup/cpu cgroup rw,nosuid,nodev,noexec,relatime,cpu 0 0 ",
				"cpuacct /host/sys/fs/cgroup/cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpuacct 0 0 ",
				"blkio /host/sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0 ",
				"memory /host/sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0 ",
				"devices /host/sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0 ",
				"freezer /host/sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0 ",
				"net_cls /host/sys/fs/cgroup/net_cls cgroup rw,nosuid,nodev,noexec,relatime,net_cls 0 0 ",
				"perf_event /host/sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0 ",
				"net_prio /host/sys/fs/cgroup/net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_prio 0 0 ",
				"hugetlb /host/sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0 ",
				"pids /host/sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0 ",
				"cgroup /host/sys/fs/cgroup/systemd cgroup rw,relatime,name=systemd 0 0 ",
				"proc /proc/bus proc ro,relatime 0 0 ",
				"proc /proc/fs proc ro,relatime 0 0 ",
				"proc /proc/irq proc ro,relatime 0 0 ",
				"proc /proc/sys proc ro,relatime 0 0 ",
				"proc /proc/sysrq-trigger proc ro,relatime 0 0 ",
				"tmpfs /proc/kcore tmpfs rw,nosuid,mode=755 0 0 ",
				"tmpfs /proc/timer_list tmpfs rw,nosuid,mode=755 0 0 ",
				"tmpfs /proc/sched_debug tmpfs rw,nosuid,mode=755 0 0 ",
				"tmpfs /sys/firmware tmpfs ro,relatime 0 0",
			},
			expected: map[string]string{
				"cpuset":     "/host/sys/fs/cgroup/cpuset",
				"cpu":        "/host/sys/fs/cgroup/cpu",
				"cpuacct":    "/host/sys/fs/cgroup/cpuacct",
				"devices":    "/host/sys/fs/cgroup/devices",
				"perf_event": "/host/sys/fs/cgroup/perf_event",
				"hugetlb":    "/host/sys/fs/cgroup/hugetlb",
				"blkio":      "/host/sys/fs/cgroup/blkio",
				"freezer":    "/host/sys/fs/cgroup/freezer",
				"memory":     "/host/sys/fs/cgroup/memory",
				"net_cls":    "/host/sys/fs/cgroup/net_cls",
				"net_prio":   "/host/sys/fs/cgroup/net_prio",
				"openrc":     "/host/sys/fs/cgroup/openrc",
				"pids":       "/host/sys/fs/cgroup/pids",
				"systemd":    "/host/sys/fs/cgroup/systemd",
			},
		},
		{
			contents: []string{
				"",
				"",
				"",
			},
			expected: map[string]string{},
		},
	} {
		contents := strings.NewReader(strings.Join(tc.contents, "\n"))
		assert.Equal(t, tc.expected, parseCgroupMountPoints(contents))
	}
}

func TestParseCgroupPaths(t *testing.T) {
	for _, tc := range []struct {
		contents          []string
		expectedContainer string
		expectedPaths     map[string]string
	}{
		{
			contents: []string{
				"11:net_cls:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"9:cpu,cpuacct:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"8:memory:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"7:blkio:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
			},
			expectedContainer: "47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
			expectedPaths: map[string]string{
				"net_cls": "/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"cpu":     "/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"cpuacct": "/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"memory":  "/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"blkio":   "/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
			},
		},
		{
			contents: []string{
				"",
				"11:net_cls:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
				"9:cpu,cpuacct:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e",
			},
			expectedContainer: "",
			expectedPaths:     nil,
		},
		{
			contents: []string{
				"6:memory:/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
				"5:cpuacct:/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
				"3:cpuset:/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
			},
			expectedContainer: "a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
			expectedPaths: map[string]string{
				"memory":  "/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
				"cpuacct": "/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
				"cpuset":  "/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
				// CPU is mising so we will automatically use from cpuacct
				"cpu": "/docker/a27f1331f6ddf72629811aac65207949fc858ea90100c438768b531a4c540419",
			},
		},
	} {
		contents := strings.NewReader(strings.Join(tc.contents, "\n"))
		c, p, err := parseCgroupPaths(contents)
		assert.NoError(t, err)
		assert.Equal(t, c, tc.expectedContainer)
		assert.Equal(t, p, tc.expectedPaths)
	}
}
