//go:generate goderive .

package checks

import (
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"sync"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/statsd"
	"github.com/StackVista/stackstate-process-agent/util"
	log "github.com/cihub/seelog"
	cache "github.com/patrickmn/go-cache"
)

// Process is a singleton ProcessCheck.
var Process = &ProcessCheck{}

// ProcessCheck collects full state, including cmdline args and related metadata,
// for live and running processes. The instance will store some state between
// checks that will be used for rates, cpu calculations, etc.
type ProcessCheck struct {
	sync.Mutex

	sysInfo      *model.SystemInfo
	lastCPUTime  cpu.TimesStat
	lastCtrRates map[string]util.ContainerRateMetrics
	lastRun      time.Time

	// Last time we did a refresh of the published processes/containers
	lastRefresh time.Time

	// Fields to keep track of what we communicated last to the remote. This is used to determine incremental changes
	lastProcState map[int32]*model.Process
	lastCtrState  map[string]*model.Container

	// Use this as the process cache to calculate rate metrics and drop short-lived processes
	cache *cache.Cache
}

// Init initializes the singleton ProcessCheck.
func (p *ProcessCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	p.sysInfo = info
	p.cache = cache.New(cfg.ProcessCacheDurationMin, cfg.ProcessCacheDurationMin)
}

// Name returns the name of the ProcessCheck.
func (p *ProcessCheck) Name() string { return "process" }

// Endpoint returns the endpoint where this check is submitted.
func (p *ProcessCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (p *ProcessCheck) RealTime() bool { return false }

// Run runs the ProcessCheck to collect a list of running processes and relevant
// stats for each. On most POSIX systems this will use a mix of procfs and other
// OS-specific APIs to collect this information. The bulk of this collection is
// abstracted into the `gopsutil` library.
// Processes are split up into a chunks of at most 100 processes per message to
// limit the message size on intake.
// See agent.proto for the schema of the message and models used.
func (p *ProcessCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32) ([]model.MessageBody, error) {
	p.Lock()
	defer p.Unlock()

	start := time.Now()
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	procs, err := getAllProcesses(cfg)
	if err != nil {
		return nil, err
	}
	ctrList, _ := util.GetContainers()

	// End check early if this is our first run.
	if p.lastRun.IsZero() {
		// fill in the process cache
		for _, fp := range procs {
			PutProcessCache(p.cache, fp)
		}

		p.lastCPUTime = cpuTimes[0]
		p.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
		p.lastRun = time.Now()
		// Put the last refresh WAAY back
		p.lastRefresh = time.Unix(0, 0)
		p.lastProcState = make(map[int32]*model.Process)
		p.lastCtrState = make(map[string]*model.Container)
		return nil, nil
	}

	var messages []model.MessageBody

	processes := p.fmtProcesses(cfg, procs, ctrList, cpuTimes[0], p.lastCPUTime, p.lastRun)

	// In case we skip every process..
	if len(processes) == 0 {
		return nil, nil
	}

	containers := fmtContainers(cfg, ctrList, p.lastCtrRates, p.lastRun)

	if cfg.EnableIncrementalPublishing && features.FeatureEnabled("incremental-topology") && time.Now().Before(p.lastRefresh.Add(cfg.IncrementalPublishingRefreshInterval)) {
		log.Debug("Sending process status increment")
		messages = p.fmtIncrement(cfg, groupID, buildIncrement(processes, containers, p.lastProcState, p.lastCtrState))
	} else {
		log.Debug("Sending process status snapshot")
		messages = p.fmtSnapshot(cfg, groupID, processes, containers)
		p.lastRefresh = time.Now()
	}

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	p.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
	p.lastCPUTime = cpuTimes[0]
	p.lastRun = time.Now()
	p.lastProcState = buildProcState(processes)
	p.lastCtrState = buildCtrState(containers)

	statsd.Client.Gauge("datadog.process.containers.host_count", float64(len(containers)), []string{}, 1)
	statsd.Client.Gauge("datadog.process.processes.host_count", float64(len(processes)), []string{}, 1)

	checkRunDuration := time.Now().Sub(start)
	log.Debugf("collected processes in %s, processes found: %v", checkRunDuration, processes)
	log.Debugf("collected containers in %s, containers found: %v", checkRunDuration, containers)
	return messages, nil
}

func buildProcState(processes []*model.Process) map[int32]*model.Process {
	procState := make(map[int32]*model.Process)
	for _, proc := range processes {
		procState[proc.Pid] = proc
	}
	return procState
}

func buildCtrState(containers []*model.Container) map[string]*model.Container {
	ctrState := make(map[string]*model.Container)
	for _, ctr := range containers {
		ctrState[ctr.Id] = ctr
	}
	return ctrState
}

func buildIncrement(
	processes []*model.Process,
	containers []*model.Container,
	lastProcesses map[int32]*model.Process,
	lastContainers map[string]*model.Container,
) []*model.CollectorCommand {
	// Put capacity to upperbound of commands that can be made
	commands := make([]*model.CollectorCommand, 0, len(processes)+len(containers)+len(lastProcesses)+len(lastContainers))
	currentContainers := buildCtrState(containers)

	// =================== Commands for containers ===============================
	for _, container := range containers {
		if previousContainer, ok := lastContainers[container.Id]; ok {
			// Was it already there? Lets see whether topology changed
			// Later we may also do comparison on metrics

			// Tags are the only topology information that change during runtime, so only if this information changed do we have to send a topology update
			if tagsEq(container.Tags, previousContainer.Tags) {
				// If no topology update, send an update with just metrics
				commands = append(commands, &model.CollectorCommand{
					Command: &model.CollectorCommand_UpdateContainerMetrics{
						UpdateContainerMetrics: container,
					},
				})
			} else {
				// Otherwise a full update
				commands = append(commands, &model.CollectorCommand{
					Command: &model.CollectorCommand_UpdateContainer{
						UpdateContainer: container,
					},
				})
			}
			delete(lastContainers, container.Id)
		} else {
			// If the process did not exist before, send a full update
			commands = append(commands, &model.CollectorCommand{
				Command: &model.CollectorCommand_UpdateContainer{
					UpdateContainer: container,
				},
			})
		}
	}

	// Iterate over the containers that were not removed
	for _, deletedContainer := range lastContainers {
		// If the container did not exist before, send a full update
		commands = append(commands, &model.CollectorCommand{
			Command: &model.CollectorCommand_DeleteContainer{
				DeleteContainer: deletedContainer,
			},
		})
	}

	// =================== Commands for processes ===============================
	for _, process := range processes {
		// check to see if we are running in Kubernetes and replicate the tags from the container to the process
		if container, ok := currentContainers[process.ContainerId]; ok {
			process = replicateKubernetesLabelsToProcess(process, container)
		}

		if previousProcess, ok := lastProcesses[process.Pid]; ok {
			// Was it already there? Lets see whether topology changed
			// Later we may also do comparison on metrics

			// Tags are the only topology information that change during runtime, so only if this information changed do we have to send a topology update
			if tagsEq(process.Tags, previousProcess.Tags) {
				// If no topology update, send an update with just metrics
				commands = append(commands, &model.CollectorCommand{
					Command: &model.CollectorCommand_UpdateProcessMetrics{
						UpdateProcessMetrics: process,
					},
				})
			} else {
				// Otherwise a full update
				commands = append(commands, &model.CollectorCommand{
					Command: &model.CollectorCommand_UpdateProcess{
						UpdateProcess: process,
					},
				})
			}
			delete(lastProcesses, process.Pid)
		} else {
			// If the process did not exist before, send a full update
			commands = append(commands, &model.CollectorCommand{
				Command: &model.CollectorCommand_UpdateProcess{
					UpdateProcess: process,
				},
			})
		}
	}

	// Iterate over the processes that were not removed
	for _, deletedProcess := range lastProcesses {
		// If the process did not exist before, send a full update
		commands = append(commands, &model.CollectorCommand{
			Command: &model.CollectorCommand_DeleteProcess{
				DeleteProcess: deletedProcess,
			},
		})
	}

	return commands
}

func (p *ProcessCheck) fmtIncrement(cfg *config.AgentConfig, groupID int32, commands []*model.CollectorCommand) []model.MessageBody {
	chunkedCommands := chunkCollectorCommands(commands, cfg.MaxPerMessage)
	groupSize := len(chunkedCommands)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorCommands{
			HostName:  cfg.HostName,
			Info:      p.sysInfo,
			Commands:  chunkedCommands[i],
			GroupId:   groupID,
			GroupSize: int32(groupSize),
		})
	}

	return messages
}

func tagsEq(a, b []string) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func (p *ProcessCheck) fmtSnapshot(cfg *config.AgentConfig,
	groupID int32,
	processes []*model.Process,
	containers []*model.Container) []model.MessageBody {

	enrichedProcesses := enrichProcessWithKubernetesTags(processes, containers)
	chunkedProcs := chunkProcesses(enrichedProcesses, cfg.MaxPerMessage, make([][]*model.Process, 0))
	groupSize := len(chunkedProcs)
	chunkedContainers := chunkedContainers(containers, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)

	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorProc{
			HostName:   cfg.HostName,
			Info:       p.sysInfo,
			Processes:  chunkedProcs[i],
			Containers: chunkedContainers[i],
			GroupId:    groupID,
			GroupSize:  int32(groupSize),
		})
	}

	return messages
}

func enrichProcessWithKubernetesTags(processes []*model.Process, containers []*model.Container) []*model.Process {
	// build container map
	enrichedProcesses := make([]*model.Process, 0, len(processes))
	currentContainers := buildCtrState(containers)
	for _, proc := range processes {
		// check to see if we are running in Kubernetes and replicate the tags from the container to the process
		if container, ok := currentContainers[proc.ContainerId]; ok {
			enrichedProcesses = append(enrichedProcesses, replicateKubernetesLabelsToProcess(proc, container))
		} else {
			// no enriching -> most likely not running in kubernetes
			enrichedProcesses = append(enrichedProcesses, proc)
		}
	}

	return enrichedProcesses
}

func (p *ProcessCheck) fmtProcesses(
	cfg *config.AgentConfig,
	procs map[int32]*process.FilledProcess,
	ctrList []*containers.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
) []*model.Process {
	cidByPid := make(map[int32]string, len(ctrList))
	for _, c := range ctrList {
		for _, p := range c.Pids {
			cidByPid[p] = c.ID
		}
	}

	// Take all process and format them to the model.Process type
	commonProcesses := make([]*ProcessCommon, 0, cfg.MaxPerMessage)
	processMap := make(map[int32]*model.Process, cfg.MaxPerMessage)
	var totalCPUUsage float32
	var totalMemUsage uint64
	totalCPUUsage = 0.0
	totalMemUsage = 0

	for _, fp := range procs {
		// Hide blacklisted args if the Scrubber is enabled
		fp.Cmdline = cfg.Scrubber.ScrubProcessCommand(fp)

		// Check to see if we have this process cached and whether we have observed it for the configured time, otherwise skip
		if processCache, ok := IsProcessCached(p.cache, fp); ok {

			// mapping to a common process type to do sorting
			command := formatCommand(fp)
			memory := formatMemory(fp)
			cpu := formatCPU(fp, fp.CpuTime, processCache.ProcessMetrics.CPUTime, syst2, syst1)
			ioStat := formatIO(fp, processCache.ProcessMetrics.IOStat, lastRun)
			commonProcesses = append(commonProcesses, &ProcessCommon{
				Pid:           fp.Pid,
				Identifier:    createProcessID(fp.Pid, fp.CreateTime),
				FirstObserved: processCache.FirstObserved,
				Command:       command,
				Memory:        memory,
				CPU:           cpu,
				IOStat:        ioStat,
			})

			processMap[fp.Pid] = &model.Process{
				Pid:                    fp.Pid,
				Command:                command,
				User:                   formatUser(fp),
				Memory:                 memory,
				Cpu:                    cpu,
				CreateTime:             fp.CreateTime,
				OpenFdCount:            fp.OpenFdCount,
				State:                  model.ProcessState(model.ProcessState_value[fp.Status]),
				IoStat:                 ioStat,
				VoluntaryCtxSwitches:   uint64(fp.CtxSwitches.Voluntary),
				InvoluntaryCtxSwitches: uint64(fp.CtxSwitches.Involuntary),
				ContainerId:            cidByPid[fp.Pid],
			}

			totalCPUUsage = totalCPUUsage + cpu.TotalPct
			totalMemUsage = totalMemUsage + memory.Rss
		}

		// put it in the cache for the next run
		PutProcessCache(p.cache, fp)
	}

	// Process inclusions
	inclusionProcessesChan := make(chan []*model.Process)
	inclusionCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(inclusionCommonProcesses, commonProcesses)
	defer close(inclusionProcessesChan)
	go func() {
		processes := make([]*model.Process, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcess(mapProcess(processMap), getProcessInclusions(inclusionCommonProcesses, cfg, totalCPUUsage, totalMemUsage))
		inclusionProcessesChan <- processes
	}()

	// Take the remainingProcesses of the process and strip all processes that should be skipped
	allProcessesChan := make(chan []*model.Process)
	allCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(allCommonProcesses, commonProcesses)
	defer close(allProcessesChan)
	go func() {
		processes := make([]*model.Process, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcess(mapProcess(processMap), deriveFilterProcesses(keepProcess(cfg), allCommonProcesses))
		allProcessesChan <- processes
	}()

	// sort all, deduplicate and chunk
	processes := append(<-inclusionProcessesChan, <-allProcessesChan...)
	cfg.Scrubber.IncrementCacheAge()
	return deriveUniqueProcesses(deriveSortProcesses(processes))
}
