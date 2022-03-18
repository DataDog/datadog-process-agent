package main

import (
	"fmt"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/health"
	"github.com/StackVista/stackstate-agent/pkg/topology"
	"github.com/StackVista/stackstate-process-agent/checks"
	log "github.com/cihub/seelog"
	"os"
)

// HealthState health state
type HealthState string

const (
	// Clear designates healthy component
	Clear HealthState = "CLEAR"
	// Deviating means a component is working but something is wrong[
	Deviating HealthState = "DEVIATING"
	// Critical means that component is suffering
	Critical HealthState = "CRITICAL"
)

func (l *Collector) agentID() string {
	return fmt.Sprintf("urn:stackstate-agent:/%s", l.cfg.HostName)
}

func (l *Collector) agentIntegrationID(check checks.Check) string {
	return fmt.Sprintf("urn:agent-integration:/%s:%s", l.cfg.HostName, check.Name())
}

func (l *Collector) integrationTopology(check checks.Check) topology.Topology {
	hostname := l.cfg.HostName
	agentID := l.agentID()
	agentPID := int32(os.Getpid())
	agentCreateTime := int64(0)
	agentProcess, err := process.NewProcess(agentPID)
	if err != nil {
		_ = log.Warnf("can't get process agent OS stats: %v", err)
	} else {
		cTime, err := agentProcess.CreateTime()
		if err != nil {
			_ = log.Warnf("can't get process agent create time: %v", err)
		} else {
			agentCreateTime = cTime
		}
	}
	agentIntegrationID := l.agentIntegrationID(check)

	return topology.Topology{
		StartSnapshot: false,
		StopSnapshot:  false,
		Instance: topology.Instance{
			Type: "agent",
			URL:  "integrations",
		},
		Components: []topology.Component{
			{
				ExternalID: agentID,
				Type: topology.Type{
					Name: "stackstate-agent",
				},
				Data: topology.Data{
					"name":     fmt.Sprintf("StackState Process Agent:%s", hostname),
					"hostname": hostname,
					"version":  publishVersion(),
					"tags": []string{
						fmt.Sprintf("hostname:%s", hostname),
						"stackstate-process-agent",
						"stackstate-agent",
					},
					"identifiers": []string{
						fmt.Sprintf("urn:process:/%s:%d:%d", hostname, agentPID, agentCreateTime),
					},
				},
			},
			{
				ExternalID: agentIntegrationID,
				Type: topology.Type{
					Name: "agent-integration",
				},
				Data: topology.Data{
					"name":        fmt.Sprintf("%s check on %s", check.Name(), l.cfg.HostName),
					"integration": check.Name(),
					"tags": []string{
						fmt.Sprintf("hostname:%s", l.cfg.HostName),
						fmt.Sprintf("integration-type:%s", check.Name()),
					},
				},
			},
		},
		Relations: []topology.Relation{
			{
				ExternalID: fmt.Sprintf("%s->%s", agentID, agentIntegrationID),
				SourceID:   agentID,
				TargetID:   agentIntegrationID,
				Type:       topology.Type{Name: "runs"},
				Data:       topology.Data{},
			},
		},
	}
}

func (l *Collector) makeHealth(result checkResult) health.Health {
	checkData := health.CheckData{
		"checkStateId":              l.agentIntegrationID(result.check),
		"topologyElementIdentifier": l.agentIntegrationID(result.check),
		"health":                    Clear,
		"name":                      result.check.Name(),
	}
	if result.err != nil {
		if result.payload != nil {
			checkData["health"] = Deviating
			checkData["message"] = fmt.Sprintf("Check partially failed:\n```\n%v\n```", result.err)
		} else {
			checkData["health"] = Critical
			checkData["message"] = fmt.Sprintf("Check failed:\n```\n%v\n```", result.err)
		}
	}
	repeatInterval := int(l.cfg.CheckInterval(result.check.Name()).Seconds())

	return health.Health{
		StartSnapshot: &health.StartSnapshotMetadata{
			RepeatIntervalS: repeatInterval,
		},
		StopSnapshot: &health.StopSnapshotMetadata{},
		Stream: health.Stream{
			Urn:       fmt.Sprintf("urn:health:stackstate-agent:%s", l.cfg.HostName),
			SubStream: l.agentIntegrationID(result.check),
		},
		CheckStates: []health.CheckData{checkData},
	}
}
