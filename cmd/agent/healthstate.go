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

// agentID builds an external ID for agent component, this will go to a component's identifiers
func (l *Collector) agentID() string {
	return fmt.Sprintf("urn:stackstate-agent:process:/%s", l.cfg.HostName)
}

// agentID builds an external ID for a check component the agent runs, this will go to a component's identifiers
func (l *Collector) agentIntegrationID(check checks.Check) string {
	return fmt.Sprintf("urn:agent-integration:/%s:process-agent:%s", l.cfg.HostName, check.Name())
}

func (l *Collector) healthStreamURN() string {
	return fmt.Sprintf("urn:health:stackstate-process-agent:%s", l.cfg.HostName)
}

func (l *Collector) currentProcessURN() string {
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
	return fmt.Sprintf("urn:process:/%s:%d:%d", l.cfg.HostName, agentPID, agentCreateTime)
}

func (l *Collector) integrationTopology(check checks.Check) ([]topology.Component, []topology.Relation) {
	hostname := l.cfg.HostName
	agentID := l.agentID()
	agentIntegrationID := l.agentIntegrationID(check)

	commonTags := []string{fmt.Sprintf("hostname:%s", hostname)}
	if l.cfg.ClusterName != "" {
		commonTags = append(commonTags, fmt.Sprintf("cluster-name:%s", l.cfg.ClusterName))
	}

	components := []topology.Component{
		{
			ExternalID: agentID,
			Type: topology.Type{
				Name: "stackstate-agent",
			},
			Data: topology.Data{
				"name":      fmt.Sprintf("StackState Process Agent:%s", hostname),
				"hostname":  hostname,
				"version":   Version,
				"buildInfo": publishVersion(),
				"tags":      append(commonTags, "stackstate-process-agent", "stackstate-agent"),
				"identifiers": []string{
					l.currentProcessURN(),
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
				"tags":        append(commonTags, "agent-integration", fmt.Sprintf("integration-type:%s", check.Name())),
			},
		},
	}
	relations := []topology.Relation{
		{
			ExternalID: fmt.Sprintf("%s -> %s", agentID, agentIntegrationID),
			SourceID:   agentID,
			TargetID:   agentIntegrationID,
			Type:       topology.Type{Name: "runs"},
			Data:       topology.Data{},
		},
	}
	return components, relations
}

func (l *Collector) makeHealth(result checkResult) (health.Stream, health.CheckData) {
	checkData := health.CheckData{
		CheckState: &health.CheckState{
			CheckStateID:              l.agentIntegrationID(result.check),
			TopologyElementIdentifier: l.agentIntegrationID(result.check),
			Health:                    health.Clear,
			Name:                      result.check.Name(),
		},
	}
	if result.err != nil {
		if result.payload != nil {
			checkData.CheckState.Health = health.Deviating
			checkData.CheckState.Message = fmt.Sprintf("Check partially failed:\n```\n%v\n```", result.err)
		} else {
			checkData.CheckState.Health = health.Critical
			checkData.CheckState.Message = fmt.Sprintf("Check failed:\n```\n%v\n```", result.err)
		}
		checkData.CheckState.Message = stripMessage(
			checkData.CheckState.Message, l.cfg.CheckHealthStateMessageLimit,
			"[...message was cut to fit...]")
	}

	stream := health.Stream{
		Urn:       l.healthStreamURN(),
		SubStream: result.check.Name(),
	}

	return stream, checkData
}

func stripMessage(message string, maxSize int, replacement string) string {
	if len(message) <= maxSize {
		return message
	}
	if maxSize <= len(replacement) {
		return message
	}

	toKeep := maxSize - len(replacement)
	toKeepRight := toKeep / 2
	toKeepLeft := toKeep - toKeepRight

	return message[0:toKeepLeft] + replacement + message[(len(message)-toKeepRight):]
}
