package util

import (
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/collectors"
)

var detector *collectors.Detector

func SetContainerSource(name string) {
	detector = collectors.NewDetector(name)
}

func GetContainers() ([]*containers.Container, error) {
	if detector == nil {
		detector = collectors.NewDetector("")
	}
	l, _, err := detector.GetPreferred()
	if err != nil {
		return nil, err
	}
	return l.List()
}
