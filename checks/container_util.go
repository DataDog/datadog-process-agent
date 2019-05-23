package checks

import (
	"github.com/StackVista/stackstate-process-agent/model"
)

// chunkContainers chunks the ctrList into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func chunkedContainers(
	ctrList []*model.Container,
	chunks int) [][]*model.Container {
	perChunk := (len(ctrList) / chunks) + 1
	chunked := make([][]*model.Container, chunks)
	chunk := make([]*model.Container, 0, perChunk)
	i := 0
	for _, ctr := range ctrList {
		chunk = append(chunk, ctr)

		if len(chunk) == perChunk {
			chunked[i] = chunk
			chunk = make([]*model.Container, 0, perChunk)
			i++
		}
	}
	if len(chunk) > 0 {
		chunked[i] = chunk
	}
	return chunked
}
