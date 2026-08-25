// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package python

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"huatuo-bamai/internal/memsnap"
)

const (
	pyGCHeadSize       = uint64(16)
	pyGenerationSize   = uint64(24)
	pyTypeReadSize     = 272
	pyTypeNameOffset   = 24
	pyTypeBasicOffset  = 32
	pyTypeItemOffset   = 40
	pyTypeFlagsOffset  = 168
	pyTypeBaseOffset   = 256
	pyTypeDictOffset   = 264
	pyObjectTypeOffset = 8
	pyObjectSizeOffset = 16

	pyTPFlagsManagedWeakref = uint64(1 << 3)
	pyTPFlagsManagedDict    = uint64(1 << 4)
	pyTPFlagsPreheader      = pyTPFlagsManagedWeakref | pyTPFlagsManagedDict
	pyTPFlagsHeapType       = uint64(1 << 9)

	maxRuntimeProbeBytes    = 1024
	maxInterpreterBytes     = 4096
	maxInstanceFields       = 64
	maxCStringBytes         = 512
	maxTypeMetadata         = 32_768
	maxTypeNameBytes        = 8 << 20
	maxInvalidTypes         = 65_536
	maxRuntimeModules       = 64
	maxRuntimeModuleMaps    = 1024
	maxRuntimeFailureBytes  = 4096
	maxScannedObjects       = 10_000_000
	maxELFMetadataBytes     = 32 << 20
	maxELFSymbols           = 1 << 20
	maxEstimatedObjectBytes = uint64(1 << 40)
	// Remote values must never be allowed to drive an unbounded allocation in
	// Huatuo. Current CPython metadata reads are at most a few KiB; these limits
	// leave ample headroom while containing corrupt or concurrently changed data.
	maxReadBytes = 1 << 20
	// Leave time to reduce copied data and return a useful result after the last
	// process_vm_readv batch.
	resultReserve = 20 * time.Millisecond

	maxInterpreterCount  = 1024
	maxInterpreterProbes = 4096
	debugOffsetsBytes    = 448
	debugVersion         = 8
	debugFreeThreaded    = 16
	debugRuntimeHead     = 40
	debugInterpreterSize = 48
	debugInterpreterNext = 64
	gcGenerationsOffset  = 24
)

// reader reads CPython's own GC and object metadata from the named
// victim. It does not execute code in the victim and does not require a Python
// package, agent, hook, debug build, or periodic discovery.
type reader struct {
	procRoot string
}

type version struct {
	major      int
	minor      int
	micro      int
	microKnown bool
}

func (v version) String() string {
	if !v.microKnown {
		return fmt.Sprintf("%d.%d.x", v.major, v.minor)
	}
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.micro)
}

type image struct {
	version        version
	runtimeAddress uint64
	layout         runtimeLayout
	order          binary.ByteOrder
}

type memoryReader interface {
	read(address uint64, size int) ([]byte, error)
	readInto(address uint64, destination []byte) error
}

type processMemory struct {
	pid int
	ctx context.Context
}

type module struct {
	hostPath string
	maps     []memsnap.ProcMap
}

type gcHeads struct {
	heads [4]uint64
}

type scanner struct {
	memory         memoryReader
	image          image
	deadline       time.Time
	types          map[uint64]typeInfo
	invalidTypes   map[uint64]struct{}
	listTypes      map[uint64]bool
	aggregates     map[uint64]*memsnap.ObjectAggregate
	typeNameBytes  int
	objectScratch  [16]byte
	scannedObjects int
	skippedObjects int
	partial        string
}

type typeInfo struct {
	address   uint64
	name      string
	basicsize int64
	itemsize  int64
	flags     uint64
	base      uint64
	dict      uint64
}

type dictEntry struct {
	name  string
	value uint64
}
