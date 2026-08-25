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

package java

import (
	"errors"
	"time"
)

const (
	// Leave time to reduce the copied sample into the final histogram.
	resultBuildReserve      = 15 * time.Millisecond
	maxSampleBytes          = 32 << 20
	windowBytes             = 4 << 10
	maxKlassAttempts        = 1024
	maxBatchKlassCandidates = 4096
	maxReadIOVs             = 128
	maxReadBytes            = 1 << 20
	maxG1Regions            = 1 << 18
	maxJavaObjectBytes      = 1 << 40
	maxProcMapEntries       = 1 << 18
	maxCachedMetadataBytes  = 8 << 20
	maxELFMetadataBytes     = 32 << 20
	maxELFSymbols           = 1 << 20
	maxCachedKlasses        = 65_536
	defaultObjectAlignment  = 8
	maxObjectAlignment      = 256
)

var errHotSpotUnavailable = errors.New("HotSpot external heap scan is unsupported")

type klass struct {
	name         string
	layoutHelper int32
}

type addressRange struct {
	start uint64
	end   uint64
}

type ptrEncoding struct {
	compressedKlass bool
	klassBase       uint64
	klassShift      uint
}

type region struct {
	bottom   uint64
	top      uint64
	tag      uint32
	hasTag   bool
	capacity uint64
}

type regionGroup struct {
	regions []region
}

type heapRegions struct {
	ordinary     []region
	humongous    []regionGroup
	ordinaryUsed uint64
}

type sampleWindow struct {
	start     uint64
	regionTop uint64
	raw       []byte
	size      uint64
}

type classSample struct {
	count uint64
	bytes uint64
}

type sampleStats struct {
	ordinarySampledBytes uint64
	ordinary             map[uint64]classSample
	humongous            map[uint64]classSample
}
