// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"huatuo-bamai/internal/memsnap"

	"golang.org/x/sys/unix"
)

const (
	hotspotResultReserve           = 8 * time.Millisecond
	hotspotReferenceReserve        = 2 * time.Millisecond
	hotspotDeadlineCheckObjects    = 64
	hotspotObjectSamplesPerClass   = 8
	hotspotObjectSampleBytes       = 512
	hotspotObjectSamplesTotal      = 512
	hotspotSampledReferencesTotal  = 512
	hotspotReferenceBatchSize      = 64
	hotspotMinimumSampleBytes      = 4 << 20
	hotspotMaximumSampleBytes      = 12 << 20
	hotspotSamplePercent           = 1
	hotspotHumongousHeaderBytes    = 4096
	hotspotShortRegionPrefixBytes  = 3 << 10
	hotspotShortMaximumSampleBytes = 6 << 20
	hotspotShortLargeRegionBytes   = 8 << 20
	hotspotShortPrefixHeapBytes    = 256 << 20
	hotspotRegionSampleWindows     = 6
	hotspotDiscoveryRegions        = 64
	hotspotWindowKlassMinHits      = 3
	hotspotWindowKlassMaxAttempts  = 64
	hotspotMaximumPrefetchRegions  = 2048
	hotspotMaximumScannedObjects   = 1_000_000
	maxG1Regions                   = 1 << 20
	maxJavaObjectBytes             = 1 << 40
	objectAlignment                = 8
)

var errOnlyHotSpotG1 = errors.New(
	"only HotSpot G1 is supported by external Java FAST scan")

func unsupportedHotSpotG1(reason string) error {
	return fmt.Errorf("%w: %s", errOnlyHotSpotG1, reason)
}

type ExternalSnapshot struct {
	RuntimeVersion   string
	Objects          []memsnap.ObjectAggregate
	Complete         bool
	PartialReason    string
	ScannedBytes     uint64
	HeapUsedBytes    uint64
	ScannedRegions   uint64
	TotalRegions     uint64
	ClassifiedBytes  uint64
	Estimated        bool
	EstimationMethod string
	SamplingSeed     uint64
	PlannedRegions   uint64
	SamplingStrata   []memsnap.SamplingStratumCoverage
	localFinalizer   func() error
}

// FinalizeLocal builds estimates and presentation data from memory already
// copied out of the victim. It must be called only after the OOM gate ACK.
func (s *ExternalSnapshot) FinalizeLocal() error {
	if s == nil || s.localFinalizer == nil {
		return nil
	}
	finalize := s.localFinalizer
	s.localFinalizer = nil
	return finalize()
}

type SnapshotReader interface {
	Capture(ctx context.Context, identity memsnap.ProcessIdentity,
		accessTID, maxObjects int) (*ExternalSnapshot, error)
}

type ExternalReader struct {
	procRoot string
}

func NewExternalReader(procRoot string) *ExternalReader {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &ExternalReader{procRoot: procRoot}
}

type hotspotClass struct {
	address      uint64
	name         string
	layoutHelper int32
	oopOffsets   []uint32
	fieldNames   map[uint32]string
	fields       map[uint32]*fieldReferenceAggregate
	fieldsLoaded bool
	samples      objectReservoir
}

type fieldReferenceAggregate struct {
	referencedType string
	count          uint64
	bytes          uint64
	unique         map[uint64]struct{}
}

type sampledObject struct {
	address uint64
	raw     []byte
}

type objectReservoir struct {
	seen    uint64
	objects []sampledObject
}

type referenceSamplingState struct {
	objects int
}

type windowKlassDiscovery struct {
	hits     map[uint64]uint8
	attempts int
}

type sampledReferenceUse struct {
	klass  *hotspotClass
	offset uint32
}

type hotspotPointerEncoding struct {
	compressedKlass bool
	klassBase       uint64
	klassShift      uint
	compressedOops  bool
	oopBase         uint64
	oopShift        uint
	referencesKnown bool
}

func (encoding hotspotPointerEncoding) headerBytes() uint64 {
	if encoding.compressedKlass {
		return 12
	}
	return 16
}

func (encoding hotspotPointerEncoding) oopBytes() uint32 {
	if encoding.compressedOops {
		return 4
	}
	return 8
}

func (encoding hotspotPointerEncoding) klassAddress(raw []byte) (uint64, bool) {
	if encoding.compressedKlass {
		if len(raw) < 12 {
			return 0, false
		}
		narrow := binary.LittleEndian.Uint32(raw[8:12])
		return encoding.klassBase + (uint64(narrow) << encoding.klassShift), narrow != 0
	}
	if len(raw) < 16 {
		return 0, false
	}
	address := binary.LittleEndian.Uint64(raw[8:16])
	return address, address != 0
}

func (encoding hotspotPointerEncoding) oopAddress(raw []byte) (uint64, bool) {
	if encoding.compressedOops {
		if len(raw) < 4 {
			return 0, false
		}
		narrow := binary.LittleEndian.Uint32(raw[:4])
		return encoding.oopBase + (uint64(narrow) << encoding.oopShift), narrow != 0
	}
	if len(raw) < 8 {
		return 0, false
	}
	address := binary.LittleEndian.Uint64(raw[:8])
	return address, address != 0
}

type g1Region struct {
	bottom      uint64
	top         uint64
	tag         uint32
	tagged      bool
	scanGroup   uint64
	capacity    uint64
	stratum     int
	humongous   bool
	sampleBytes uint64
}

type g1RegionUnit struct {
	regions   []g1Region
	stratum   int
	usedBytes uint64
	humongous bool
}

type g1RegionSampleWindow struct {
	start uint64
	raw   []byte
}

type g1RegionSample struct {
	windows []g1RegionSampleWindow
}

type g1SamplingStratum struct {
	name             string
	totalRegions     uint64
	plannedRegions   uint64
	completedRegions uint64
	totalUsedBytes   uint64
	classifiedBytes  uint64
}

type g1SamplingPlan struct {
	units     []g1RegionUnit
	strata    map[int]*g1SamplingStratum
	seed      uint64
	estimated bool
}

type g1RegionClassObservation struct {
	count uint64
	bytes uint64
}

type g1ClassStatistics struct {
	count           uint64
	bytes           uint64
	regions         uint64
	usedBytesCross  float64
	bytesSquaredSum float64
}

type g1StratumStatistics struct {
	regions        uint64
	usedBytes      uint64
	usedSquaredSum float64
	classes        map[uint64]*g1ClassStatistics
}

type g1OnlineStatistics map[int]*g1StratumStatistics

func (statistics g1OnlineStatistics) observe(stratum int, used uint64,
	classes map[uint64]g1RegionClassObservation,
) {
	stratumStatistics := statistics[stratum]
	if stratumStatistics == nil {
		stratumStatistics = &g1StratumStatistics{
			classes: make(map[uint64]*g1ClassStatistics),
		}
		statistics[stratum] = stratumStatistics
	}
	stratumStatistics.regions++
	stratumStatistics.usedBytes = saturatedAdd(stratumStatistics.usedBytes, used)
	usedFloat := float64(used)
	stratumStatistics.usedSquaredSum += usedFloat * usedFloat
	for classAddress, observation := range classes {
		classStatistics := stratumStatistics.classes[classAddress]
		if classStatistics == nil {
			classStatistics = &g1ClassStatistics{}
			stratumStatistics.classes[classAddress] = classStatistics
		}
		classStatistics.count = saturatedAdd(classStatistics.count, observation.count)
		classStatistics.bytes = saturatedAdd(classStatistics.bytes, observation.bytes)
		if observation.count != 0 {
			classStatistics.regions++
		}
		bytesFloat := float64(observation.bytes)
		classStatistics.usedBytesCross += usedFloat * bytesFloat
		classStatistics.bytesSquaredSum += bytesFloat * bytesFloat
	}
}

//nolint:gocognit,cyclop,funlen // Heap walking keeps all address validation local.
func (r *ExternalReader) Capture(ctx context.Context,
	identity memsnap.ProcessIdentity, accessTID, maxObjects int,
) (*ExternalSnapshot, error) {
	readTID := accessTID
	if readTID <= 0 {
		// The leader's TID equals its TGID, so it can stand in as the access
		// thread when no gate thread was frozen.
		readTID = identity.TGID
	}
	if readTID <= 0 || maxObjects <= 0 {
		return nil, errors.New("HotSpot external scan limits are invalid")
	}
	metadata, err := loadHotSpotMetadata(r.procRoot, readTID)
	if err != nil {
		return nil, err
	}
	memory := processMemory{pid: readTID}
	regions, err := g1Regions(memory, metadata)
	if err != nil {
		return nil, err
	}
	snapshot := &ExternalSnapshot{
		RuntimeVersion: metadata.image.runtimeVersion,
		TotalRegions:   uint64(len(regions)),
	}
	for _, region := range regions {
		if region.top > region.bottom {
			snapshot.HeapUsedBytes = saturatedAdd(snapshot.HeapUsedBytes,
				region.top-region.bottom)
		}
	}
	shortWindow := g1ShortWindow(ctx)
	regionPrefixBytes := g1ShortWindowPrefixBytes(ctx, regions,
		snapshot.HeapUsedBytes)
	if snapshot.HeapUsedBytes < hotspotShortPrefixHeapBytes &&
		inferG1RegionCapacity(regions) <= 2<<20 {
		regionPrefixBytes = 0
	}
	plan := planG1RegionSampleForBudget(regions, metadata, regionPrefixBytes,
		shortWindow)
	regions = flattenG1SamplingPlan(plan)
	snapshot.Estimated = plan.estimated
	snapshot.EstimationMethod = "g1_region_stratified_v1"
	if regionPrefixBytes != 0 {
		snapshot.EstimationMethod = "g1_region_prefix_stratified_v2"
	}
	snapshot.SamplingSeed = plan.seed
	for _, stratum := range plan.strata {
		snapshot.PlannedRegions = saturatedAdd(snapshot.PlannedRegions,
			stratum.plannedRegions)
	}
	klassBase, klassShift, err := compressedKlassParameters(memory, metadata)
	if err != nil {
		return nil, err
	}
	mirrorOopSizeOffset, err := classMirrorOopSizeOffset(memory, metadata)
	if err != nil {
		return nil, err
	}
	oopBase, oopShift, err := compressedOopParameters(memory, metadata)
	if err != nil {
		return nil, err
	}
	encoding, err := detectHotSpotPointerEncoding(memory, metadata, regions,
		klassBase, klassShift, oopBase, oopShift, mirrorOopSizeOffset)
	if err != nil {
		return nil, err
	}
	referenceDeadline, hasDeadline := memsnap.OOMSnapshotDeadlineWithReserve(
		ctx, hotspotResultReserve)
	scanDeadline := referenceDeadline
	firstEvidenceDeadline := scanDeadline
	if hasDeadline && !shortWindow {
		scanDeadline = scanDeadline.Add(-hotspotReferenceReserve)
		// Metadata discovery consumes a noticeable share of a 50ms gate. Allow
		// the first complete sampling unit to use part of the reference reserve;
		// once evidence exists, return to the normal scan deadline.
		firstEvidenceDeadline = referenceDeadline.Add(
			hotspotResultReserve - hotspotReferenceReserve)
	}
	classes := make(map[uint64]*hotspotClass)
	aggregates := make(map[uint64]*memsnap.ObjectAggregate)
	statistics := make(g1OnlineStatistics)
	sampling := referenceSamplingState{}
	windowDiscovery := windowKlassDiscovery{hits: make(map[uint64]uint8)}
	var regionBuffer []byte
	prefetched := prefetchG1RegionSamples(memory, regions, plan.seed)
	var coveredUntil uint64
	var lastScanGroup uint64
	invalidRegions := 0
	var firstInvalidReason error
	var scannedObjects uint64
	var prefixDiscoveryRegions uint64
	recordRegion := func(region g1Region, sampledUsed uint64,
		regionAggregates map[uint64]g1RegionClassObservation,
	) {
		snapshot.ScannedRegions++
		classified := uint64(0)
		for classAddress, observation := range regionAggregates {
			classified = saturatedAdd(classified, observation.bytes)
			aggregate := aggregates[classAddress]
			if aggregate == nil {
				klass := classes[classAddress]
				aggregate = &memsnap.ObjectAggregate{
					TypeName: normalizeClassName(klass.name), RawTypeName: klass.name,
				}
				aggregates[classAddress] = aggregate
			}
			aggregate.Count = saturatedAdd(aggregate.Count, observation.count)
			aggregate.ShallowBytes = saturatedAdd(aggregate.ShallowBytes,
				observation.bytes)
		}
		snapshot.ClassifiedBytes = saturatedAdd(snapshot.ClassifiedBytes, classified)
		stratumKey := regionStratumKey(region)
		statistics.observe(stratumKey, sampledUsed, regionAggregates)
		if stratum := plan.strata[stratumKey]; stratum != nil {
			stratum.completedRegions++
			stratum.classifiedBytes = saturatedAdd(stratum.classifiedBytes, classified)
		}
	}
	for _, region := range regions {
		activeScanDeadline := scanDeadline
		if len(aggregates) == 0 {
			activeScanDeadline = firstEvidenceDeadline
		}
		if region.scanGroup != lastScanGroup {
			coveredUntil = 0
			lastScanGroup = region.scanGroup
		}
		if err := ctx.Err(); err != nil ||
			memsnap.OOMSnapshotDeadlineReached(activeScanDeadline, hasDeadline) {
			snapshot.PartialReason = "deadline reached during external HotSpot heap scan"
			break
		}
		if region.bottom == 0 || region.top <= region.bottom {
			snapshot.ScannedRegions++
			if stratum := plan.strata[regionStratumKey(region)]; stratum != nil {
				stratum.completedRegions++
			}
			continue
		}
		if region.top <= coveredUntil ||
			(region.humongous && region.bottom < coveredUntil) {
			snapshot.ScannedRegions++
			if stratum := plan.strata[regionStratumKey(region)]; stratum != nil {
				stratum.completedRegions++
			}
			continue
		}
		readBytes := region.top - region.bottom
		if region.sampleBytes != 0 && readBytes > region.sampleBytes {
			readBytes = region.sampleBytes
		}
		if region.humongous && readBytes > hotspotHumongousHeaderBytes {
			readBytes = hotspotHumongousHeaderBytes
		}
		readStart := region.bottom
		sample, prefetchedOK := prefetched[region.bottom]
		if prefetchedOK {
			regionAggregates := make(map[uint64]g1RegionClassObservation)
			var sampledUsed uint64
			for _, window := range sample.windows {
				knownObjects := scanKnownHotSpotWindow(memory, window.raw,
					window.start, classes, encoding, metadata,
					mirrorOopSizeOffset, regionAggregates, &sampling,
					&windowDiscovery)
				scannedObjects = saturatedAdd(scannedObjects, knownObjects)
				sampledUsed = saturatedAdd(sampledUsed, uint64(len(window.raw)))
			}
			if sampledUsed != 0 {
				snapshot.ScannedBytes = saturatedAdd(snapshot.ScannedBytes, sampledUsed)
				recordRegion(region, sampledUsed, regionAggregates)
			}
			continue
		} else if region.sampleBytes != 0 && !region.humongous &&
			prefixDiscoveryRegions >= hotspotDiscoveryRegions {
			continue
		}
		sampleTop := readStart + readBytes
		var regionData []byte
		var readErr error
		if uint64(cap(regionBuffer)) < readBytes {
			regionBuffer = make([]byte, int(readBytes))
		}
		regionData = regionBuffer[:int(readBytes)]
		readErr = memory.readInto(readStart, regionData)
		if readErr != nil {
			invalidRegions++
			if firstInvalidReason == nil {
				firstInvalidReason = readErr
			}
			continue
		}
		snapshot.ScannedBytes = saturatedAdd(snapshot.ScannedBytes, readBytes)
		address := readStart
		if address < coveredUntil {
			address = coveredUntil
		}
		regionValid := true
		deadlineStopped := false
		regionAggregates := make(map[uint64]g1RegionClassObservation)
		var lastKlassAddress uint64
		var lastKlass *hotspotClass
		var runKlassAddress uint64
		var runObservation g1RegionClassObservation
		flushRun := func() {
			if runKlassAddress == 0 || runObservation.count == 0 {
				return
			}
			observation := regionAggregates[runKlassAddress]
			observation.count = saturatedAdd(observation.count,
				runObservation.count)
			observation.bytes = saturatedAdd(observation.bytes,
				runObservation.bytes)
			regionAggregates[runKlassAddress] = observation
			runKlassAddress = 0
			runObservation = g1RegionClassObservation{}
		}
		for address < sampleTop {
			if scannedObjects&(hotspotDeadlineCheckObjects-1) == 0 &&
				(memsnap.OOMSnapshotDeadlineReached(activeScanDeadline, hasDeadline) ||
					scannedObjects >= hotspotMaximumScannedObjects) {
				snapshot.PartialReason = "deadline reached during external HotSpot heap scan"
				if scannedObjects >= hotspotMaximumScannedObjects {
					snapshot.PartialReason = "object work limit reached during external HotSpot heap scan"
				}
				regionValid = false
				deadlineStopped = true
				break
			}
			scannedObjects++
			if address < readStart {
				regionValid = false
				break
			}
			if address-readStart+encoding.headerBytes() > uint64(len(regionData)) {
				if sampleTop < region.top {
					address = sampleTop
					break
				}
				regionValid = false
				break
			}
			offset := address - readStart
			klassAddress, validKlass := encoding.klassAddress(regionData[offset:])
			if !validKlass {
				regionValid = false
				break
			}
			klass := lastKlass
			if klassAddress != lastKlassAddress || klass == nil {
				var ok bool
				klass, ok = classes[klassAddress]
				if !ok {
					klass, readErr = readHotSpotClass(memory, metadata, klassAddress)
					if readErr != nil {
						if firstInvalidReason == nil {
							firstInvalidReason = fmt.Errorf(
								"object %#x Klass %#x: %w", address,
								klassAddress, readErr)
						}
						regionValid = false
						break
					}
					classes[klassAddress] = klass
				}
				lastKlassAddress, lastKlass = klassAddress, klass
			}
			objectBytes, sizeErr := hotspotObjectSize(regionData[offset:], klass,
				metadata, mirrorOopSizeOffset, encoding.headerBytes())
			if sizeErr != nil || objectBytes == 0 || objectBytes > maxJavaObjectBytes {
				if firstInvalidReason == nil {
					firstInvalidReason = sizeErr
					if firstInvalidReason == nil {
						firstInvalidReason = fmt.Errorf(
							"HotSpot object size %d is invalid", objectBytes)
					}
				}
				regionValid = false
				break
			}
			objectStart := address
			if runKlassAddress != klassAddress {
				flushRun()
				runKlassAddress = klassAddress
			}
			runObservation.count++
			runObservation.bytes = saturatedAdd(runObservation.bytes, objectBytes)
			if isBusinessHotSpotClass(klass.name) {
				sampleHotSpotObject(regionData[offset:], objectBytes, address, klass,
					&sampling)
			}
			address += objectBytes
			if finishesG1RegionAfterObject(region, objectStart, objectBytes) {
				coveredUntil = address
				if address < region.top {
					address = region.top
				}
			} else if address > region.top {
				coveredUntil = address
			}
		}
		flushRun()
		if !regionValid && !deadlineStopped {
			invalidRegions++
		}
		if regionValid && address >= sampleTop {
			recordRegion(region, readBytes, regionAggregates)
			if region.sampleBytes != 0 && !region.humongous {
				prefixDiscoveryRegions++
			}
		}
	}
	if !shortWindow {
		captureSampledReferences(memory, metadata, classes, aggregates, maxObjects,
			encoding, mirrorOopSizeOffset,
			referenceDeadline, hasDeadline)
	}
	if !plan.estimated && snapshot.ScannedRegions == snapshot.PlannedRegions &&
		invalidRegions == 0 &&
		snapshot.PartialReason == "" {
		snapshot.Complete = true
	} else if snapshot.PartialReason == "" {
		if invalidRegions != 0 {
			snapshot.PartialReason = fmt.Sprintf(
				"%d G1 regions could not be validated during external heap scan",
				invalidRegions)
		} else {
			snapshot.PartialReason = fmt.Sprintf(
				"bounded stratified G1 sampling completed %d of %d planned regions",
				snapshot.ScannedRegions, snapshot.PlannedRegions)
		}
	}
	if snapshot.ScannedRegions < snapshot.PlannedRegions {
		plan.estimated = true
		snapshot.Estimated = true
	}
	if len(aggregates) > maxObjects {
		snapshot.Complete = false
		if snapshot.PartialReason == "" {
			snapshot.PartialReason = "Java class aggregate limit reached"
		}
	}
	if len(aggregates) == 0 {
		if firstInvalidReason == nil {
			firstInvalidReason = errors.New("scan stopped before the first valid object")
		}
		return nil, fmt.Errorf("external HotSpot scan found no valid Java objects: %w",
			firstInvalidReason)
	}
	snapshot.localFinalizer = func() error {
		estimateG1Aggregates(aggregates, statistics, plan)
		snapshot.SamplingStrata = samplingCoverage(plan)
		snapshot.Objects = make([]memsnap.ObjectAggregate, 0, len(aggregates))
		for classAddress, aggregate := range aggregates {
			klass := classes[classAddress]
			offsets := make([]int, 0, len(klass.fields))
			for offset := range klass.fields {
				offsets = append(offsets, int(offset))
			}
			sort.Ints(offsets)
			for _, offsetValue := range offsets {
				offset := uint32(offsetValue)
				field := klass.fields[offset]
				if field == nil || field.count == 0 || len(field.unique) == 0 {
					continue
				}
				name := klass.fieldNames[offset]
				if name == "" {
					name = fmt.Sprintf("oop@%d", offset)
				}
				aggregate.Fields = append(aggregate.Fields, memsnap.FieldShape{
					Name: name, ReferencedType: field.referencedType,
					ReferenceCount:          field.count,
					UniqueReferencedObjects: uint64(len(field.unique)),
					ReferencedShallowBytes:  field.bytes,
					AverageReferencedBytes: float64(field.bytes) /
						float64(len(field.unique)),
				})
			}
			if aggregate.Count != 0 {
				aggregate.AverageBytes = float64(aggregate.ShallowBytes) /
					float64(aggregate.Count)
			}
			snapshot.Objects = append(snapshot.Objects, *aggregate)
		}
		sort.SliceStable(snapshot.Objects, func(i, j int) bool {
			return snapshot.Objects[i].ShallowBytes > snapshot.Objects[j].ShallowBytes
		})
		if len(snapshot.Objects) > maxObjects {
			snapshot.Objects = snapshot.Objects[:maxObjects]
		}
		return nil
	}
	return snapshot, nil
}

func finishesG1RegionAfterObject(region g1Region, objectStart,
	objectBytes uint64,
) bool {
	if objectStart != region.bottom {
		return false
	}
	if region.humongous {
		return true
	}
	// Older HotSpot LTS releases do not export G1HeapRegionType::_tag. G1
	// allocates objects larger than half a region as humongous, so the first
	// such object is also the only object in this region. Avoid interpreting
	// the unused tail as another object when the explicit tag is unavailable.
	return region.capacity != 0 && objectBytes > region.capacity/2
}

func sampleHotSpotObject(raw []byte, objectBytes, address uint64,
	klass *hotspotClass, sampling *referenceSamplingState,
) {
	reservoir := &klass.samples
	if len(reservoir.objects) >= hotspotObjectSamplesPerClass ||
		sampling.objects >= hotspotObjectSamplesTotal {
		return
	}
	reservoir.seen++
	sampleBytes := objectBytes
	if sampleBytes > hotspotObjectSampleBytes {
		sampleBytes = hotspotObjectSampleBytes
	}
	if sampleBytes > uint64(len(raw)) {
		sampleBytes = uint64(len(raw))
	}
	if sampleBytes < 12 {
		return
	}
	sample := func() sampledObject {
		data := append([]byte(nil), raw[:sampleBytes]...)
		return sampledObject{address: address, raw: data}
	}
	reservoir.objects = append(reservoir.objects, sample())
	sampling.objects++
}

func scanKnownHotSpotWindow(memory processMemory, raw []byte, base uint64,
	classes map[uint64]*hotspotClass, encoding hotspotPointerEncoding,
	metadata *hotspotMetadata, mirrorOopSizeOffset int,
	observations map[uint64]g1RegionClassObservation,
	sampling *referenceSamplingState, discovery *windowKlassDiscovery,
) uint64 {
	var objects uint64
	for offset := uint64(0); offset+encoding.headerBytes() <= uint64(len(raw)); offset += objectAlignment {
		mark := binary.LittleEndian.Uint64(raw[offset : offset+8])
		if mark&3 != 1 {
			continue
		}
		klassAddress, validKlass := encoding.klassAddress(raw[offset:])
		if !validKlass {
			continue
		}
		klass := classes[klassAddress]
		if klass == nil {
			if discovery == nil || klassAddress == 0 ||
				discovery.attempts >= hotspotWindowKlassMaxAttempts {
				continue
			}
			hits := discovery.hits[klassAddress]
			if hits < hotspotWindowKlassMinHits {
				hits++
				discovery.hits[klassAddress] = hits
			}
			if hits < hotspotWindowKlassMinHits {
				continue
			}
			delete(discovery.hits, klassAddress)
			discovery.attempts++
			var err error
			klass, err = readHotSpotClass(memory, metadata, klassAddress)
			if err != nil {
				continue
			}
			classes[klassAddress] = klass
		}
		objectBytes, err := hotspotObjectSize(raw[offset:], klass, metadata,
			mirrorOopSizeOffset, encoding.headerBytes())
		if err != nil || objectBytes == 0 || objectBytes > maxJavaObjectBytes {
			continue
		}
		observation := observations[klassAddress]
		observation.count++
		observation.bytes = saturatedAdd(observation.bytes, objectBytes)
		observations[klassAddress] = observation
		if isBusinessHotSpotClass(klass.name) {
			sampleHotSpotObject(raw[offset:], objectBytes, base+offset, klass, sampling)
		}
		objects++
		offset += objectBytes - objectAlignment
	}
	return objects
}

func prefetchG1RegionSamples(memory processMemory, regions []g1Region,
	seed uint64,
) map[uint64]g1RegionSample {
	result := make(map[uint64]g1RegionSample)
	var local []unix.Iovec
	var remote []unix.RemoteIovec
	var keys []uint64
	var starts []uint64
	eligible := make([]g1Region, 0, len(regions))
	for _, region := range regions {
		if region.sampleBytes == 0 || region.humongous ||
			region.top-region.bottom <= region.sampleBytes {
			continue
		}
		eligible = append(eligible, region)
	}
	discoveryRegions := hotspotDiscoveryRegions
	if len(eligible) <= discoveryRegions {
		// A few very large Regions otherwise consume the whole short gate as
		// contiguous prefixes. Their distributed windows discover repeated
		// Klass pointers directly, so no separate prefix Region is needed.
		discoveryRegions = 0
	}
	if len(eligible) > discoveryRegions {
		eligible = eligible[discoveryRegions:]
	} else {
		return result
	}
	step := 1
	if len(eligible) > hotspotMaximumPrefetchRegions {
		step = (len(eligible) + hotspotMaximumPrefetchRegions - 1) /
			hotspotMaximumPrefetchRegions
	}
	if len(eligible) == 0 {
		return result
	}
	regionCount := (len(eligible) + step - 1) / step
	windowCount := uint64(2)
	if eligible[0].capacity > 2<<20 {
		windowCount = 64
	}
	windowBytes := eligible[0].sampleBytes / windowCount
	if windowBytes < 16 {
		windowBytes = eligible[0].sampleBytes
	}
	windowsPerRegion := int(eligible[0].sampleBytes / windowBytes)
	buffer := make([]byte, regionCount*windowsPerRegion*int(windowBytes))
	for candidateIndex := 0; candidateIndex < len(eligible); candidateIndex += step {
		region := eligible[candidateIndex]
		span := region.top - region.bottom - windowBytes
		for windowIndex := 0; windowIndex < windowsPerRegion; windowIndex++ {
			segmentBegin := span * uint64(windowIndex) / uint64(windowsPerRegion)
			segmentEnd := span * uint64(windowIndex+1) / uint64(windowsPerRegion)
			segmentSpan := segmentEnd - segmentBegin
			offset := segmentBegin
			if segmentSpan != 0 {
				offset += mixG1SampleValue(region.bottom^seed^
					(uint64(windowIndex+1)*0x9e3779b97f4a7c15)) % (segmentSpan + 1)
			}
			start := region.bottom + (offset &^ (objectAlignment - 1))
			item := len(keys)
			itemData := buffer[item*int(windowBytes) : (item+1)*int(windowBytes)]
			local = append(local, unix.Iovec{Base: &itemData[0], Len: uint64(len(itemData))})
			remote = append(remote, unix.RemoteIovec{Base: uintptr(start), Len: len(itemData)})
			keys = append(keys, region.bottom)
			starts = append(starts, start)
		}
	}
	for begin := 0; begin < len(local); begin += 256 {
		end := begin + 256
		if end > len(local) {
			end = len(local)
		}
		read, _ := unix.ProcessVMReadv(memory.pid, local[begin:end],
			remote[begin:end], 0)
		remaining := read
		for index := begin; index < end; index++ {
			itemBytes := int(windowBytes)
			if remaining < itemBytes {
				break
			}
			itemData := buffer[index*itemBytes : (index+1)*itemBytes]
			sample := result[keys[index]]
			sample.windows = append(sample.windows, g1RegionSampleWindow{
				start: starts[index], raw: itemData,
			})
			result[keys[index]] = sample
			remaining -= itemBytes
		}
	}
	return result
}

func deterministicReservoirSlot(address, seen uint64) uint64 {
	value := address ^ (seen * 0x9e3779b97f4a7c15)
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	value ^= value >> 31
	return value % seen
}

// captureSampledReferences is the bounded second phase. The census never issues
// per-reference syscalls; only samples belonging to the largest observed classes
// are decoded, duplicate target addresses are coalesced, and headers are read in
// batches before the result/ACK reserve begins.
//
//nolint:funlen,gocognit,cyclop
func captureSampledReferences(memory processMemory, metadata *hotspotMetadata,
	classes map[uint64]*hotspotClass,
	aggregates map[uint64]*memsnap.ObjectAggregate, maxObjects int,
	encoding hotspotPointerEncoding,
	mirrorOopSizeOffset int, deadline time.Time, hasDeadline bool,
) {
	// A wide Klass pointer does not tell us whether ordinary oops are wide too.
	// Without startup flags or a trustworthy VM flag address, guessing here can
	// turn valid heap words into bogus references. The object histogram remains
	// valid; omit the optional field-reference enrichment for this encoding.
	if !encoding.referencesKnown {
		return
	}
	classAddresses := make([]uint64, 0, len(aggregates))
	for address := range aggregates {
		classAddresses = append(classAddresses, address)
	}
	sort.SliceStable(classAddresses, func(i, j int) bool {
		left := aggregates[classAddresses[i]].ShallowBytes
		right := aggregates[classAddresses[j]].ShallowBytes
		if left == right {
			return classAddresses[i] < classAddresses[j]
		}
		return left > right
	})
	if len(classAddresses) > maxObjects {
		classAddresses = classAddresses[:maxObjects]
	}

	usesByAddress := make(map[uint64][]sampledReferenceUse)
	addresses := make([]uint64, 0, hotspotSampledReferencesTotal)
	referenceCount := 0
	for _, classAddress := range classAddresses {
		if memsnap.OOMSnapshotDeadlineReached(deadline, hasDeadline) ||
			referenceCount >= hotspotSampledReferencesTotal {
			break
		}
		klass := classes[classAddress]
		if klass == nil || len(klass.samples.objects) == 0 {
			continue
		}
		loadHotSpotFields(memory, metadata, klass, encoding.oopBytes())
		for _, offset := range klass.oopOffsets {
			for _, object := range klass.samples.objects {
				width := int(encoding.oopBytes())
				if int(offset)+width > len(object.raw) {
					continue
				}
				objectAddress, validOop := encoding.oopAddress(
					object.raw[offset : int(offset)+width])
				if !validOop {
					continue
				}
				if _, exists := usesByAddress[objectAddress]; !exists {
					addresses = append(addresses, objectAddress)
				}
				usesByAddress[objectAddress] = append(usesByAddress[objectAddress],
					sampledReferenceUse{klass: klass, offset: offset})
				referenceCount++
				if referenceCount >= hotspotSampledReferencesTotal {
					break
				}
			}
			if referenceCount >= hotspotSampledReferencesTotal {
				break
			}
		}
	}

	for index := 0; index < len(addresses); {
		if memsnap.OOMSnapshotDeadlineReached(deadline, hasDeadline) {
			return
		}
		end := index + hotspotReferenceBatchSize
		if end > len(addresses) {
			end = len(addresses)
		}
		batchSize := end - index
		headerBytes := int(encoding.headerBytes())
		if headerBytes < 20 {
			headerBytes = 20
		}
		raw, completed := readHotSpotHeaderBatch(memory, addresses[index:end],
			headerBytes)
		for item := 0; item < completed; item++ {
			address := addresses[index+item]
			header := raw[item*headerBytes : (item+1)*headerBytes]
			captureResolvedReference(header, address, usesByAddress[address], memory,
				metadata, classes, encoding, mirrorOopSizeOffset)
		}
		index += completed
		if completed < batchSize {
			// process_vm_readv stops at the first unreadable remote iovec. Skip
			// that one address and continue batching the remaining valid samples.
			index++
		}
	}
}

func loadHotSpotFields(memory processMemory, metadata *hotspotMetadata,
	klass *hotspotClass, oopBytes uint32,
) {
	if klass.fieldsLoaded {
		return
	}
	klass.fieldsLoaded = true
	klass.fieldNames, _ = readInstanceFieldNames(memory, metadata, klass.address)
	klass.oopOffsets, _ = readInstanceOopOffsets(memory, metadata, klass.address,
		oopBytes)
	if len(klass.oopOffsets) == 0 && len(klass.fieldNames) != 0 {
		klass.oopOffsets = sortedFieldOffsets(klass.fieldNames)
	}
	klass.fields = make(map[uint32]*fieldReferenceAggregate, len(klass.oopOffsets))
}

func readHotSpotHeaderBatch(memory processMemory, addresses []uint64,
	headerBytes int,
) ([]byte, int) {
	if len(addresses) == 0 {
		return nil, 0
	}
	data := make([]byte, len(addresses)*headerBytes)
	local := []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}}
	remote := make([]unix.RemoteIovec, 0, len(addresses))
	for _, address := range addresses {
		remote = append(remote, unix.RemoteIovec{Base: uintptr(address), Len: headerBytes})
	}
	read, _ := unix.ProcessVMReadv(memory.pid, local, remote, 0)
	if read <= 0 {
		return nil, 0
	}
	completed := read / headerBytes
	return data[:completed*headerBytes], completed
}

func captureResolvedReference(header []byte, objectAddress uint64,
	uses []sampledReferenceUse, memory processMemory, metadata *hotspotMetadata,
	classes map[uint64]*hotspotClass, encoding hotspotPointerEncoding,
	mirrorOopSizeOffset int,
) {
	if uint64(len(header)) < encoding.headerBytes() {
		return
	}
	classAddress, validKlass := encoding.klassAddress(header)
	if !validKlass {
		return
	}
	referencedClass := classes[classAddress]
	var err error
	if referencedClass == nil {
		referencedClass, err = readHotSpotClass(memory, metadata, classAddress)
		if err != nil {
			return
		}
		classes[classAddress] = referencedClass
	}
	if referencedClass.layoutHelper >= 0 {
		return
	}
	size, err := hotspotObjectSize(header, referencedClass, metadata,
		mirrorOopSizeOffset, encoding.headerBytes())
	if err != nil {
		return
	}
	for _, use := range uses {
		field := use.klass.fields[use.offset]
		if field == nil {
			field = &fieldReferenceAggregate{
				referencedType: normalizeClassName(referencedClass.name),
				unique:         make(map[uint64]struct{}),
			}
			use.klass.fields[use.offset] = field
		}
		field.count++
		if _, exists := field.unique[objectAddress]; !exists {
			field.unique[objectAddress] = struct{}{}
			field.bytes = saturatedAdd(field.bytes, size)
		}
	}
}

func sortedFieldOffsets(fields map[uint32]string) []uint32 {
	offsets := make([]uint32, 0, len(fields))
	for offset := range fields {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	return offsets
}

func compressedOopParameters(memory processMemory,
	metadata *hotspotMetadata,
) (uint64, uint, error) {
	baseField := firstVMStruct(metadata,
		"CompressedOops::_base", "CompressedOops::_narrow_oop._base",
		"Universe::_narrow_oop._base")
	shiftField := firstVMStruct(metadata,
		"CompressedOops::_shift", "CompressedOops::_narrow_oop._shift",
		"Universe::_narrow_oop._shift")
	if !baseField.isStatic || !shiftField.isStatic {
		return 0, 0, errors.New("HotSpot compressed oop metadata is unavailable")
	}
	base, err := memory.uint64(baseField.address)
	if err != nil {
		return 0, 0, err
	}
	shift, err := memory.uint32(shiftField.address)
	if err != nil || shift > 16 {
		return 0, 0, errors.New("HotSpot compressed oop shift is invalid")
	}
	return base, uint(shift), nil
}

func detectHotSpotPointerEncoding(memory processMemory, metadata *hotspotMetadata,
	regions []g1Region, klassBase uint64, klassShift uint, oopBase uint64,
	oopShift uint, mirrorOopSizeOffset int,
) (hotspotPointerEncoding, error) {
	candidates := []hotspotPointerEncoding{
		{compressedKlass: true, klassBase: klassBase, klassShift: klassShift,
			compressedOops: true, oopBase: oopBase, oopShift: oopShift,
			referencesKnown: true},
		{compressedKlass: false, compressedOops: false},
	}
	probes := 0
	for _, region := range regions {
		if region.top <= region.bottom || probes >= 32 {
			continue
		}
		raw, err := memory.read(region.bottom, 32)
		if err != nil {
			continue
		}
		probes++
		for _, candidate := range candidates {
			klassAddress, ok := candidate.klassAddress(raw)
			if !ok {
				continue
			}
			klass, classErr := readHotSpotClass(memory, metadata, klassAddress)
			if classErr != nil {
				continue
			}
			size, sizeErr := hotspotObjectSize(raw, klass, metadata,
				mirrorOopSizeOffset, candidate.headerBytes())
			if sizeErr == nil && size != 0 && size <= maxJavaObjectBytes {
				return candidate, nil
			}
		}
	}
	return hotspotPointerEncoding{}, errors.New(
		"HotSpot object pointer encoding could not be identified")
}

func readInstanceOopOffsets(memory processMemory, metadata *hotspotMetadata,
	klassAddress uint64, oopBytes uint32,
) ([]uint32, error) {
	vtableField := metadata.structs["Klass::_vtable_len"]
	itableField := metadata.structs["InstanceKlass::_itable_len"]
	mapSizeField := metadata.structs["InstanceKlass::_nonstatic_oop_map_size"]
	vtableLength, err := memory.uint32(klassAddress + vtableField.offset)
	if err != nil {
		return nil, err
	}
	itableLength, err := memory.uint32(klassAddress + itableField.offset)
	if err != nil {
		return nil, err
	}
	mapWords, err := memory.uint32(klassAddress + mapSizeField.offset)
	if err != nil || mapWords > 4096 {
		return nil, errors.New("HotSpot instance oop map size is invalid")
	}
	instanceType, ok := metadata.types["InstanceKlass"]
	if !ok || instanceType.size == 0 {
		return nil, errors.New("HotSpot InstanceKlass size is unavailable")
	}
	mapAddress := klassAddress + instanceType.size +
		uint64(vtableLength+itableLength)*8
	raw, err := memory.read(mapAddress, int(mapWords)*8)
	if err != nil {
		return nil, err
	}
	offsets := make([]uint32, 0, mapWords)
	for index := uint32(0); index < mapWords; index++ {
		base := index * 8
		offset := binary.LittleEndian.Uint32(raw[base : base+4])
		count := binary.LittleEndian.Uint32(raw[base+4 : base+8])
		if offset == 0 || count > 1024 {
			return nil, errors.New("HotSpot instance oop map entry is invalid")
		}
		for slot := uint32(0); slot < count; slot++ {
			offsets = append(offsets, offset+slot*oopBytes)
		}
	}
	return offsets, nil
}

func readInstanceFieldNames(memory processMemory, metadata *hotspotMetadata,
	klassAddress uint64,
) (map[uint32]string, error) {
	streamField, ok := metadata.structs["InstanceKlass::_fieldinfo_stream"]
	if !ok {
		return readLegacyInstanceFieldNames(memory, metadata, klassAddress)
	}
	streamAddress, err := memory.uint64(klassAddress + streamField.offset)
	if err != nil || streamAddress == 0 {
		return nil, errors.New("HotSpot field-info stream is unavailable")
	}
	length, err := memory.uint32(streamAddress)
	if err != nil || length == 0 || length > 1<<20 {
		return nil, errors.New("HotSpot field-info stream length is invalid")
	}
	stream, err := memory.read(streamAddress+4, int(length))
	if err != nil {
		return nil, err
	}
	reader := unsigned5Reader{data: stream}
	javaFields, err := reader.next()
	if err != nil {
		return nil, err
	}
	injectedFields, err := reader.next()
	if err != nil || javaFields+injectedFields > 65535 {
		return nil, errors.New("HotSpot field-info count is invalid")
	}
	constantsField := metadata.structs["InstanceKlass::_constants"]
	constantPool, err := memory.uint64(klassAddress + constantsField.offset)
	if err != nil || constantPool == 0 {
		return nil, errors.New("HotSpot constant pool is unavailable")
	}
	names := make(map[uint32]string)
	for index := uint32(0); index < javaFields+injectedFields; index++ {
		nameIndex, readErr := reader.next()
		if readErr != nil {
			return names, readErr
		}
		signatureIndex, readErr := reader.next()
		if readErr != nil {
			return names, readErr
		}
		offset, readErr := reader.next()
		if readErr != nil {
			return names, readErr
		}
		accessFlags, readErr := reader.next()
		if readErr != nil {
			return names, readErr
		}
		fieldFlags, readErr := reader.next()
		if readErr != nil {
			return names, readErr
		}
		for bit := uint32(0); bit < 5; bit++ {
			if fieldFlags&(1<<bit) != 0 && (bit == 0 || bit == 2 || bit == 4) {
				if _, readErr = reader.next(); readErr != nil {
					return names, readErr
				}
			}
		}
		// ACC_STATIC fields are stored in the class mirror, not instances.
		if accessFlags&0x8 != 0 || index >= javaFields {
			continue
		}
		signature, symbolErr := readConstantPoolSymbol(memory, metadata,
			constantPool, signatureIndex)
		if symbolErr != nil || signature == "" ||
			(signature[0] != 'L' && signature[0] != '[') {
			continue
		}
		name, symbolErr := readConstantPoolSymbol(memory, metadata, constantPool,
			nameIndex)
		if symbolErr == nil && name != "" {
			names[offset] = name
		}
	}
	return names, nil
}

func readLegacyInstanceFieldNames(memory processMemory,
	metadata *hotspotMetadata, klassAddress uint64,
) (map[uint32]string, error) {
	fieldsField, ok := metadata.structs["InstanceKlass::_fields"]
	if !ok {
		return nil, errors.New("HotSpot field-info layout is unavailable")
	}
	fieldsAddress, err := memory.uint64(klassAddress + fieldsField.offset)
	if err != nil || fieldsAddress == 0 {
		return nil, errors.New("HotSpot legacy field-info array is unavailable")
	}
	length, err := memory.uint32(fieldsAddress)
	if err != nil || length == 0 || length > 6*65535 {
		return nil, errors.New("HotSpot legacy field-info length is invalid")
	}
	const legacyFieldSlots = uint32(6)
	fieldCount := length / legacyFieldSlots
	if fieldCount == 0 {
		return nil, errors.New("HotSpot legacy field-info array is empty")
	}
	raw, err := memory.read(fieldsAddress+4, int(fieldCount*legacyFieldSlots*2))
	if err != nil {
		return nil, err
	}
	constantsField := metadata.structs["InstanceKlass::_constants"]
	constantPool, err := memory.uint64(klassAddress + constantsField.offset)
	if err != nil || constantPool == 0 {
		return nil, errors.New("HotSpot constant pool is unavailable")
	}
	names := make(map[uint32]string)
	for index := uint32(0); index < fieldCount; index++ {
		entry := raw[index*legacyFieldSlots*2 : (index+1)*legacyFieldSlots*2]
		accessFlags := binary.LittleEndian.Uint16(entry[0:2])
		nameIndex := uint32(binary.LittleEndian.Uint16(entry[2:4]))
		signatureIndex := uint32(binary.LittleEndian.Uint16(entry[4:6]))
		lowPacked := uint32(binary.LittleEndian.Uint16(entry[8:10]))
		highPacked := uint32(binary.LittleEndian.Uint16(entry[10:12]))
		// The low tag bit marks a packed byte offset. Static fields reside in
		// the class mirror and internal fields may use VM symbol IDs instead of
		// constant-pool indices, so neither belongs to an instance OopMap.
		if accessFlags&0x8 != 0 || accessFlags&0x1000 != 0 || lowPacked&1 == 0 {
			continue
		}
		signature, symbolErr := readConstantPoolSymbol(memory, metadata,
			constantPool, signatureIndex)
		if symbolErr != nil || signature == "" ||
			(signature[0] != 'L' && signature[0] != '[') {
			continue
		}
		name, symbolErr := readConstantPoolSymbol(memory, metadata, constantPool,
			nameIndex)
		if symbolErr != nil || name == "" {
			continue
		}
		packedOffset := lowPacked | highPacked<<16
		names[packedOffset>>2] = name
	}
	return names, nil
}

func readConstantPoolSymbol(memory processMemory, metadata *hotspotMetadata,
	constantPool uint64, index uint32,
) (string, error) {
	typeInfo, ok := metadata.types["ConstantPool"]
	if !ok || typeInfo.size == 0 || index > 65535 {
		return "", errors.New("HotSpot ConstantPool layout is invalid")
	}
	symbolAddress, err := memory.uint64(constantPool + typeInfo.size + uint64(index)*8)
	if err != nil || symbolAddress == 0 {
		return "", errors.New("HotSpot constant pool symbol is unavailable")
	}
	return readHotSpotSymbol(memory, metadata, symbolAddress)
}

type unsigned5Reader struct {
	data     []byte
	position int
}

func (r *unsigned5Reader) next() (uint32, error) {
	const (
		excluded = uint32(1)
		lowCount = uint32(191)
	)
	if r.position >= len(r.data) {
		return 0, errors.New("HotSpot UNSIGNED5 stream ended early")
	}
	var sum uint32
	shift := uint(0)
	for index := 0; index < 5; index++ {
		if r.position >= len(r.data) {
			return 0, errors.New("HotSpot UNSIGNED5 value is truncated")
		}
		value := uint32(r.data[r.position])
		r.position++
		if value < excluded {
			return 0, errors.New("HotSpot UNSIGNED5 contains an excluded byte")
		}
		sum += (value - excluded) << shift
		if value < excluded+lowCount || index == 4 {
			return sum, nil
		}
		shift += 6
	}
	return 0, errors.New("HotSpot UNSIGNED5 value exceeds five bytes")
}

func isBusinessHotSpotClass(name string) bool {
	return name != "" && name[0] != '[' &&
		!strings.HasPrefix(name, "java/") &&
		!strings.HasPrefix(name, "jdk/") &&
		!strings.HasPrefix(name, "sun/") &&
		!strings.HasPrefix(name, "com/sun/")
}

const (
	g1YoungKind = iota
	g1OldKind
	g1OtherKind
	g1RegionKinds
	g1OccupancyBuckets = 4
	g1HumongousStratum = g1RegionKinds * g1OccupancyBuckets
	g1FallbackStratum  = g1HumongousStratum + 1
	g1FallbackStrata   = 64
)

func planG1RegionSample(regions []g1Region,
	metadata *hotspotMetadata,
) g1SamplingPlan {
	return planG1RegionSampleForBudget(regions, metadata, 0, false)
}

func planG1RegionSampleWithPrefix(regions []g1Region,
	metadata *hotspotMetadata, prefixBytes uint64,
) g1SamplingPlan {
	return planG1RegionSampleForBudget(regions, metadata, prefixBytes, false)
}

func planG1RegionSampleForBudget(regions []g1Region,
	metadata *hotspotMetadata, prefixBytes uint64, exhaustBudget bool,
) g1SamplingPlan {
	plan := g1SamplingPlan{strata: make(map[int]*g1SamplingStratum)}
	if len(regions) == 0 {
		return plan
	}
	regionCapacity := inferG1RegionCapacity(regions)
	units, ok := buildG1RegionUnits(regions, metadata, regionCapacity)
	if !ok {
		// When VM region tags are unavailable, occupancy is a safer estimator
		// stratum than address. Allocation phases are commonly contiguous in
		// address space; treating each phase as its own population amplifies a
		// class concentrated in only a few Regions.
		for index, region := range regions {
			stratumKey := g1FallbackStratum + g1OccupancyBucket(
				region.top-region.bottom, regionCapacity)
			stratum := plan.strata[stratumKey]
			if stratum == nil {
				stratum = &g1SamplingStratum{
					name: fmt.Sprintf("fallback_occupancy_%02d",
						stratumKey-g1FallbackStratum),
				}
				plan.strata[stratumKey] = stratum
			}
			region.scanGroup = uint64(index + 1)
			region.capacity = regionCapacity
			region.stratum = stratumKey
			used := region.top - region.bottom
			plan.units = append(plan.units, g1RegionUnit{
				regions: []g1Region{region}, stratum: stratumKey,
				usedBytes: used,
			})
			stratum.totalRegions++
			stratum.plannedRegions++
			stratum.totalUsedBytes = saturatedAdd(stratum.totalUsedBytes, used)
		}
		plan.seed = g1SamplingSeed(regions)
		if prefixBytes != 0 {
			orderG1PrefixSamplingCandidates(plan.units)
			for unitIndex := range plan.units {
				for regionIndex := range plan.units[unitIndex].regions {
					used := plan.units[unitIndex].regions[regionIndex].top -
						plan.units[unitIndex].regions[regionIndex].bottom
					if used > prefixBytes {
						plan.units[unitIndex].regions[regionIndex].sampleBytes =
							prefixBytes
					}
				}
			}
			plan.estimated = true
		}
		return plan
	}
	plan.seed = g1SamplingSeed(regions)
	strataUnits := make(map[int][]g1RegionUnit)
	var heapUsed uint64
	var nonHumongousUsed uint64
	for _, unit := range units {
		strataUnits[unit.stratum] = append(strataUnits[unit.stratum], unit)
		heapUsed = saturatedAdd(heapUsed, unit.usedBytes)
		stratum := plan.strata[unit.stratum]
		if stratum == nil {
			stratum = &g1SamplingStratum{name: g1SamplingStratumName(unit.stratum)}
			plan.strata[unit.stratum] = stratum
		}
		stratum.totalRegions = saturatedAdd(stratum.totalRegions,
			uint64(len(unit.regions)))
		stratum.totalUsedBytes = saturatedAdd(stratum.totalUsedBytes, unit.usedBytes)
		if !unit.humongous {
			nonHumongousUsed = saturatedAdd(nonHumongousUsed, unit.usedBytes)
		}
	}
	target := heapUsed * hotspotSamplePercent / 100
	if target < hotspotMinimumSampleBytes {
		target = hotspotMinimumSampleBytes
	}
	if target > hotspotMaximumSampleBytes {
		target = hotspotMaximumSampleBytes
	}
	if target > nonHumongousUsed {
		target = nonHumongousUsed
	}

	selected := make(map[int][]g1RegionUnit, len(strataUnits))
	remaining := make(map[int][]g1RegionUnit, len(strataUnits))
	for key, candidates := range strataUnits {
		if prefixBytes != 0 && key != g1HumongousStratum {
			orderG1PrefixSamplingCandidates(candidates)
		} else {
			orderG1SamplingCandidates(candidates, plan.seed^uint64(key+1))
		}
		if key == g1HumongousStratum {
			selected[key] = candidates
			continue
		}
		desired := uint64(0)
		if nonHumongousUsed != 0 {
			desired = target * plan.strata[key].totalUsedBytes / nonHumongousUsed
		}
		minimum := 2
		if len(candidates) < minimum {
			minimum = len(candidates)
		}
		var selectedBytes uint64
		for index, unit := range candidates {
			if index >= minimum && selectedBytes >= desired {
				if exhaustBudget {
					for _, extra := range candidates[index:] {
						remaining[key] = append(remaining[key],
							limitG1RegionUnitSample(extra, prefixBytes))
					}
				}
				break
			}
			unit = limitG1RegionUnitSample(unit, prefixBytes)
			if prefixBytes != 0 && !unit.humongous {
				plan.estimated = true
			}
			selected[key] = append(selected[key], unit)
			selectedBytes = saturatedAdd(selectedBytes,
				g1UnitSampleBytes(unit))
		}
		if len(selected[key]) < len(candidates) {
			plan.estimated = true
		}
	}

	// Exact humongous objects are both cheap (only their header is read) and
	// highly diagnostic for OOM. Publish one unit as first evidence, then keep
	// the remaining units in the normal round-robin so a humongous-heavy heap
	// cannot starve every ordinary-region stratum during a short gate.
	if humongous := selected[g1HumongousStratum]; len(humongous) != 0 {
		unit := humongous[0]
		plan.units = append(plan.units, unit)
		plan.strata[g1HumongousStratum].plannedRegions = saturatedAdd(
			plan.strata[g1HumongousStratum].plannedRegions,
			uint64(len(unit.regions)))
		selected[g1HumongousStratum] = humongous[1:]
	}
	keys := make([]int, 0, len(selected))
	for key := range selected {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	// A ratio estimate from one normal region is too unstable in an extreme
	// heap. Complete the planned two-region floor for every normal stratum
	// before resuming the general round-robin.
	for _, key := range keys {
		if key == g1HumongousStratum {
			continue
		}
		bootstrap := 2
		if len(selected[key]) < bootstrap {
			bootstrap = len(selected[key])
		}
		for _, unit := range selected[key][:bootstrap] {
			plan.units = append(plan.units, unit)
			plan.strata[key].plannedRegions = saturatedAdd(
				plan.strata[key].plannedRegions, uint64(len(unit.regions)))
		}
		selected[key] = selected[key][bootstrap:]
	}
	for {
		progress := false
		for _, key := range keys {
			if len(selected[key]) == 0 {
				continue
			}
			unit := selected[key][0]
			selected[key] = selected[key][1:]
			plan.units = append(plan.units, unit)
			plan.strata[key].plannedRegions = saturatedAdd(
				plan.strata[key].plannedRegions, uint64(len(unit.regions)))
			progress = true
		}
		if !progress {
			break
		}
	}
	if exhaustBudget {
		// The fixed sample above guarantees representation for each stratum.
		// During a short OOM gate, keep visiting the remaining strata in round-
		// robin order and let the scan deadline stop the walk. This converts
		// otherwise idle gate time into coverage without extending the gate.
		for {
			progress := false
			for _, key := range keys {
				if len(remaining[key]) == 0 {
					continue
				}
				unit := remaining[key][0]
				remaining[key] = remaining[key][1:]
				plan.units = append(plan.units, unit)
				plan.strata[key].plannedRegions = saturatedAdd(
					plan.strata[key].plannedRegions, uint64(len(unit.regions)))
				progress = true
			}
			if !progress {
				break
			}
		}
		if prefixBytes == 0 {
			// Every full region is now planned. A deadline-shortened walk is
			// changed back to estimated after the scan sees incomplete coverage.
			plan.estimated = false
		}
	}
	return plan
}

func limitG1RegionUnitSample(unit g1RegionUnit, prefixBytes uint64) g1RegionUnit {
	if prefixBytes == 0 || unit.humongous {
		return unit
	}
	for regionIndex := range unit.regions {
		used := unit.regions[regionIndex].top - unit.regions[regionIndex].bottom
		if used > prefixBytes {
			unit.regions[regionIndex].sampleBytes = prefixBytes
		}
	}
	return unit
}

func g1UnitSampleBytes(unit g1RegionUnit) uint64 {
	var result uint64
	for _, region := range unit.regions {
		used := region.top - region.bottom
		if region.sampleBytes != 0 && used > region.sampleBytes {
			used = region.sampleBytes
		}
		result = saturatedAdd(result, used)
	}
	return result
}

func buildG1RegionUnits(regions []g1Region, metadata *hotspotMetadata,
	capacity uint64,
) ([]g1RegionUnit, bool) {
	starts, startsOK := metadata.constants["G1HeapRegionType::StartsHumongousTag"]
	continues, continuesOK := metadata.constants["G1HeapRegionType::ContinuesHumongousTag"]
	if !startsOK || !continuesOK {
		return nil, false
	}
	units := make([]g1RegionUnit, 0, len(regions))
	var scanGroup uint64
	for index := 0; index < len(regions); {
		region := regions[index]
		if !region.tagged {
			return nil, false
		}
		scanGroup++
		kind := g1RegionKind(region.tag, metadata)
		stratum := kind*g1OccupancyBuckets + g1OccupancyBucket(
			region.top-region.bottom, capacity)
		unit := g1RegionUnit{
			regions: []g1Region{region}, stratum: stratum,
			usedBytes: region.top - region.bottom,
		}
		unit.regions[0].scanGroup = scanGroup
		unit.regions[0].capacity = capacity
		unit.regions[0].stratum = stratum
		if int64(region.tag) == starts {
			unit.stratum = g1HumongousStratum
			unit.humongous = true
			unit.regions[0].stratum = g1HumongousStratum
			unit.regions[0].humongous = true
			for next := index + 1; next < len(regions) &&
				int64(regions[next].tag) == continues &&
				regions[next-1].top == regions[next].bottom; next++ {
				continuation := regions[next]
				continuation.scanGroup = scanGroup
				continuation.capacity = capacity
				continuation.stratum = g1HumongousStratum
				continuation.humongous = true
				unit.regions = append(unit.regions, continuation)
				unit.usedBytes = saturatedAdd(unit.usedBytes,
					continuation.top-continuation.bottom)
				index = next
			}
		}
		units = append(units, unit)
		index++
	}
	return units, true
}

func flattenG1SamplingPlan(plan g1SamplingPlan) []g1Region {
	count := 0
	for _, unit := range plan.units {
		count += len(unit.regions)
	}
	ordered := make([]g1Region, 0, count)
	for _, unit := range plan.units {
		ordered = append(ordered, unit.regions...)
	}
	return ordered
}

func scheduleG1Regions(regions []g1Region, metadata *hotspotMetadata) []g1Region {
	return flattenG1SamplingPlan(planG1RegionSample(regions, metadata))
}

func g1RegionKind(tag uint32, metadata *hotspotMetadata) int {
	youngMask := uint32(metadata.constants["G1HeapRegionType::YoungMask"])
	oldMask := uint32(metadata.constants["G1HeapRegionType::OldMask"])
	switch {
	case youngMask != 0 && tag&youngMask != 0:
		return g1YoungKind
	case oldMask != 0 && tag&oldMask != 0:
		return g1OldKind
	default:
		return g1OtherKind
	}
}

func inferG1RegionCapacity(regions []g1Region) uint64 {
	capacity := uint64(0)
	for index := 1; index < len(regions); index++ {
		if regions[index].bottom <= regions[index-1].bottom {
			continue
		}
		delta := regions[index].bottom - regions[index-1].bottom
		if capacity == 0 || delta < capacity {
			capacity = delta
		}
	}
	if capacity == 0 {
		for _, region := range regions {
			if used := region.top - region.bottom; used > capacity {
				capacity = used
			}
		}
	}
	return capacity
}

func g1OccupancyBucket(used, capacity uint64) int {
	if capacity == 0 || used >= capacity {
		return g1OccupancyBuckets - 1
	}
	percent := used * 100 / capacity
	switch {
	case percent <= 25:
		return 0
	case percent <= 50:
		return 1
	case percent <= 75:
		return 2
	default:
		return 3
	}
}

func g1SamplingSeed(regions []g1Region) uint64 {
	seed := uint64(0xcbf29ce484222325)
	for _, region := range regions {
		seed ^= region.bottom
		seed *= 0x100000001b3
		seed ^= region.top - region.bottom
		seed *= 0x100000001b3
	}
	return seed
}

func orderG1SamplingCandidates(units []g1RegionUnit, seed uint64) {
	sort.SliceStable(units, func(i, j int) bool {
		left := mixG1SampleValue(units[i].regions[0].bottom ^ seed)
		right := mixG1SampleValue(units[j].regions[0].bottom ^ seed)
		if left == right {
			return units[i].regions[0].bottom < units[j].regions[0].bottom
		}
		return left < right
	})
}

func orderG1PrefixSamplingCandidates(units []g1RegionUnit) {
	sort.SliceStable(units, func(i, j int) bool {
		return units[i].regions[0].bottom < units[j].regions[0].bottom
	})
	if len(units) < 3 {
		return
	}
	// Visit address quantiles in bit-reversed order. Every short prefix of this
	// sequence spans the stratum instead of following one allocation phase.
	ordered := make([]g1RegionUnit, 0, len(units))
	used := make([]bool, len(units))
	for denominator := 1; len(ordered) < len(units); denominator <<= 1 {
		for numerator := 1; numerator < denominator; numerator += 2 {
			index := numerator * len(units) / denominator
			if index >= len(units) {
				index = len(units) - 1
			}
			if !used[index] {
				ordered = append(ordered, units[index])
				used[index] = true
			}
		}
		if denominator > len(units)*2 {
			break
		}
	}
	for index := range units {
		if !used[index] {
			ordered = append(ordered, units[index])
		}
	}
	copy(units, ordered)
}

func mixG1SampleValue(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	return value ^ (value >> 31)
}

func regionStratumKey(region g1Region) int {
	return region.stratum
}

func g1SamplingStratumName(stratum int) string {
	if stratum == g1HumongousStratum {
		return "humongous_exact"
	}
	if stratum >= g1FallbackStratum &&
		stratum < g1FallbackStratum+g1FallbackStrata {
		return fmt.Sprintf("fallback_occupancy_%02d", stratum-g1FallbackStratum)
	}
	kinds := [...]string{"young", "old", "other"}
	buckets := [...]string{"0_25", "25_50", "50_75", "75_100"}
	kind := stratum / g1OccupancyBuckets
	bucket := stratum % g1OccupancyBuckets
	if kind < 0 || kind >= len(kinds) || bucket < 0 || bucket >= len(buckets) {
		return "unknown"
	}
	return kinds[kind] + "_" + buckets[bucket]
}

func estimateG1Aggregates(aggregates map[uint64]*memsnap.ObjectAggregate,
	statistics g1OnlineStatistics, plan g1SamplingPlan,
) {
	for classAddress, aggregate := range aggregates {
		aggregate.SampledBytes = aggregate.ShallowBytes
		aggregate.SampledCount = aggregate.Count
		if !plan.estimated {
			continue
		}
		estimatedBytes := uint64(0)
		estimatedCount := uint64(0)
		varianceBytes := float64(0)
		confidenceAvailable := false
		for key, stratum := range plan.strata {
			stratumStatistics := statistics[key]
			var sampleUsed, sampleBytes, sampleCount, classRegions uint64
			var classStatistics *g1ClassStatistics
			if stratumStatistics != nil {
				sampleUsed = stratumStatistics.usedBytes
				classStatistics = stratumStatistics.classes[classAddress]
			}
			if classStatistics != nil {
				sampleBytes = classStatistics.bytes
				sampleCount = classStatistics.count
				classRegions = classStatistics.regions
			}
			aggregate.SampledRegions = saturatedAdd(aggregate.SampledRegions,
				classRegions)
			if key == g1HumongousStratum || sampleUsed == 0 ||
				sampleUsed >= stratum.totalUsedBytes {
				estimatedBytes = saturatedAdd(estimatedBytes, sampleBytes)
				estimatedCount = saturatedAdd(estimatedCount, sampleCount)
				continue
			}
			stratumBytes := scaleG1Estimate(sampleBytes, stratum.totalUsedBytes,
				sampleUsed)
			stratumCount := scaleG1Estimate(sampleCount, stratum.totalUsedBytes,
				sampleUsed)
			estimatedBytes = saturatedAdd(estimatedBytes, stratumBytes)
			estimatedCount = saturatedAdd(estimatedCount, stratumCount)
			if stratumStatistics != nil && stratumStatistics.regions >= 2 &&
				sampleBytes != 0 {
				varianceBytes += g1RatioEstimateVariance(stratumStatistics,
					classStatistics,
					stratum.totalRegions, stratum.totalUsedBytes)
				confidenceAvailable = true
			}
		}
		if estimatedBytes < aggregate.SampledBytes {
			estimatedBytes = aggregate.SampledBytes
		}
		if estimatedCount < aggregate.SampledCount {
			estimatedCount = aggregate.SampledCount
		}
		aggregate.ShallowBytes = estimatedBytes
		aggregate.Count = estimatedCount
		aggregate.Estimated = estimatedBytes != aggregate.SampledBytes ||
			estimatedCount != aggregate.SampledCount
		if !aggregate.Estimated {
			continue
		}
		if !confidenceAvailable || varianceBytes <= 0 {
			aggregate.EstimateConfidence = "insufficient_sample"
			continue
		}
		standardError := math.Sqrt(varianceBytes)
		aggregate.EstimateRSE = standardError / float64(estimatedBytes)
		margin := 1.96 * standardError
		lower := float64(estimatedBytes) - margin
		if lower < float64(aggregate.SampledBytes) {
			lower = float64(aggregate.SampledBytes)
		}
		upper := float64(estimatedBytes) + margin
		aggregate.EstimateLowerBytes = clampFloatToUint64(lower)
		aggregate.EstimateUpperBytes = clampFloatToUint64(upper)
		aggregate.EstimateConfidence = "approx_95_percent"
	}
}

func scaleG1Estimate(observed, totalUsed, sampledUsed uint64) uint64 {
	if observed == 0 || totalUsed == 0 || sampledUsed == 0 {
		return 0
	}
	estimate := float64(observed) * float64(totalUsed) / float64(sampledUsed)
	result := clampFloatToUint64(math.Round(estimate))
	if result < observed {
		return observed
	}
	return result
}

func g1RatioEstimateVariance(samples *g1StratumStatistics,
	classSample *g1ClassStatistics,
	totalRegions, totalUsed uint64,
) float64 {
	if samples == nil || classSample == nil || samples.regions < 2 ||
		totalRegions <= samples.regions {
		return 0
	}
	if samples.usedBytes == 0 {
		return 0
	}
	ratio := float64(classSample.bytes) / float64(samples.usedBytes)
	residualSquares := classSample.bytesSquaredSum -
		2*ratio*classSample.usedBytesCross +
		ratio*ratio*samples.usedSquaredSum
	if residualSquares < 0 {
		residualSquares = 0
	}
	n := float64(samples.regions)
	population := float64(totalRegions)
	sampleVariance := residualSquares / (n - 1)
	meanUsed := float64(totalUsed) / population
	if meanUsed == 0 {
		return 0
	}
	// Ratio-estimator variance with a finite-population correction. Occupancy
	// buckets keep the region used-byte spread bounded enough for this FAST-mode
	// confidence interval to be useful without pretending it is exact.
	return population * population * (1 - n/population) * sampleVariance / n
}

func clampFloatToUint64(value float64) uint64 {
	if value <= 0 || math.IsNaN(value) {
		return 0
	}
	if value >= float64(^uint64(0)) || math.IsInf(value, 1) {
		return ^uint64(0)
	}
	return uint64(value)
}

func samplingCoverage(plan g1SamplingPlan) []memsnap.SamplingStratumCoverage {
	keys := make([]int, 0, len(plan.strata))
	for key := range plan.strata {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	result := make([]memsnap.SamplingStratumCoverage, 0, len(keys))
	for _, key := range keys {
		stratum := plan.strata[key]
		result = append(result, memsnap.SamplingStratumCoverage{
			Name: stratum.name, TotalRegions: stratum.totalRegions,
			PlannedRegions:   stratum.plannedRegions,
			CompletedRegions: stratum.completedRegions,
			TotalUsedBytes:   stratum.totalUsedBytes,
			ClassifiedBytes:  stratum.classifiedBytes,
		})
	}
	return result
}

func g1Regions(memory processMemory, metadata *hotspotMetadata) ([]g1Region, error) {
	heapField, ok := metadata.structs["Universe::_collectedHeap"]
	if !ok || !heapField.isStatic || heapField.address == 0 {
		return nil, errors.New("HotSpot Universe heap pointer is unavailable")
	}
	heap, err := memory.uint64(heapField.address)
	if err != nil || heap == 0 {
		return nil, errors.New("HotSpot collected heap pointer is invalid")
	}
	hrmField, ok := metadata.structs["G1CollectedHeap::_hrm"]
	if !ok {
		return nil, errOnlyHotSpotG1
	}
	regionsField := firstVMStruct(metadata,
		"G1HeapRegionManager::_regions", "HeapRegionManager::_regions")
	if regionsField.typeString == "" {
		return nil, unsupportedHotSpotG1("region manager layout is unavailable")
	}
	table := heap + hrmField.offset + regionsField.offset
	baseField := metadata.structs["G1HeapRegionTable::_base"]
	lengthField := metadata.structs["G1HeapRegionTable::_length"]
	base, err := memory.uint64(table + baseField.offset)
	if err != nil || base == 0 || base&7 != 0 {
		return nil, unsupportedHotSpotG1("region table base is invalid")
	}
	length, err := memory.uint64(table + lengthField.offset)
	if err != nil || length == 0 || length > maxG1Regions {
		return nil, unsupportedHotSpotG1("region table length is invalid")
	}
	pointers, err := memory.read(base, int(length)*8)
	if err != nil {
		return nil, unsupportedHotSpotG1(fmt.Sprintf("read region table: %v", err))
	}
	regionType := "G1HeapRegion"
	if _, ok := metadata.types[regionType]; !ok {
		regionType = "HeapRegion"
	}
	bottomField := inheritedVMStruct(metadata, regionType, "_bottom")
	topField := inheritedVMStruct(metadata, regionType, "_top")
	endField := inheritedVMStruct(metadata, regionType, "_end")
	if bottomField.typeString == "" || topField.typeString == "" ||
		endField.typeString == "" {
		return nil, unsupportedHotSpotG1("region boundary layout is unavailable")
	}
	typeField := metadata.structs[regionType+"::_type"]
	tagField := metadata.structs["G1HeapRegionType::_tag"]
	hasRegionTags := typeField.typeString != "" && tagField.typeString != ""
	regions := make([]g1Region, 0, length)
	var minimumRegionCapacity uint64
	for index := uint64(0); index < length; index++ {
		regionAddress := binary.LittleEndian.Uint64(pointers[index*8 : index*8+8])
		if regionAddress == 0 {
			continue
		}
		if regionAddress&7 != 0 {
			return nil, unsupportedHotSpotG1("region pointer is misaligned")
		}
		bottom, bottomErr := memory.uint64(regionAddress + bottomField.offset)
		top, topErr := memory.uint64(regionAddress + topField.offset)
		end, endErr := memory.uint64(regionAddress + endField.offset)
		capacity := end - bottom
		if bottomErr != nil || topErr != nil || endErr != nil || bottom == 0 ||
			bottom&7 != 0 || top&7 != 0 || end&7 != 0 || top < bottom ||
			end <= bottom || top > end || capacity < 1<<20 || capacity > 512<<20 {
			return nil, unsupportedHotSpotG1(fmt.Sprintf(
				"region %d boundaries are invalid: bottom=%#x top=%#x end=%#x",
				index, bottom, top, end))
		}
		if minimumRegionCapacity == 0 || capacity < minimumRegionCapacity {
			minimumRegionCapacity = capacity
		}
		region := g1Region{bottom: bottom, top: top, capacity: capacity}
		if hasRegionTags {
			tag, tagErr := memory.uint32(regionAddress + typeField.offset +
				tagField.offset)
			if tagErr == nil {
				region.tag = tag
				region.tagged = true
			}
		}
		regions = append(regions, region)
	}
	if len(regions) == 0 {
		return nil, unsupportedHotSpotG1("region table contains no regions")
	}
	// JDK 8 exposes a humongous start Region whose _end spans its continuation
	// Regions. Its capacity is therefore an integer multiple of the configured
	// G1 Region size rather than equal to it.
	if minimumRegionCapacity&(minimumRegionCapacity-1) != 0 {
		return nil, unsupportedHotSpotG1("minimum region capacity is invalid")
	}
	for _, region := range regions {
		if region.capacity%minimumRegionCapacity != 0 {
			return nil, unsupportedHotSpotG1("region capacities are inconsistent")
		}
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].bottom < regions[j].bottom })
	normalized := regions[:0]
	for _, region := range regions {
		if len(normalized) == 0 {
			normalized = append(normalized, region)
			continue
		}
		previous := normalized[len(normalized)-1]
		previousEnd := previous.bottom + previous.capacity
		regionEnd := region.bottom + region.capacity
		if region.bottom >= previousEnd {
			normalized = append(normalized, region)
			continue
		}
		// JDK 8 retains table entries for continuation Regions covered by the
		// humongous start Region's spanning _end. Ignore only those completely
		// contained base-size entries; all other overlap remains invalid.
		if region.capacity == minimumRegionCapacity && regionEnd <= previousEnd {
			continue
		}
		if region.bottom < previousEnd {
			return nil, unsupportedHotSpotG1("regions overlap")
		}
	}
	return normalized, nil
}

func compressedKlassParameters(memory processMemory,
	metadata *hotspotMetadata,
) (uint64, uint, error) {
	baseField := firstVMStruct(metadata, "CompressedKlassPointers::_base",
		"CompressedKlassPointers::_narrow_klass._base",
		"Universe::_narrow_klass._base")
	shiftField := firstVMStruct(metadata, "CompressedKlassPointers::_shift",
		"CompressedKlassPointers::_narrow_klass._shift",
		"Universe::_narrow_klass._shift")
	if !baseField.isStatic || !shiftField.isStatic {
		return 0, 0, errors.New("HotSpot compressed Klass metadata is unavailable")
	}
	base, err := memory.uint64(baseField.address)
	if err != nil {
		return 0, 0, err
	}
	shift, err := memory.uint32(shiftField.address)
	if err != nil || shift > 16 {
		return 0, 0, errors.New("HotSpot compressed Klass shift is invalid")
	}
	return base, uint(shift), nil
}

func firstVMStruct(metadata *hotspotMetadata, names ...string) vmStruct {
	for _, name := range names {
		if field, ok := metadata.structs[name]; ok {
			return field
		}
	}
	return vmStruct{}
}

func inheritedVMStruct(metadata *hotspotMetadata, typeName, fieldName string) vmStruct {
	for depth := 0; typeName != "" && depth < 16; depth++ {
		if field, ok := metadata.structs[typeName+"::"+fieldName]; ok {
			return field
		}
		// JDK 11's VMType table omits the G1ContiguousSpace to Space link,
		// although the C++ layout still embeds Space at offset zero.
		if typeName == "G1ContiguousSpace" && fieldName == "_bottom" {
			return metadata.structs["Space::_bottom"]
		}
		typeName = metadata.types[typeName].superclass
	}
	return vmStruct{}
}

func readHotSpotClass(memory processMemory, metadata *hotspotMetadata,
	address uint64,
) (*hotspotClass, error) {
	if address == 0 || address&7 != 0 {
		return nil, errors.New("HotSpot Klass address is invalid")
	}
	layoutField := metadata.structs["Klass::_layout_helper"]
	nameField := metadata.structs["Klass::_name"]
	layout, err := memory.uint32(address + layoutField.offset)
	if err != nil {
		return nil, err
	}
	namePointer, err := memory.uint64(address + nameField.offset)
	if err != nil || namePointer == 0 {
		return nil, errors.New("HotSpot Klass name is unavailable")
	}
	name, err := readHotSpotSymbol(memory, metadata, namePointer)
	if err != nil {
		return nil, fmt.Errorf("read HotSpot Klass name: %w", err)
	}
	return &hotspotClass{
		address: address, name: name, layoutHelper: int32(layout),
	}, nil
}

func readHotSpotSymbol(memory processMemory, metadata *hotspotMetadata,
	address uint64,
) (string, error) {
	lengthField, lengthOK := metadata.structs["Symbol::_length"]
	bodyField, bodyOK := metadata.structs["Symbol::_body[0]"]
	if !bodyOK {
		bodyField, bodyOK = metadata.structs["Symbol::_body"]
	}
	if !lengthOK || !bodyOK {
		return "", errors.New("HotSpot Symbol layout is unavailable")
	}
	lengthRaw, err := memory.read(address+lengthField.offset, 2)
	if err != nil {
		return "", err
	}
	length := binary.LittleEndian.Uint16(lengthRaw)
	if length == 0 || length > maxHotSpotStringBytes {
		return "", errors.New("HotSpot Symbol length is invalid")
	}
	raw, err := memory.read(address+bodyField.offset, int(length))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func hotspotObjectSize(raw []byte, klass *hotspotClass,
	metadata *hotspotMetadata, mirrorOopSizeOffset int, objectHeaderBytes uint64,
) (uint64, error) {
	layout := klass.layoutHelper
	if layout > 0 {
		slowBit := uint32(metadata.constants["Klass::_lh_instance_slow_path_bit"])
		if uint32(layout)&slowBit != 0 {
			if klass.name != "java/lang/Class" {
				return 0, fmt.Errorf("unsupported HotSpot slow-path instance %s",
					klass.name)
			}
			if mirrorOopSizeOffset <= 0 || mirrorOopSizeOffset+4 > len(raw) {
				return 0, errors.New("HotSpot class mirror size field is unavailable")
			}
			words := binary.LittleEndian.Uint32(
				raw[mirrorOopSizeOffset : mirrorOopSizeOffset+4])
			if words == 0 {
				return 0, errors.New("HotSpot class mirror size is zero")
			}
			return uint64(words) * uint64(metadata.constants["HeapWordSize"]), nil
		}
		bytes := uint64(uint32(layout) &^ slowBit)
		if bytes == 0 {
			return 0, errors.New("HotSpot instance size is zero")
		}
		return alignUp(bytes, objectAlignment), nil
	}
	if layout == 0 {
		return 0, errors.New("HotSpot neutral layout helper is unsupported")
	}
	headerShift := uint(metadata.constants["Klass::_lh_header_size_shift"])
	headerMask := uint32(metadata.constants["Klass::_lh_header_size_mask"])
	elementShift := uint(metadata.constants["Klass::_lh_log2_element_size_shift"])
	elementMask := uint32(metadata.constants["Klass::_lh_log2_element_size_mask"])
	headerBytes := uint64((uint32(layout) >> headerShift) & headerMask)
	logElementBytes := (uint32(layout) >> elementShift) & elementMask
	lengthOffset := int64(objectHeaderBytes)
	if value, ok := metadata.constants["arrayOopDesc_length_offset_in_bytes"]; ok {
		lengthOffset = value
	}
	if lengthOffset < 0 || lengthOffset+4 > int64(len(raw)) || logElementBytes > 8 {
		return 0, errors.New("HotSpot array layout is invalid")
	}
	length := binary.LittleEndian.Uint32(raw[lengthOffset : lengthOffset+4])
	bytes := headerBytes + (uint64(length) << logElementBytes)
	return alignUp(bytes, objectAlignment), nil
}

func classMirrorOopSizeOffset(memory processMemory,
	metadata *hotspotMetadata,
) (int, error) {
	field, ok := metadata.structs["java_lang_Class::_oop_size_offset"]
	if !ok || !field.isStatic || field.address == 0 {
		return 0, errors.New("HotSpot class mirror size offset is unavailable")
	}
	value, err := memory.uint32(field.address)
	if err != nil || value > 4096 {
		return 0, errors.New("HotSpot class mirror size offset is invalid")
	}
	return int(value), nil
}

func g1ShortWindowPrefixBytes(ctx context.Context, regions []g1Region,
	heapUsedBytes uint64,
) uint64 {
	if !g1ShortWindow(ctx) {
		return 0
	}
	regionCount := uint64(0)
	for _, region := range regions {
		if region.top > region.bottom {
			regionCount++
		}
	}
	if regionCount == 0 {
		return hotspotShortRegionPrefixBytes
	}
	minimumTarget := uint64(hotspotMinimumSampleBytes)
	maximumTarget := uint64(hotspotShortMaximumSampleBytes)
	if inferG1RegionCapacity(regions) > 2<<20 {
		// Large Regions need distributed windows rather than a large contiguous
		// byte budget. Sixty-four windows spread this bounded budget across each
		// Region and leave enough time to finish before the short gate expires.
		minimumTarget = hotspotShortLargeRegionBytes
		maximumTarget = hotspotShortLargeRegionBytes
	}
	target := heapUsedBytes * hotspotSamplePercent / 100
	if target < minimumTarget {
		target = minimumTarget
	}
	if target > maximumTarget {
		target = maximumTarget
	}
	if target > heapUsedBytes {
		target = heapUsedBytes
	}
	prefixBytes := alignUp((target+regionCount-1)/regionCount, objectAlignment)
	if prefixBytes < hotspotShortRegionPrefixBytes {
		return hotspotShortRegionPrefixBytes
	}
	return prefixBytes
}

func g1ShortWindow(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) < 100*time.Millisecond
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func saturatedAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}
