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
	"bufio"
	"context"
	"encoding/binary"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

func TestExternalReaderAgainstVersionedG1Fixture(t *testing.T) {
	javaHome := os.Getenv("HUATUO_TEST_JAVA_HOME")
	if javaHome == "" {
		t.Skip("HUATUO_TEST_JAVA_HOME is unset")
	}
	fixtureDir := os.Getenv("HUATUO_TEST_JAVA_FIXTURE_DIR")
	if fixtureDir == "" {
		t.Fatal("HUATUO_TEST_JAVA_FIXTURE_DIR is unset")
	}
	java := filepath.Join(javaHome, "bin", "java")
	javaOptions := []string{"-XX:+UseG1GC", "-Xms256m", "-Xmx2g"}
	if value := os.Getenv("HUATUO_TEST_JAVA_OPTIONS"); value != "" {
		javaOptions = strings.Fields(value)
	}
	javaOptions = append(javaOptions, "-cp", fixtureDir, "HuatuoSnapshotFixture")
	command := exec.Command(java, javaOptions...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() ||
		!strings.HasPrefix(scanner.Text(), "READY ") {
		t.Fatal("Java fixture did not become ready")
	}
	gateMilliseconds := uint64(500)
	if value := os.Getenv("HUATUO_TEST_GATE_MILLISECONDS"); value != "" {
		parsed, parseErr := strconv.ParseUint(value, 10, 64)
		if parseErr != nil || parsed == 0 {
			t.Fatalf("invalid HUATUO_TEST_GATE_MILLISECONDS=%q", value)
		}
		gateMilliseconds = parsed
	}
	gateDuration := time.Duration(gateMilliseconds) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), gateDuration)
	defer cancel()
	started := time.Now()
	snapshot, err := NewExternalReader("/proc").Capture(ctx,
		memsnap.ProcessIdentity{TGID: command.Process.Pid}, 0, 100000)
	if os.Getenv("HUATUO_TEST_JAVA_EXPECT_UNSUPPORTED") == "1" {
		if err == nil {
			t.Fatalf("unsupported Java collector returned snapshot: %+v", snapshot)
		}
		if !strings.Contains(err.Error(), "only HotSpot G1 is supported") {
			t.Fatalf("unsupported Java collector error=%q", err)
		}
		if elapsed := time.Since(started); elapsed > gateDuration {
			t.Fatalf("unsupported Java collector exceeded bounded return budget: %s", elapsed)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if err := snapshot.FinalizeLocal(); err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s elapsed=%s complete=%t estimated=%t regions=%d/%d objects=%d reason=%q",
		snapshot.RuntimeVersion, elapsed, snapshot.Complete, snapshot.Estimated,
		snapshot.ScannedRegions, snapshot.TotalRegions, len(snapshot.Objects),
		snapshot.PartialReason)
	if elapsed > gateDuration {
		t.Fatalf("Java capture exceeded bounded return budget: %s", elapsed)
	}
	objectsBySuffix := func(suffix string) *memsnap.ObjectAggregate {
		for index := range snapshot.Objects {
			if strings.HasSuffix(snapshot.Objects[index].TypeName, suffix) {
				return &snapshot.Objects[index]
			}
		}
		return nil
	}
	if snapshot.RuntimeVersion == "" || snapshot.ScannedRegions == 0 ||
		len(snapshot.Objects) == 0 {
		t.Fatalf("incomplete versioned Java snapshot: %+v", snapshot)
	}
	expectedClasses := []struct {
		suffix string
		env    string
	}{
		{"HuatuoSnapshotFixture$SmallPayload", "HUATUO_FIXTURE_SMALL_OBJECTS"},
	}
	if os.Getenv("HUATUO_FIXTURE_MODE") == "mixed" {
		expectedClasses = []struct {
			suffix string
			env    string
		}{
			{"HuatuoSnapshotFixture$HotPayload", "HUATUO_FIXTURE_HOT_OBJECTS"},
			{"HuatuoSnapshotFixture$WarmPayload", "HUATUO_FIXTURE_WARM_OBJECTS"},
			{"HuatuoSnapshotFixture$ColdPayload", "HUATUO_FIXTURE_COLD_OBJECTS"},
		}
	}
	maxError := 0.40
	if value := os.Getenv("HUATUO_FIXTURE_MAX_ERROR"); value != "" {
		parsed, parseErr := strconv.ParseFloat(value, 64)
		if parseErr != nil || parsed < 0 {
			t.Fatalf("invalid HUATUO_FIXTURE_MAX_ERROR=%q", value)
		}
		maxError = parsed
	}
	recalled := 0
	for _, expectedClass := range expectedClasses {
		expectedText := os.Getenv(expectedClass.env)
		if expectedText == "" {
			continue
		}
		expected, parseErr := strconv.ParseUint(expectedText, 10, 64)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		probe := objectsBySuffix(expectedClass.suffix)
		if probe == nil || probe.Count == 0 {
			t.Errorf("Java mixed-object class %s was not sampled", expectedClass.suffix)
			continue
		}
		recalled++
		errorRatio := float64(absUint64Difference(probe.Count, expected)) /
			float64(expected)
		averageBytes := probe.AverageBytes
		if probe.SampledCount != 0 {
			averageBytes = float64(probe.SampledBytes) /
				float64(probe.SampledCount)
		}
		expectedBytes := uint64(math.Round(float64(expected) * averageBytes))
		byteErrorRatio := float64(absUint64Difference(probe.ShallowBytes,
			expectedBytes)) / float64(expectedBytes)
		t.Logf("class=%s count=%d sampled_count=%d expected=%d count_error=%.4f bytes=%d expected_bytes=%d byte_error=%.4f",
			expectedClass.suffix, probe.Count, probe.SampledCount, expected, errorRatio,
			probe.ShallowBytes, expectedBytes, byteErrorRatio)
		if errorRatio > maxError {
			t.Errorf("Java %s estimate error %.3f exceeds %.0f%%",
				expectedClass.suffix, errorRatio, maxError*100)
		}
		if byteErrorRatio > maxError {
			t.Errorf("Java %s byte estimate error %.3f exceeds %.0f%%",
				expectedClass.suffix, byteErrorRatio, maxError*100)
		}
	}
	if len(expectedClasses) != 0 && float64(recalled)/float64(len(expectedClasses)) < 0.90 {
		t.Errorf("Java expected Top-K recall=%d/%d is below 90%%", recalled,
			len(expectedClasses))
	}
}

func absUint64Difference(left, right uint64) uint64 {
	if left > right {
		return left - right
	}
	return right - left
}

func TestLoadHotSpotMetadataFromLiveProcess(t *testing.T) {
	pidText := os.Getenv("HUATUO_JAVA_TEST_PID")
	if pidText == "" {
		t.Skip("HUATUO_JAVA_TEST_PID is unset")
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := loadHotSpotMetadata("/proc", pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.structs) < 100 || len(metadata.types) < 100 ||
		len(metadata.constants) < 10 {
		t.Fatalf("structs=%d types=%d constants=%d long_constants=%d",
			len(metadata.structs), len(metadata.types), len(metadata.constants),
			len(metadata.longConsts))
	}
	for _, key := range []string{
		"Universe::_collectedHeap", "Klass::_name", "Klass::_layout_helper",
	} {
		if _, ok := metadata.structs[key]; !ok {
			t.Errorf("missing VMStruct %s", key)
		}
	}
	t.Logf("libjvm=%s structs=%d types=%d constants=%d long_constants=%d",
		metadata.image.path, len(metadata.structs), len(metadata.types),
		len(metadata.constants), len(metadata.longConsts))
	keys := make([]string, 0)
	for key := range metadata.structs {
		for _, prefix := range []string{
			"Universe::", "CompressedKlassPointers::", "CompressedOops::",
			"Abstract_VM_Version::", "VM_Version::",
			"G1CollectedHeap::",
			"G1HeapRegionManager::", "G1HeapRegionTable::", "HeapRegion::",
			"G1ContiguousSpace::", "Space::",
			"ContiguousSpace::", "CompactibleSpace::", "oopDesc::", "Klass::",
			"Symbol::", "InstanceKlass::", "ArrayKlass::", "ObjArrayKlass::",
			"TypeArrayKlass::",
			"java_lang_Class::", "InstanceMirrorKlass::",
			"ConstantPool::", "Array<int>::", "Array<u1>::", "Array<u2>::",
		} {
			if strings.HasPrefix(key, prefix) || strings.Contains(key, "Region") {
				keys = append(keys, key)
				break
			}
		}
	}
	typeKeys := make([]string, 0)
	for key := range metadata.types {
		if strings.Contains(key, "Region") || strings.Contains(key, "Space") ||
			key == "G1CollectedHeap" {
			typeKeys = append(typeKeys, key)
		}
	}
	sort.Strings(typeKeys)
	for _, key := range typeKeys {
		entry := metadata.types[key]
		t.Logf("type %s super=%s size=%d", key, entry.superclass, entry.size)
	}
	sort.Strings(keys)
	for _, key := range keys {
		field := metadata.structs[key]
		if testing.Verbose() {
			t.Logf("%s static=%t offset=%#x address=%#x type=%s", key,
				field.isStatic, field.offset, field.address, field.typeString)
		}
	}
	constantKeys := make([]string, 0)
	for key := range metadata.constants {
		if strings.HasPrefix(key, "Klass::_lh_") || strings.Contains(key, "HeapWord") ||
			strings.HasPrefix(key, "G1HeapRegionType::") {
			constantKeys = append(constantKeys, key)
		}
	}
	sort.Strings(constantKeys)
	for _, key := range constantKeys {
		t.Logf("constant %s=%d", key, metadata.constants[key])
	}
}

func TestExternalReaderAgainstLiveG1Process(t *testing.T) {
	pidText := os.Getenv("HUATUO_JAVA_TEST_PID")
	if pidText == "" {
		t.Skip("HUATUO_JAVA_TEST_PID is unset")
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	snapshot, err := NewExternalReader("/proc").Capture(ctx,
		memsnap.ProcessIdentity{TGID: pid}, 0, 256)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.FinalizeLocal(); err != nil {
		t.Fatal(err)
	}
	for _, object := range snapshot.Objects {
		if strings.Contains(object.TypeName, "HotSpotProbe") ||
			object.TypeName == "byte[]" {
			t.Logf("object=%s count=%d bytes=%d sampled_count=%d sampled_bytes=%d estimated=%t rse=%.4f interval=[%d,%d] confidence=%q average=%.1f fields=%+v",
				object.TypeName, object.Count, object.ShallowBytes,
				object.SampledCount, object.SampledBytes, object.Estimated,
				object.EstimateRSE, object.EstimateLowerBytes,
				object.EstimateUpperBytes, object.EstimateConfidence,
				object.AverageBytes, object.Fields)
		}
	}
	rawCoverage := float64(0)
	if snapshot.HeapUsedBytes != 0 {
		rawCoverage = float64(snapshot.ScannedBytes) / float64(snapshot.HeapUsedBytes)
	}
	t.Logf("runtime=%q elapsed=%s complete=%t estimated=%t method=%q seed=%d reason=%q regions=%d/%d planned=%d raw_bytes=%d heap_used=%d raw_coverage=%.4f classified_bytes=%d objects=%d strata=%+v",
		snapshot.RuntimeVersion, elapsed, snapshot.Complete, snapshot.Estimated,
		snapshot.EstimationMethod, snapshot.SamplingSeed, snapshot.PartialReason,
		snapshot.ScannedRegions, snapshot.TotalRegions, snapshot.PlannedRegions,
		snapshot.ScannedBytes, snapshot.HeapUsedBytes,
		rawCoverage, snapshot.ClassifiedBytes, len(snapshot.Objects),
		snapshot.SamplingStrata)
}

func TestExternalScanDeadlineReservesResultAndAckTime(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	got, ok := memsnap.OOMSnapshotDeadlineWithReserve(ctx, hotspotResultReserve)
	if !ok {
		t.Fatal("external scan deadline is disabled")
	}
	if want := deadline.Add(-hotspotResultReserve); !got.Equal(want) {
		t.Fatalf("external scan deadline=%v, want %v", got, want)
	}
	if reserve := deadline.Sub(got); reserve != hotspotResultReserve {
		t.Fatalf("result and ACK reserve=%v, want %v", reserve,
			hotspotResultReserve)
	}
}

func TestScheduleG1RegionsInterleavesStrataAndKeepsHumongousUnit(t *testing.T) {
	metadata := &hotspotMetadata{constants: map[string]int64{
		"G1HeapRegionType::FreeTag":               0,
		"G1HeapRegionType::EdenTag":               2,
		"G1HeapRegionType::SurvTag":               3,
		"G1HeapRegionType::StartsHumongousTag":    4,
		"G1HeapRegionType::ContinuesHumongousTag": 5,
		"G1HeapRegionType::YoungMask":             2,
		"G1HeapRegionType::HumongousMask":         4,
		"G1HeapRegionType::OldMask":               8,
	}}
	regions := []g1Region{
		{bottom: 0x1000, top: 0x2000, tag: 2, tagged: true},
		{bottom: 0x2000, top: 0x3000, tag: 8, tagged: true},
		{bottom: 0x3000, top: 0x4000, tag: 4, tagged: true},
		{bottom: 0x4000, top: 0x5000, tag: 5, tagged: true},
		{bottom: 0x5000, top: 0x6000, tag: 2, tagged: true},
	}

	got := scheduleG1Regions(regions, metadata)
	if len(got) != len(regions) {
		t.Fatalf("scheduled regions=%d, want %d", len(got), len(regions))
	}
	humongousStart := -1
	for index, region := range got {
		if region.tag == 4 {
			humongousStart = index
			break
		}
	}
	if humongousStart < 0 || humongousStart+1 >= len(got) ||
		got[humongousStart+1].tag != 5 ||
		got[humongousStart].scanGroup != got[humongousStart+1].scanGroup {
		t.Fatalf("humongous unit was split: %+v", got)
	}
	if got[0].tag != 4 || got[1].tag != 5 {
		t.Fatalf("first scheduling unit tags=%v, want humongous [4 5]",
			[]uint32{got[0].tag, got[1].tag, got[2].tag})
	}
}

func TestPlanG1RegionSampleIsStratifiedAndDeterministic(t *testing.T) {
	metadata := g1SamplingTestMetadata()
	const capacity = uint64(1 << 20)
	regions := make([]g1Region, 0, 512)
	for index := 0; index < 512; index++ {
		tag := uint32(8)
		if index%3 == 0 {
			tag = 2
		}
		used := capacity * uint64(index%4+1) / 4
		bottom := uint64(0x10000000) + uint64(index)*capacity
		regions = append(regions, g1Region{
			bottom: bottom, top: bottom + used, tag: tag, tagged: true,
		})
	}
	first := planG1RegionSample(regions, metadata)
	second := planG1RegionSample(regions, metadata)
	if !first.estimated {
		t.Fatal("large heap plan must use estimation")
	}
	firstRegions := flattenG1SamplingPlan(first)
	secondRegions := flattenG1SamplingPlan(second)
	if len(firstRegions) >= len(regions) || len(firstRegions) != len(secondRegions) {
		t.Fatalf("sampled regions=%d/%d second=%d", len(firstRegions), len(regions),
			len(secondRegions))
	}
	var sampledBytes uint64
	for index := range firstRegions {
		sampledBytes += firstRegions[index].top - firstRegions[index].bottom
		if firstRegions[index].bottom != secondRegions[index].bottom {
			t.Fatalf("sampling is not deterministic at index %d", index)
		}
	}
	if sampledBytes < hotspotMinimumSampleBytes ||
		sampledBytes > hotspotMaximumSampleBytes+capacity*12 {
		t.Fatalf("sampled bytes=%d outside target range", sampledBytes)
	}
	for key, stratum := range first.strata {
		if key == g1HumongousStratum || stratum.totalRegions == 0 {
			continue
		}
		if stratum.plannedRegions < 2 {
			t.Fatalf("stratum %s planned=%d, want at least 2", stratum.name,
				stratum.plannedRegions)
		}
	}
}

func TestPlanG1RegionSampleKeepsHumongousExact(t *testing.T) {
	metadata := g1SamplingTestMetadata()
	regions := []g1Region{
		{bottom: 0x100000, top: 0x180000, tag: 2, tagged: true},
		{bottom: 0x200000, top: 0x300000, tag: 4, tagged: true},
		{bottom: 0x300000, top: 0x400000, tag: 5, tagged: true},
	}
	plan := planG1RegionSample(regions, metadata)
	stratum := plan.strata[g1HumongousStratum]
	if stratum == nil || stratum.totalRegions != 2 || stratum.plannedRegions != 2 {
		t.Fatalf("humongous stratum=%+v, want exact two regions", stratum)
	}
	ordered := flattenG1SamplingPlan(plan)
	if len(ordered) < 2 || ordered[0].tag != 4 || ordered[1].tag != 5 {
		t.Fatalf("humongous unit is not first: %+v", ordered)
	}
	for index := range ordered {
		if ordered[index].tag == 4 &&
			(index+1 >= len(ordered) || ordered[index+1].tag != 5) {
			t.Fatalf("humongous continuation was split: %+v", ordered)
		}
	}
}

func TestPlanG1RegionPrefixSampleCoversMoreRegionsWithinByteBudget(t *testing.T) {
	metadata := g1SamplingTestMetadata()
	const capacity = uint64(1 << 20)
	regions := make([]g1Region, 0, 512)
	for index := 0; index < 512; index++ {
		bottom := uint64(0x10000000) + uint64(index)*capacity
		regions = append(regions, g1Region{
			bottom: bottom, top: bottom + capacity, tag: 8, tagged: true,
		})
	}
	full := planG1RegionSample(regions, metadata)
	prefix := planG1RegionSampleWithPrefix(regions, metadata,
		hotspotShortRegionPrefixBytes)
	if len(prefix.units) <= len(full.units) {
		t.Fatalf("prefix units=%d, full units=%d", len(prefix.units), len(full.units))
	}
	var sampledBytes uint64
	for _, unit := range prefix.units {
		sampledBytes = saturatedAdd(sampledBytes, g1UnitSampleBytes(unit))
		for _, region := range unit.regions {
			if !region.humongous && region.sampleBytes !=
				hotspotShortRegionPrefixBytes {
				t.Fatalf("region sample bytes=%d", region.sampleBytes)
			}
		}
	}
	wantMinimum := uint64(hotspotMinimumSampleBytes)
	if available := uint64(len(regions)) * hotspotShortRegionPrefixBytes; available < wantMinimum {
		wantMinimum = available
	}
	if sampledBytes < wantMinimum ||
		sampledBytes > hotspotMaximumSampleBytes+hotspotShortRegionPrefixBytes*12 {
		t.Fatalf("prefix sampled bytes=%d outside target", sampledBytes)
	}
	if !prefix.estimated {
		t.Fatal("prefix plan must be estimated")
	}
}

func TestG1ShortWindowPrefixUsesAvailableReadBudget(t *testing.T) {
	const (
		capacity = uint64(1 << 20)
		regions  = 1024
	)
	heap := make([]g1Region, 0, regions)
	for index := 0; index < regions; index++ {
		bottom := uint64(0x10000000) + uint64(index)*capacity
		heap = append(heap, g1Region{bottom: bottom, top: bottom + capacity})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	prefix := g1ShortWindowPrefixBytes(ctx, heap, capacity*regions)
	want := uint64(hotspotShortMaximumSampleBytes / regions)
	if prefix != want {
		t.Fatalf("short-window prefix=%d, want %d", prefix, want)
	}
	if total := prefix * regions; total > hotspotShortMaximumSampleBytes {
		t.Fatalf("short-window sample=%d exceeds cap", total)
	}
}

func TestScanKnownHotSpotWindowCountsObjectWhoseBodyCrossesWindow(t *testing.T) {
	const (
		klassAddress = uint64(0x2000)
		klassBase    = uint64(0x1000)
	)
	raw := make([]byte, 512)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(klassAddress-klassBase))
	klass := &hotspotClass{name: "service/LargePayload", layoutHelper: 128 << 10}
	classes := map[uint64]*hotspotClass{klassAddress: klass}
	observations := make(map[uint64]g1RegionClassObservation)
	metadata := &hotspotMetadata{constants: map[string]int64{
		"ObjectAlignmentInBytes": objectAlignment,
	}}
	objects := scanKnownHotSpotWindow(processMemory{}, raw, 0x4000, classes,
		hotspotPointerEncoding{compressedKlass: true, klassBase: klassBase},
		metadata, 0, observations, &referenceSamplingState{}, nil)
	if objects != 1 {
		t.Fatalf("objects=%d, want 1", objects)
	}
	observation := observations[klassAddress]
	if observation.count != 1 || observation.bytes != 128<<10 {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestPlanG1RegionSampleUsesRemainingShortGateBudget(t *testing.T) {
	metadata := g1SamplingTestMetadata()
	const capacity = uint64(1 << 20)
	regions := make([]g1Region, 0, 128)
	for index := 0; index < 128; index++ {
		bottom := uint64(0x10000000) + uint64(index)*capacity
		regions = append(regions, g1Region{
			bottom: bottom, top: bottom + capacity, tag: 8, tagged: true,
		})
	}
	fixed := planG1RegionSample(regions, metadata)
	exhaustive := planG1RegionSampleForBudget(regions, metadata, 0, true)
	if len(exhaustive.units) != len(regions) {
		t.Fatalf("budget plan units=%d, want %d", len(exhaustive.units), len(regions))
	}
	if len(fixed.units) >= len(exhaustive.units) {
		t.Fatalf("fixed units=%d, budget units=%d", len(fixed.units),
			len(exhaustive.units))
	}
	for index := range fixed.units {
		if fixed.units[index].regions[0].bottom !=
			exhaustive.units[index].regions[0].bottom {
			t.Fatalf("fixed sampling prefix changed at unit %d", index)
		}
	}
	if exhaustive.estimated {
		t.Fatal("a completed full-region budget plan must remain exact")
	}
}

func TestFinishesG1RegionAfterHumongousHeader(t *testing.T) {
	const capacity = uint64(1 << 20)
	region := g1Region{
		bottom: 0x100000, top: 0x200000, capacity: capacity, humongous: true,
	}
	if !finishesG1RegionAfterObject(region, region.bottom, 768<<10) {
		t.Fatal("explicit humongous region must finish after its first object header")
	}
	region.humongous = false
	if !finishesG1RegionAfterObject(region, region.bottom, 768<<10) {
		t.Fatal("fallback scan must recognize a greater-than-half-region object")
	}
	if finishesG1RegionAfterObject(region, region.bottom, 256<<10) {
		t.Fatal("ordinary object must not skip the remaining region")
	}
	if finishesG1RegionAfterObject(region, region.bottom+8, 768<<10) {
		t.Fatal("only an object starting at the region bottom can finish the region")
	}
}

func TestEstimateG1AggregatesPreservesObservedTotals(t *testing.T) {
	const classAddress = uint64(0xabc)
	aggregates := map[uint64]*memsnap.ObjectAggregate{
		classAddress: {Count: 10, ShallowBytes: 100},
	}
	plan := g1SamplingPlan{estimated: true, strata: map[int]*g1SamplingStratum{
		0: {
			name: "young_0_25", totalRegions: 4, completedRegions: 2,
			totalUsedBytes: 400,
		},
	}}
	statistics := make(g1OnlineStatistics)
	statistics.observe(0, 100, map[uint64]g1RegionClassObservation{
		classAddress: {count: 4, bytes: 40},
	})
	statistics.observe(0, 100, map[uint64]g1RegionClassObservation{
		classAddress: {count: 6, bytes: 60},
	})
	estimateG1Aggregates(aggregates, statistics, plan)
	got := aggregates[classAddress]
	if got.SampledBytes != 100 || got.SampledCount != 10 ||
		got.ShallowBytes != 200 || got.Count != 20 || !got.Estimated {
		t.Fatalf("aggregate=%+v", got)
	}
	if got.EstimateConfidence == "" || got.SampledRegions != 2 {
		t.Fatalf("confidence=%q sampled_regions=%d", got.EstimateConfidence,
			got.SampledRegions)
	}
}

func TestG1OnlineVarianceMatchesRegionFormula(t *testing.T) {
	const classAddress = uint64(0xabc)
	statistics := make(g1OnlineStatistics)
	samples := []struct {
		used  uint64
		bytes uint64
	}{
		{used: 80, bytes: 20},
		{used: 100, bytes: 0},
		{used: 120, bytes: 70},
	}
	for _, sample := range samples {
		classes := make(map[uint64]g1RegionClassObservation)
		if sample.bytes != 0 {
			classes[classAddress] = g1RegionClassObservation{count: 1, bytes: sample.bytes}
		}
		statistics.observe(0, sample.used, classes)
	}
	stratum := statistics[0]
	got := g1RatioEstimateVariance(stratum, stratum.classes[classAddress], 10, 1000)
	ratio := float64(90) / float64(300)
	residualSquares := float64(0)
	for _, sample := range samples {
		residual := float64(sample.bytes) - ratio*float64(sample.used)
		residualSquares += residual * residual
	}
	n := float64(len(samples))
	want := 10 * 10 * (1 - n/10) * (residualSquares / (n - 1)) / n
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("variance=%f, want %f", got, want)
	}
}

func g1SamplingTestMetadata() *hotspotMetadata {
	return &hotspotMetadata{constants: map[string]int64{
		"G1HeapRegionType::FreeTag":               0,
		"G1HeapRegionType::EdenTag":               2,
		"G1HeapRegionType::SurvTag":               3,
		"G1HeapRegionType::StartsHumongousTag":    4,
		"G1HeapRegionType::ContinuesHumongousTag": 5,
		"G1HeapRegionType::YoungMask":             2,
		"G1HeapRegionType::HumongousMask":         4,
		"G1HeapRegionType::OldMask":               8,
	}}
}

func TestUnsigned5Reader(t *testing.T) {
	// Values below 191 use one byte; larger values use the modified base-64
	// continuation format used by HotSpot FieldInfoStream.
	reader := unsigned5Reader{data: []byte{1, 191, 192, 1, 255, 1}}
	wants := []uint32{0, 190, 191, 254}
	for index, want := range wants {
		got, err := reader.next()
		if err != nil || got != want {
			t.Fatalf("value[%d]=%d, want %d, err=%v", index, got, want, err)
		}
	}
}

func TestReadJavaRuntimeVersion(t *testing.T) {
	root := t.TempDir()
	releaseDir := filepath.Join(root, "123", "root", "opt", "jdk")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "release"),
		[]byte("IMPLEMENTOR=\"OpenJDK\"\nJAVA_VERSION=\"17.0.19\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readJavaRuntimeVersion(root, 123, "/opt/jdk/lib/server/libjvm.so")
	if got != "17.0.19" {
		t.Fatalf("runtime version=%q, want 17.0.19", got)
	}
}

func TestFirstVMStructAliases(t *testing.T) {
	metadata := &hotspotMetadata{structs: map[string]vmStruct{
		"old": {typeString: "address", offset: 8},
	}}
	got := firstVMStruct(metadata, "new", "old")
	if got.offset != 8 {
		t.Fatalf("offset=%d, want 8", got.offset)
	}
}

func TestInheritedVMStruct(t *testing.T) {
	metadata := &hotspotMetadata{
		structs: map[string]vmStruct{
			"Base::_field": {typeString: "address", offset: 16},
		},
		types: map[string]vmType{
			"Derived": {superclass: "Base"},
		},
	}
	got := inheritedVMStruct(metadata, "Derived", "_field")
	if got.offset != 16 {
		t.Fatalf("offset=%d, want 16", got.offset)
	}
}

func TestRuntimeVersionUnavailable(t *testing.T) {
	metadata := &hotspotMetadata{structs: map[string]vmStruct{}}
	if got := metadata.runtimeVersion(processMemory{}); got != "" {
		t.Fatalf("runtime version=%q, want empty", got)
	}
}
