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
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

func TestExternalReaderAgainstRealLegacyCPython(t *testing.T) {
	if os.Getenv("HUATUO_TEST_PYTHON_EXTERNAL") != "1" {
		t.Skip("set HUATUO_TEST_PYTHON_EXTERNAL=1 to run the process-memory test")
	}
	pythonName := os.Getenv("HUATUO_TEST_PYTHON_BINARY")
	if pythonName == "" {
		pythonName = "python3"
	}
	python, err := exec.LookPath(pythonName)
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	command := exec.Command(python, "-c", legacyCPythonFixture)
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
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatalf("Python fixture did not become ready")
	}
	gateMilliseconds := fixtureCount("HUATUO_TEST_GATE_MILLISECONDS", 500)
	deadline := time.Now().Add(time.Duration(gateMilliseconds) * time.Millisecond)
	captureStarted := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	response, err := (RuntimeExecutor{ProcRoot: "/proc"}).Execute(
		ctx, memsnap.Request{
			Identity:       memsnap.ProcessIdentity{TGID: command.Process.Pid},
			GateDeadline:   deadline,
			MaxObjects:     200000,
			MaxOutputBytes: 8 << 20,
		})
	if err != nil {
		t.Fatal(err)
	}
	captureElapsed := time.Since(captureStarted)
	if response.FinalizeLocal != nil {
		if err := response.FinalizeLocal(); err != nil {
			t.Fatal(err)
		}
		response.FinalizeLocal = nil
	}
	t.Logf("version=%s status=%s truncated=%v reasons=%v objects=%d",
		response.RuntimeVersion, response.Status, response.Truncated,
		response.TruncationReasons, len(response.Objects))
	t.Logf("capture elapsed=%s", captureElapsed)
	t.Logf("coverage consistency=%s estimated=%v method=%s raw=%.4f scanned=%d total=%d strata=%d",
		response.Coverage.Consistency, response.Coverage.Estimated,
		response.Coverage.EstimationMethod, response.Coverage.RawCoverage,
		response.Coverage.ScannedBytes, response.Coverage.HeapUsedBytes,
		len(response.Coverage.SamplingStrata))
	if captureElapsed > time.Duration(gateMilliseconds)*time.Millisecond {
		t.Fatalf("Python capture exceeded bounded return budget: %s", captureElapsed)
	}
	allowPartial := os.Getenv("HUATUO_FIXTURE_ALLOW_PARTIAL") == "1"
	for index, object := range response.Objects {
		if index >= 20 {
			break
		}
		t.Logf("object[%d]=%s count=%d bytes=%d fields=%d", index,
			object.TypeName, object.Count, object.ShallowBytes, len(object.Fields))
	}
	if os.Getenv("HUATUO_FIXTURE_MODE") == "mixed" {
		assertMixedPythonSample(t, response)
		return
	}
	if strings.HasPrefix(response.Coverage.Consistency, "cpython_pymalloc_") {
		if response.Coverage.ObjectType == "allocator_size_class" {
			if len(response.Objects) == 0 ||
				!strings.HasPrefix(response.Objects[0].TypeName, "pymalloc.size_") {
				t.Fatalf("invalid bounded pymalloc snapshot: %+v", response)
			}
			return
		}
		for _, expected := range []struct {
			name string
			want uint64
		}{
			{"__main__.CheckoutPayload", fixtureCount("HUATUO_FIXTURE_CHECKOUT", 2048)},
			{"__main__.CacheEntry", fixtureCount("HUATUO_FIXTURE_CACHE", 4096)},
			{"__main__.ImagePayload", fixtureCount("HUATUO_FIXTURE_IMAGE", 1024)},
		} {
			object := findObject(response.Objects, expected.name)
			if object == nil || object.SampledCount == 0 {
				t.Fatalf("sampled object %s=%+v", expected.name, object)
			}
			errorRatio := float64(absDifference(object.Count, expected.want)) /
				float64(expected.want)
			if errorRatio > 0.25 {
				t.Fatalf("sampled object %s count=%d want=%d error=%.3f",
					expected.name, object.Count, expected.want, errorRatio)
			}
		}
		return
	}
	if response.Coverage.Consistency == "cpython_external_gc_bounded_sample" {
		if len(response.Objects) == 0 || !response.Truncated {
			t.Fatalf("invalid bounded external GC snapshot: %+v", response)
		}
		return
	}
	for _, expected := range []struct {
		typeName  string
		field     string
		fullCount uint64
		itemBytes uint64
	}{
		{"__main__.CheckoutPayload", "data", fixtureCount("HUATUO_FIXTURE_CHECKOUT", 2048), 32768},
		{"__main__.CacheEntry", "value", fixtureCount("HUATUO_FIXTURE_CACHE", 4096), 4096},
		{"__main__.ImagePayload", "pixels", fixtureCount("HUATUO_FIXTURE_IMAGE", 1024), 16384},
	} {
		minimumCount := expected.fullCount * 2 / 5
		if allowPartial {
			minimumCount = 1
		}
		minimumBytes := minimumCount * expected.itemBytes
		object := findObject(response.Objects, expected.typeName)
		if object == nil || object.Count == 0 ||
			(!allowPartial && object.Count < expected.fullCount*9/10) {
			t.Fatalf("object %s=%+v", expected.typeName, object)
		}
		// CPython 3.13 moved managed dictionary internals. The external GC
		// census supports object type/count on 3.13, while field shapes remain
		// best-effort and are covered strictly through 3.12.
		if strings.HasPrefix(response.RuntimeVersion, "3.13.") {
			continue
		}
		field := findField(object.Fields, expected.field)
		if field == nil || field.ReferenceCount < minimumCount ||
			field.ReferencedShallowBytes < minimumBytes {
			t.Fatalf("field %s.%s=%+v", expected.typeName, expected.field, field)
		}
		t.Logf("field %s.%s references=%d unique=%d bytes=%d", expected.typeName,
			expected.field, field.ReferenceCount, field.UniqueReferencedObjects,
			field.ReferencedShallowBytes)
	}
}

func assertMixedPythonSample(t *testing.T, response *CaptureResponse) {
	t.Helper()
	expected := []struct {
		name  string
		count uint64
	}{
		{"__main__.HotPayload", fixtureCount("HUATUO_FIXTURE_PY_HOT", 30000)},
		{"__main__.WarmPayload", fixtureCount("HUATUO_FIXTURE_PY_WARM", 9000)},
		{"__main__.ColdPayload", fixtureCount("HUATUO_FIXTURE_PY_COLD", 3000)},
	}
	var observedTotal, expectedTotal uint64
	for _, item := range expected {
		expectedTotal += item.count
		if object := findObject(response.Objects, item.name); object != nil {
			observedTotal += object.Count
		}
	}
	if observedTotal == 0 {
		if response.Coverage.ObjectType == "allocator_size_class" {
			if len(response.Objects) == 0 ||
				!strings.HasPrefix(response.Objects[0].TypeName, "pymalloc.size_") {
				t.Fatalf("invalid bounded mixed pymalloc snapshot: %+v", response)
			}
			t.Log("mixed same-size types are intentionally reported as allocator size classes")
			return
		}
		t.Fatalf("mixed Python types are absent: consistency=%s objects=%+v",
			response.Coverage.Consistency, response.Objects)
	}
	for _, item := range expected {
		object := findObject(response.Objects, item.name)
		if object == nil || object.Count == 0 {
			t.Fatalf("mixed Python type %s was missed", item.name)
		}
		if response.Coverage.Estimated {
			errorRatio := float64(absDifference(object.Count, item.count)) /
				float64(item.count)
			if errorRatio > 0.20 {
				t.Fatalf("mixed Python type %s count=%d want=%d error=%.3f",
					item.name, object.Count, item.count, errorRatio)
			}
		}
		wantShare := float64(item.count) / float64(expectedTotal)
		gotShare := float64(object.Count) / float64(observedTotal)
		if response.Coverage.Estimated {
			if difference := gotShare - wantShare; difference > 0.10 || difference < -0.10 {
				t.Fatalf("mixed Python type %s share=%.3f want=%.3f count=%d total=%d",
					item.name, gotShare, wantShare, object.Count, observedTotal)
			}
		}
		t.Logf("mixed type %s count=%d share=%.3f want_share=%.3f",
			item.name, object.Count, gotShare, wantShare)
	}
}

func fixtureCount(name string, fallback uint64) uint64 {
	value, err := strconv.ParseUint(os.Getenv(name), 10, 64)
	if err != nil || value == 0 {
		return fallback
	}
	return value
}

func absDifference(left, right uint64) uint64 {
	if left > right {
		return left - right
	}
	return right - left
}

func findObject(objects []memsnap.ObjectAggregate,
	name string,
) *memsnap.ObjectAggregate {
	for index := range objects {
		if objects[index].TypeName == name {
			return &objects[index]
		}
	}
	return nil
}

func findField(fields []memsnap.FieldShape, name string) *memsnap.FieldShape {
	for index := range fields {
		if fields[index].Name == name {
			return &fields[index]
		}
	}
	return nil
}

const legacyCPythonFixture = `
import gc,os,threading,time
class CheckoutPayload:
 def __init__(self): self.data=bytearray(32768);self.kind='checkout'
class CacheEntry:
 def __init__(self): self.value=bytearray(4096);self.key='cache'
class ImagePayload:
 def __init__(self): self.pixels=bytearray(16384);self.format='rgb'
parts=[]
if os.getenv('HUATUO_FIXTURE_MODE') == 'mixed':
 class HotPayload:
  __slots__=('left','right')
  def __init__(self,value):self.left=value;self.right=value+1
 class WarmPayload:
  __slots__=('left','right')
  def __init__(self,value):self.left=value;self.right=value+1
 class ColdPayload:
  __slots__=('left','right')
  def __init__(self,value):self.left=value;self.right=value+1
 mixed=[]
 def build_mixed(cls,count):mixed.append([cls(index) for index in range(count)])
 specs=((HotPayload,int(os.getenv('HUATUO_FIXTURE_PY_HOT','30000'))),(WarmPayload,int(os.getenv('HUATUO_FIXTURE_PY_WARM','9000'))),(ColdPayload,int(os.getenv('HUATUO_FIXTURE_PY_COLD','3000'))))
 gc.disable()
 for index,spec in enumerate(specs):
  thread=threading.Thread(target=build_mixed,args=spec);thread.start();thread.join()
  if index == 0:gc.collect(2)
  if index == 1:gc.collect(0)
 print('READY',flush=True)
 while True:
  sum(range(100));time.sleep(.001)
def build(kind,count):
 cls=(CheckoutPayload,CacheEntry,ImagePayload)[kind]
 items=[cls() for _ in range(count)]
 for item in items[::2]:vars(item)
 parts.append(items)
counts=(int(os.getenv('HUATUO_FIXTURE_CHECKOUT','2048')),int(os.getenv('HUATUO_FIXTURE_CACHE','4096')),int(os.getenv('HUATUO_FIXTURE_IMAGE','1024')))
threads=[threading.Thread(target=build,args=item) for item in ((0,counts[0]),(1,counts[1]),(2,counts[2]))]
for thread in threads:thread.start()
for thread in threads:thread.join()
print('READY',flush=True)
while True:
 sum(range(100));time.sleep(.001)
`
