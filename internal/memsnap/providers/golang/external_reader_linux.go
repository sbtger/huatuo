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

package golang

import (
	"container/heap"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/goheap"
	"huatuo-bamai/internal/memsnap"
)

const (
	bucketHeaderBytes = 6 * 8
	memRecordBytes    = 4 * 4 * 8
	maxVisitedBuckets = 262144
	// Keep the hard gate deadline for copying the best stacks and returning the
	// bounded result. A scan that consumes the whole context cannot produce a
	// useful two-phase snapshot.
	scanFinishReserve  = 5 * time.Millisecond
	resultBuildReserve = 2 * time.Millisecond
)

type ExternalReader struct {
	procRoot   string
	discoverer *goheap.ProcDiscoverer
}

func NewExternalReader(procRoot string) *ExternalReader {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &ExternalReader{
		procRoot:   procRoot,
		discoverer: goheap.NewProcDiscoverer(procRoot),
	}
}

func (r *ExternalReader) Capture(ctx context.Context,
	identity memsnap.ProcessIdentity, accessTID, maxStacks, maxDepth int,
) (*RawSnapshot, error) {
	readTID := accessTID
	if readTID <= 0 {
		// The leader's TID equals its TGID, so it can stand in as the access
		// thread when no gate thread was frozen.
		readTID = identity.TGID
	}
	if maxStacks <= 0 || maxDepth <= 0 || maxDepth > goheap.MaxStackDepth {
		return nil, errors.New("Go mbucket limits are invalid")
	}
	target, err := r.discoverer.DiscoverPIDWithAccess(ctx, identity.TGID, readTID)
	if err != nil {
		return nil, err
	}
	if target.StartTimeTicks != identity.StartTimeTicks {
		return nil, errors.New("Go victim identity changed during address discovery")
	}
	if _, err := goheap.LayoutForVersion(target.GoVersion); err != nil {
		return nil, err
	}
	byteOrder, err := r.targetByteOrder(readTID)
	if err != nil {
		return nil, err
	}
	symbolizer, err := goheap.NewELFSymbolizer(r.procPath(readTID, "exe"),
		target.LoadBias)
	if err != nil {
		return nil, err
	}
	snapshot := &RawSnapshot{RuntimeVersion: target.GoVersion}
	scanDeadline, hasScanDeadline := memsnap.OOMSnapshotDeadlineWithReserve(
		ctx, scanFinishReserve)
	stackDeadline, hasStackDeadline := memsnap.OOMSnapshotDeadlineWithReserve(
		ctx, resultBuildReserve)
	if rateAddress := target.MemProfileRateAddress(); rateAddress != 0 {
		rateRaw, readErr := readProcess(readTID, rateAddress, 8)
		if readErr == nil {
			snapshot.SampleRate = int64(byteOrder.Uint64(rateRaw))
			snapshot.RateKnown = true
		}
	}
	headRaw, err := readProcess(readTID, target.MBucketsAddress(), 8)
	if err != nil {
		return nil, fmt.Errorf("read runtime.mbuckets head: %w", err)
	}
	address := byteOrder.Uint64(headRaw)
	// Config validation only requires MaxStacks > 0; clamp it so a
	// misconfigured value cannot drive an unbounded upfront allocation. The
	// scan itself is independently bounded by maxVisitedBuckets below.
	if maxStacks > maxVisitedBuckets {
		maxStacks = maxVisitedBuckets
	}
	candidates := make(candidateHeap, 0, maxStacks)
	visitedLimit := maxStacks * 64
	if visitedLimit < 4096 {
		visitedLimit = 4096
	}
	if visitedLimit > maxVisitedBuckets {
		visitedLimit = maxVisitedBuckets
	}
	for address != 0 {
		if err := ctx.Err(); err != nil {
			snapshot.PartialReason = "deadline reached while scanning mbucket counters"
			break
		}
		if memsnap.OOMSnapshotDeadlineReached(scanDeadline, hasScanDeadline) {
			snapshot.PartialReason = "soft deadline reached; reserved time for copying Top-K stacks"
			break
		}
		if snapshot.VisitedBuckets >= visitedLimit {
			snapshot.PartialReason = fmt.Sprintf("mbucket safety limit %d reached",
				visitedLimit)
			break
		}
		header, readErr := readProcess(readTID, address, bucketHeaderBytes)
		if readErr != nil {
			if snapshot.VisitedBuckets == 0 {
				return nil, fmt.Errorf("read mbucket header %#x: %w", address, readErr)
			}
			snapshot.PartialReason = fmt.Sprintf("mbucket header read failed after %d buckets",
				snapshot.VisitedBuckets)
			break
		}
		snapshot.VisitedBuckets++
		next := byteOrder.Uint64(header[8:16])
		depth := byteOrder.Uint64(header[40:48])
		if depth > 0 {
			recordAddress := address + bucketHeaderBytes + depth*8
			recordRaw, recordErr := readProcess(readTID, recordAddress,
				memRecordBytes)
			if recordErr == nil {
				record := decodeMemRecord(recordRaw, byteOrder)
				objects, bytes := rawInUse(&record)
				if objects != 0 && bytes != 0 {
					// Deep stacks (Go 1.21+ profstackdepth) are truncated to
					// the configured depth rather than dropped wholesale.
					stackDepth := depth
					if stackDepth > uint64(maxDepth) {
						stackDepth = uint64(maxDepth)
					}
					pushTopCandidate(&candidates, maxStacks, bucketCandidate{
						address: address, depth: int(stackDepth),
						objects: objects, bytes: bytes,
					})
				}
			}
		}
		if next == address {
			snapshot.PartialReason = "mbucket chain contains a self-loop"
			break
		}
		address = next
	}
	if address == 0 {
		snapshot.Complete = true
	}
	selected := make([]bucketCandidate, len(candidates))
	copy(selected, candidates)
	sortCandidates(selected)
	snapshot.Allocations = make([]RawAllocation, 0, len(selected))
	for _, candidate := range selected {
		if err := ctx.Err(); err != nil {
			snapshot.Complete = false
			snapshot.PartialReason = "deadline reached while copying selected mbucket stacks"
			break
		}
		if memsnap.OOMSnapshotDeadlineReached(stackDeadline, hasStackDeadline) {
			snapshot.Complete = false
			snapshot.PartialReason = "result-build reserve reached while copying selected mbucket stacks"
			break
		}
		stackRaw, readErr := readProcess(readTID,
			candidate.address+bucketHeaderBytes, candidate.depth*8)
		if readErr != nil {
			snapshot.Complete = false
			snapshot.PartialReason = "selected mbucket stack became unreadable"
			continue
		}
		stack := make([]string, 0, candidate.depth)
		for offset := 0; offset < len(stackRaw); offset += 8 {
			pc := byteOrder.Uint64(stackRaw[offset : offset+8])
			if pc == 0 {
				break
			}
			name := symbolizer.Resolve(pc)
			if name == "" {
				name = fmt.Sprintf("0x%x", pc)
			}
			stack = append(stack, name)
		}
		if len(stack) != 0 {
			snapshot.Allocations = append(snapshot.Allocations, RawAllocation{
				Stack: stack, SampledBytes: candidate.bytes,
				SampledCount: candidate.objects,
			})
		}
	}
	return snapshot, nil
}

func (r *ExternalReader) procPath(pid int, name string) string {
	return filepath.Join(r.procRoot, strconv.Itoa(pid), name)
}

func (r *ExternalReader) targetByteOrder(pid int) (binary.ByteOrder, error) {
	file, err := elf.Open(r.procPath(pid, "exe"))
	if err != nil {
		return nil, fmt.Errorf("open Go victim ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("unsupported Go victim ELF class %s", file.Class)
	}
	return file.ByteOrder, nil
}

func readProcess(pid int, address uint64, size int) ([]byte, error) {
	if size <= 0 || address == 0 {
		return nil, errors.New("process memory read range is invalid")
	}
	data := make([]byte, size)
	local := []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}}
	remote := []unix.RemoteIovec{{Base: uintptr(address), Len: len(data)}}
	read, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	if read != len(data) {
		return nil, fmt.Errorf("short process memory read: got %d, want %d", read,
			len(data))
	}
	return data, nil
}

func decodeMemRecord(raw []byte, order binary.ByteOrder) goheap.MemRecord {
	cycles := make([]goheap.MemRecordCycle, 4)
	for index := range cycles {
		base := index * 32
		cycles[index] = goheap.MemRecordCycle{
			Allocs:     order.Uint64(raw[base : base+8]),
			Frees:      order.Uint64(raw[base+8 : base+16]),
			AllocBytes: order.Uint64(raw[base+16 : base+24]),
			FreeBytes:  order.Uint64(raw[base+24 : base+32]),
		}
	}
	return goheap.MemRecord{
		Active: cycles[0],
		Future: [3]goheap.MemRecordCycle{cycles[1], cycles[2], cycles[3]},
	}
}

func rawInUse(record *goheap.MemRecord) (uint64, uint64) {
	cycles := [4]goheap.MemRecordCycle{
		record.Active, record.Future[0],
		record.Future[1], record.Future[2],
	}
	var allocs, frees, allocBytes, freeBytes uint64
	for _, cycle := range cycles {
		allocs = saturatedUint64Add(allocs, cycle.Allocs)
		frees = saturatedUint64Add(frees, cycle.Frees)
		allocBytes = saturatedUint64Add(allocBytes, cycle.AllocBytes)
		freeBytes = saturatedUint64Add(freeBytes, cycle.FreeBytes)
	}
	return nonNegativeUint64Delta(allocs, frees),
		nonNegativeUint64Delta(allocBytes, freeBytes)
}

func saturatedUint64Add(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func nonNegativeUint64Delta(left, right uint64) uint64 {
	if right > left {
		return 0
	}
	return left - right
}

type bucketCandidate struct {
	address uint64
	depth   int
	objects uint64
	bytes   uint64
}

type candidateHeap []bucketCandidate

func (h candidateHeap) Len() int           { return len(h) }
func (h candidateHeap) Less(i, j int) bool { return h[i].bytes < h[j].bytes }
func (h candidateHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *candidateHeap) Push(value any)    { *h = append(*h, value.(bucketCandidate)) }
func (h *candidateHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func pushTopCandidate(candidates *candidateHeap, limit int,
	candidate bucketCandidate,
) {
	if candidates.Len() < limit {
		heap.Push(candidates, candidate)
		return
	}
	if candidate.bytes <= (*candidates)[0].bytes {
		return
	}
	(*candidates)[0] = candidate
	heap.Fix(candidates, 0)
}

func sortCandidates(candidates []bucketCandidate) {
	for index := len(candidates)/2 - 1; index >= 0; index-- {
		siftDownMax(candidates, index, len(candidates))
	}
	for end := len(candidates) - 1; end > 0; end-- {
		candidates[0], candidates[end] = candidates[end], candidates[0]
		siftDownMax(candidates, 0, end)
	}
}

func siftDownMax(values []bucketCandidate, root, length int) {
	for {
		child := root*2 + 1
		if child >= length {
			return
		}
		if child+1 < length && values[child].bytes < values[child+1].bytes {
			child++
		}
		if values[root].bytes >= values[child].bytes {
			return
		}
		values[root], values[child] = values[child], values[root]
		root = child
	}
}
