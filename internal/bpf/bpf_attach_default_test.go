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

package bpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestParseSectionSymbol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sectionName string
		want        string
		wantErr     bool
	}{
		{name: "valid section", sectionName: "kprobe/do_sys_open", want: "do_sys_open"},
		{name: "nested symbol", sectionName: "tracepoint/syscalls/sys_enter_open", want: "syscalls/sys_enter_open"},
		{name: "missing separator", sectionName: "kprobe", wantErr: true},
		{name: "empty symbol", sectionName: "kprobe/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseSectionSymbol(tt.sectionName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSectionSymbol(%q) error = %v, wantErr %t", tt.sectionName, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseSectionSymbol(%q) = %q, want %q", tt.sectionName, got, tt.want)
			}
		})
	}
}

func TestInternalTailCallProgram(t *testing.T) {
	t.Parallel()

	if !isInternalTailCallProgram(&loadedProgram{
		sectionPrefix: "kprobe",
		sectionName:   "kprobe/huatuo_tailcall_oom_snapshot_poll",
	}) {
		t.Fatal("Huatuo tail-call program would be attached as a real kprobe")
	}
	if isInternalTailCallProgram(&loadedProgram{
		sectionPrefix: "kprobe", sectionName: "kprobe/oom_kill_process",
	}) {
		t.Fatal("ordinary kprobe was classified as an internal tail call")
	}
	if isInternalTailCallProgram(&loadedProgram{
		sectionPrefix: "kprobe", sectionName: "kprobe/exit_mm_release",
	}) {
		t.Fatal("exit_mm_release gate kprobe was classified as an internal tail call")
	}
}

func TestParseKprobeAttachOptions(t *testing.T) {
	t.Parallel()

	program := &loadedProgram{}
	tests := []struct {
		name              string
		symbol            string
		isRetprobe        bool
		retprobeMaxActive int
		wantSymbol        string
		wantOffset        uint64
		wantIsRetprobe    bool
		wantMaxActive     int
		wantErr           bool
	}{
		{
			name:       "kprobe",
			symbol:     "do_sys_open",
			wantSymbol: "do_sys_open",
		},
		{
			name:       "kprobe with offset",
			symbol:     "do_sys_open+16",
			wantSymbol: "do_sys_open",
			wantOffset: 16,
		},
		{
			name:           "kretprobe default max active",
			symbol:         "do_sys_open",
			isRetprobe:     true,
			wantSymbol:     "do_sys_open",
			wantIsRetprobe: true,
		},
		{
			name:              "kretprobe custom max active",
			symbol:            "do_sys_open",
			isRetprobe:        true,
			retprobeMaxActive: 128,
			wantSymbol:        "do_sys_open",
			wantIsRetprobe:    true,
			wantMaxActive:     128,
		},
		{
			name:              "negative max active",
			symbol:            "do_sys_open",
			isRetprobe:        true,
			retprobeMaxActive: -1,
			wantErr:           true,
		},
		{
			name:              "max active on kprobe",
			symbol:            "do_sys_open",
			retprobeMaxActive: 128,
			wantErr:           true,
		},
		{name: "empty symbol", wantErr: true},
		{name: "empty base symbol", symbol: "+16", wantErr: true},
		{name: "empty offset", symbol: "do_sys_open+", wantErr: true},
		{name: "invalid offset", symbol: "do_sys_open+offset", wantErr: true},
		{name: "multiple offsets", symbol: "do_sys_open+8+16", wantErr: true},
		{name: "kretprobe with offset", symbol: "do_sys_open+16", isRetprobe: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseKprobeAttachOptions(
				program,
				tt.symbol,
				tt.isRetprobe,
				tt.retprobeMaxActive,
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseKprobeAttachOptions(%q) error = %v, wantErr %t", tt.symbol, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.program != program {
				t.Error("parseKprobeAttachOptions() did not preserve program")
			}
			if got.symbol != tt.wantSymbol {
				t.Errorf("symbol = %q, want %q", got.symbol, tt.wantSymbol)
			}
			if got.linkOptions.Offset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", got.linkOptions.Offset, tt.wantOffset)
			}
			if got.isRetprobe != tt.wantIsRetprobe {
				t.Errorf("isRetprobe = %t, want %t", got.isRetprobe, tt.wantIsRetprobe)
			}
			gotMaxActive := got.linkOptions.RetprobeMaxActive //nolint:staticcheck // Verify explicit deprecated opt-in propagation.
			if gotMaxActive != tt.wantMaxActive {
				t.Errorf(
					"RetprobeMaxActive = %d, want %d",
					gotMaxActive,
					tt.wantMaxActive,
				)
			}
		})
	}
}

func TestParseTracepointAttachOptions(t *testing.T) {
	t.Parallel()

	program := &loadedProgram{}
	tests := []struct {
		name       string
		symbol     string
		wantSystem string
		wantSymbol string
		wantErr    bool
	}{
		{
			name:       "valid tracepoint",
			symbol:     "syscalls/sys_enter_open",
			wantSystem: "syscalls",
			wantSymbol: "sys_enter_open",
		},
		{name: "missing separator", symbol: "sys_enter_open", wantErr: true},
		{name: "empty system", symbol: "/sys_enter_open", wantErr: true},
		{name: "empty symbol", symbol: "syscalls/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTracepointAttachOptions(program, tt.symbol)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTracepointAttachOptions(%q) error = %v, wantErr %t", tt.symbol, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.program != program {
				t.Error("parseTracepointAttachOptions() did not preserve program")
			}
			if got.system != tt.wantSystem {
				t.Errorf("system = %q, want %q", got.system, tt.wantSystem)
			}
			if got.symbol != tt.wantSymbol {
				t.Errorf("symbol = %q, want %q", got.symbol, tt.wantSymbol)
			}
		})
	}
}

func TestParseRawTracepointAttachOptions(t *testing.T) {
	t.Parallel()

	handle := new(ebpf.Program)
	program := &loadedProgram{handle: handle}

	opts, err := parseRawTracepointAttachOptions(program, "sched_switch")
	if err != nil {
		t.Fatalf("parseRawTracepointAttachOptions() error = %v", err)
	}
	if opts.program != program {
		t.Error("parseRawTracepointAttachOptions() did not preserve program")
	}
	if opts.linkOptions.Name != "sched_switch" {
		t.Errorf("name = %q, want %q", opts.linkOptions.Name, "sched_switch")
	}
	if opts.linkOptions.Program != handle {
		t.Error("parseRawTracepointAttachOptions() did not preserve program handle")
	}

	if _, err := parseRawTracepointAttachOptions(program, ""); err == nil {
		t.Fatal("parseRawTracepointAttachOptions() error = nil, want non-nil")
	}
}

func TestSetAttachSkip(t *testing.T) {
	t.Parallel()

	b := &defaultBPF{attachSkip: make(map[string]bool)}
	b.SetAttachSkip("exit_mm_release", "other")
	if !b.attachSkip["exit_mm_release"] || !b.attachSkip["other"] {
		t.Fatal("SetAttachSkip did not mark all names")
	}
}

func TestAttachSkipsMarkedPrograms(t *testing.T) {
	t.Parallel()

	b := &defaultBPF{
		attachSkip: map[string]bool{"unsupported": true},
		programsByID: map[uint32]*loadedProgram{
			1: {
				name: "unsupported", programType: ebpf.UnspecifiedProgram,
				sectionName: "kprobe/unsupported", sectionPrefix: "kprobe",
			},
		},
	}

	// The only program is marked skipped, so attach() must return without
	// attempting it; an UnspecifiedProgram would otherwise fail immediately.
	if err := b.attach(); err != nil {
		t.Fatalf("attach() with only a skipped program: %v", err)
	}
}

func TestAttachProgramAndDetachProgramLifecycle(t *testing.T) {
	t.Parallel()

	newBPF := func() *defaultBPF {
		return &defaultBPF{
			programIDsByName: map[string]uint32{"foo": 1},
			programsByID: map[uint32]*loadedProgram{
				1: {
					name: "foo", programType: ebpf.UnspecifiedProgram,
					sectionName: "kprobe/foo", sectionPrefix: "kprobe",
					links: map[string]link.Link{},
				},
			},
		}
	}

	t.Run("unknown program", func(t *testing.T) {
		t.Parallel()
		b := newBPF()
		if err := b.AttachProgram("nope"); err == nil {
			t.Fatal("AttachProgram with unknown name: want error")
		}
		if err := b.DetachProgram("nope"); err == nil {
			t.Fatal("DetachProgram with unknown name: want error")
		}
	})

	t.Run("fresh attach reaches program", func(t *testing.T) {
		t.Parallel()
		b := newBPF()
		// An unsupported program type fails in attachProgram before any kernel
		// call, proving AttachProgram dispatches to the attach path.
		if err := b.AttachProgram("foo"); err == nil {
			t.Fatal("AttachProgram on unsupported program type: want error")
		}
	})

	t.Run("idempotent attach and detach", func(t *testing.T) {
		t.Parallel()
		b := newBPF()
		prog := b.programsByID[1]
		prog.links["foo+0"] = link.Link(nil)

		// Attaching an already-attached program is a no-op.
		if err := b.AttachProgram("foo"); err != nil {
			t.Fatalf("AttachProgram on attached program: %v", err)
		}

		if err := b.DetachProgram("foo"); err != nil {
			t.Fatalf("DetachProgram: %v", err)
		}
		if len(prog.links) != 0 {
			t.Fatalf("DetachProgram left %d links, want 0", len(prog.links))
		}

		// Detaching an already-detached program is a no-op.
		if err := b.DetachProgram("foo"); err != nil {
			t.Fatalf("DetachProgram on detached program: %v", err)
		}
	})
}

func TestDuplicateAttachErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "kprobe",
			run: func() error {
				program := &loadedProgram{links: map[string]link.Link{"do_sys_open+0": nil}}
				return new(defaultBPF).attachKprobe(kprobeAttachOptions{
					program: program,
					symbol:  "do_sys_open",
				})
			},
		},
		{
			name: "tracepoint",
			run: func() error {
				program := &loadedProgram{links: map[string]link.Link{"syscalls/sys_enter_open": nil}}
				return new(defaultBPF).attachTracepoint(tracepointAttachOptions{
					program: program,
					system:  "syscalls",
					symbol:  "sys_enter_open",
				})
			},
		},
		{
			name: "raw tracepoint",
			run: func() error {
				program := &loadedProgram{links: map[string]link.Link{"sched_switch": nil}}
				return new(defaultBPF).attachRawTracepoint(rawTracepointAttachOptions{
					program: program,
					linkOptions: link.RawTracepointOptions{
						Name: "sched_switch",
					},
				})
			},
		},
		{
			name: "perf event",
			run: func() error {
				b := &defaultBPF{perfEvent: new(perfEventAttach)}
				return b.attachPerfEvent(new(perfEventOption))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.run(); !errors.Is(err, ErrDuplicateAttach) {
				t.Errorf("error = %v, want an error matching ErrDuplicateAttach", err)
			}
		})
	}
}
