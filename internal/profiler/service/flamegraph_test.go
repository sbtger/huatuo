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

package service

import (
	"errors"
	"strings"
	"testing"

	querierv1 "github.com/grafana/pyroscope/api/gen/proto/go/querier/v1"
	"github.com/prometheus/prometheus/model/labels"
)

func TestServiceReadyRejectsUninitializedStorage(t *testing.T) {
	err := (*Service)(nil).Ready(t.Context())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("Ready() error = %v, want initialization error", err)
	}
}

func TestApplyProfileMatcherRegion(t *testing.T) {
	filter := &SearchFilter{}
	matcher := &labels.Matcher{Name: "region", Value: "cn-beijing", Type: labels.MatchEqual}

	if err := applyProfileMatcher(filter, matcher); err != nil {
		t.Fatalf("applyProfileMatcher() error = %v", err)
	}
	if filter.Region != "cn-beijing" {
		t.Errorf("filter.Region = %q, want %q", filter.Region, "cn-beijing")
	}
}

func TestApplyProfileMatcherTracerID(t *testing.T) {
	filter := &SearchFilter{}
	matcher := &labels.Matcher{Name: "tracer_id", Value: "oom-event-2026", Type: labels.MatchEqual}

	if err := applyProfileMatcher(filter, matcher); err != nil {
		t.Fatalf("applyProfileMatcher() error = %v", err)
	}
	if filter.TracerID != "oom-event-2026" {
		t.Errorf("filter.TracerID = %q, want %q", filter.TracerID, "oom-event-2026")
	}
}

func TestSelectMergeStacktracesAcceptsTracerIDScope(t *testing.T) {
	_, err := (&Service{}).SelectMergeStacktraces(t.Context(), &querierv1.SelectMergeStacktracesRequest{
		Start:         1,
		End:           2,
		ProfileTypeID: "memory:inuse_space:bytes:space:bytes",
		LabelSelector: `{tracer_id="oom-event-2026"}`,
	})
	if err == nil {
		t.Fatal("SelectMergeStacktraces() error = nil, want uninitialized storage error")
	}
	if errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("SelectMergeStacktraces() error = %v, tracer_id scope was rejected", err)
	}
}

func TestApplyProfileMatcherRejectsUnknownLabel(t *testing.T) {
	filter := &SearchFilter{}
	matcher := &labels.Matcher{Name: "unknown", Value: "x", Type: labels.MatchEqual}

	if err := applyProfileMatcher(filter, matcher); err == nil {
		t.Fatal("applyProfileMatcher() error = nil, want error for unknown label")
	}
}

func TestProfileStringRejectsInvalidIndex(t *testing.T) {
	table := []string{"", "samples"}
	if got, ok := profileString(table, 1); !ok || got != "samples" {
		t.Fatalf("profileString(1)=(%q,%t), want (samples,true)", got, ok)
	}
	for _, index := range []int64{-1, 2, 100} {
		if got, ok := profileString(table, index); ok || got != "" {
			t.Errorf("profileString(%d)=(%q,%t), want empty,false", index, got, ok)
		}
	}
}

func TestBuildProfileSearchQueryIncludesPage(t *testing.T) {
	query := buildProfileSearchQuery(&SearchFilter{TracerID: "task-2026", Limit: 25, Offset: 50})
	if query.Limit != 25 || query.Offset != 50 {
		t.Fatalf("query page=(%d,%d), want (25,50)", query.Limit, query.Offset)
	}
}
