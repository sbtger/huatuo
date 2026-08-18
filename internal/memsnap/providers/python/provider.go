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
	"errors"
	"fmt"
	"sort"
	"strings"

	"huatuo-bamai/internal/memsnap"
)

var ErrUnsupportedRuntime = errors.New("CPython runtime is unsupported")

type CaptureResponse struct {
	RuntimeVersion    string                    `json:"runtime_version"`
	Status            memsnap.CompletionStatus  `json:"status"`
	Truncated         bool                      `json:"truncated"`
	TruncationReasons []string                  `json:"truncation_reasons"`
	Coverage          memsnap.Coverage          `json:"coverage"`
	Objects           []memsnap.ObjectAggregate `json:"objects"`
	FinalizeLocal     func() error              `json:"-"`
}

type Executor interface {
	Execute(ctx context.Context, request memsnap.Request) (*CaptureResponse, error)
}

type Provider struct {
	executor Executor
}

func NewProvider(executor Executor) (*Provider, error) {
	if executor == nil {
		return nil, errors.New("Python on-demand executor is required")
	}
	return &Provider{executor: executor}, nil
}

func (p *Provider) Language() memsnap.Language { return memsnap.LanguagePython }

//nolint:gocritic // Providers receive an isolated request value from the coordinator.
func (p *Provider) Capture(ctx context.Context,
	request memsnap.Request,
) (*memsnap.Result, error) {
	response, err := p.executor.Execute(ctx, request)
	if errors.Is(err, ErrUnsupportedRuntime) {
		return pythonFailure(memsnap.StatusProviderUnavailable, err.Error()), nil
	}
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("Python on-demand executor returned a nil response")
	}
	if err := validateStatus(response.Status); err != nil {
		return nil, err
	}
	result := &memsnap.Result{Manifest: memsnap.Manifest{
		RuntimeVersion: response.RuntimeVersion, Status: response.Status,
		Truncated:         response.Truncated,
		TruncationReasons: append([]string(nil), response.TruncationReasons...),
		Coverage:          response.Coverage,
	}}
	result.FinalizeLocal = func() error {
		if response.FinalizeLocal != nil {
			finalize := response.FinalizeLocal
			response.FinalizeLocal = nil
			if err := finalize(); err != nil {
				return err
			}
		}
		result.Manifest.Coverage = response.Coverage
		result.Objects = make([]memsnap.ObjectAggregate, 0, len(response.Objects))
		for _, object := range response.Objects {
			if err := validateObject(&object); err != nil {
				return err
			}
			result.Objects = append(result.Objects, object)
		}
		sort.SliceStable(result.Objects, func(i, j int) bool {
			return pythonDiagnosticBytes(&result.Objects[i]) >
				pythonDiagnosticBytes(&result.Objects[j])
		})
		return nil
	}
	return result, nil
}

func validateObject(object *memsnap.ObjectAggregate) error {
	if object.TypeName == "" || len(object.TypeName) > 512 ||
		!strings.Contains(object.TypeName, ".") {
		return fmt.Errorf("Python capture returned invalid type name %q", object.TypeName)
	}
	if object.AverageBytes < 0 {
		return fmt.Errorf("Python capture returned negative average size for %s",
			object.TypeName)
	}
	for _, field := range object.Fields {
		if field.Name == "" || field.ReferencedType == "" ||
			!strings.Contains(field.ReferencedType, ".") ||
			field.UniqueReferencedObjects > field.ReferenceCount {
			return fmt.Errorf("Python capture returned invalid field shape")
		}
	}
	return nil
}

func pythonDiagnosticBytes(object *memsnap.ObjectAggregate) uint64 {
	largestField := uint64(0)
	for _, field := range object.Fields {
		if field.ReferencedShallowBytes > largestField {
			largestField = field.ReferencedShallowBytes
		}
	}
	return object.ShallowBytes + largestField
}

func pythonFailure(status memsnap.CompletionStatus,
	reason string,
) *memsnap.Result {
	return &memsnap.Result{Manifest: memsnap.Manifest{
		Status: status,
		Coverage: memsnap.Coverage{
			Consistency: "not_captured", SizeSemantics: "unavailable",
			KnownGaps: []string{reason},
		},
	}}
}

func validateStatus(status memsnap.CompletionStatus) error {
	switch status {
	case memsnap.StatusComplete, memsnap.StatusPartialOutputLimit,
		memsnap.StatusPartialObjectLimit, memsnap.StatusPartialRecordLimit,
		memsnap.StatusPartialDeadline,
		memsnap.StatusPartialMemoryPressure, memsnap.StatusCaptureFailed:
		return nil
	default:
		return fmt.Errorf("unknown Python runtime snapshot status %q", status)
	}
}
