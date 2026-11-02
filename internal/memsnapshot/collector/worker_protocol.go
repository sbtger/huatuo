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

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ccfos/huatuo/internal/memsnapshot"
)

const (
	workerProtocolVersion = 1
	maxWorkerRequestBytes = 4 << 10
	maxWorkerReplyBytes   = 1 << 20
	maxWorkerStderrBytes  = 64 << 10
)

type workerRequest struct {
	Version  int                 `json:"version"`
	ID       uint64              `json:"id"`
	Deadline int64               `json:"deadline"`
	Request  memsnapshot.Request `json:"request"`
}

type workerResponse struct {
	Version int     `json:"version"`
	ID      uint64  `json:"id"`
	Result  *Result `json:"result,omitempty"`
	Error   string  `json:"error,omitempty"`
}

func decodeWorkerMessage(reader io.Reader, maximum int64, dst any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maximum {
		return fmt.Errorf("worker message exceeds %d bytes", maximum)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("worker message has trailing data")
	}
	return nil
}

// ServeWorker handles one private-pipe request without starting an Agent.
func ServeWorker(input io.Reader, output io.Writer) error {
	var request workerRequest
	if err := decodeWorkerMessage(input, maxWorkerRequestBytes, &request); err != nil {
		return fmt.Errorf("decode memory snapshot request: %w", err)
	}
	if request.Version != workerProtocolVersion || request.ID == 0 {
		return errors.New("unsupported memory snapshot worker protocol")
	}
	response := workerResponse{Version: workerProtocolVersion, ID: request.ID}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, request.Deadline))
	defer cancel()
	options := Options{
		MaxMemoryObjectEntries: request.Request.MaxMemoryObjectEntries,
		SnapshotTimeout:        time.Until(time.Unix(0, request.Deadline)),
	}
	var err error
	if err = options.validate(); err == nil {
		if err = memsnapshot.ValidateProcessInstanceID(request.Request.Process); err == nil {
			response.Result, err = snapshotLocal(ctx, request.Request.Process, options, request.Request.SamplingSeed)
			if err == nil {
				err = memsnapshot.ValidateProcessInstanceID(request.Request.Process)
			}
		}
	}
	if err != nil {
		response.Result = nil
		response.Error = err.Error()
		if len(response.Error) > 4096 {
			response.Error = response.Error[:4096]
		}
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(encoded) > maxWorkerReplyBytes {
		return errors.New("memory snapshot worker response exceeds limit")
	}
	_, err = output.Write(encoded)
	return err
}

func validateWorkerResponse(response workerResponse, request workerRequest) error {
	if response.Version != workerProtocolVersion || response.ID != request.ID {
		return errors.New("memory snapshot worker protocol or request identity mismatch")
	}
	if response.Error != "" {
		if len(response.Error) > 4096 || response.Result != nil {
			return errors.New("invalid memory snapshot worker error")
		}
		return fmt.Errorf("memory snapshot worker: %s", response.Error)
	}
	result := response.Result
	if result == nil || result.Process != request.Request.Process || result.Snapshot == nil || result.SnapshotStartedAt.IsZero() {
		return errors.New("memory snapshot worker returned missing or mismatched process data")
	}
	if !validSnapshotStatus(result.Snapshot.Status) {
		return errors.New("memory snapshot worker returned invalid snapshot status")
	}
	switch result.Language {
	case memsnapshot.LanguageUnknown, memsnapshot.LanguageGo, memsnapshot.LanguageJava, memsnapshot.LanguagePython,
		memsnapshot.LanguageCPP, memsnapshot.LanguageNative, memsnapshot.LanguageRust, memsnapshot.LanguageJavaScript,
		memsnapshot.LanguageRuby, memsnapshot.LanguagePHP, memsnapshot.LanguageDotNet:
	default:
		return errors.New("memory snapshot worker returned invalid language")
	}
	if result.ProcessMemory != nil && !validSnapshotStatus(result.ProcessMemory.Status) {
		return errors.New("memory snapshot worker returned invalid process memory status")
	}
	return memsnapshot.LimitOutput(result.Snapshot, request.Request.MaxMemoryObjectEntries)
}

func validSnapshotStatus(status memsnapshot.Status) bool {
	switch status {
	case memsnapshot.SnapshotStatusComplete, memsnapshot.SnapshotStatusPartial,
		memsnapshot.SnapshotStatusFailed, memsnapshot.SnapshotStatusUnavailable:
		return true
	default:
		return false
	}
}
