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

package handlers

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"huatuo-bamai/pkg/tracing"
	pkgtypes "huatuo-bamai/pkg/types"
)

// DocumentToWatchEvent converts a tracing Document into a CloudEvents 1.0 WatchEvent.
func DocumentToWatchEvent(doc *tracing.Document) pkgtypes.WatchEvent {
	return documentToWatchEvent(doc, false)
}

func documentToWatchEvent(
	doc *tracing.Document, includeTracerData bool,
) pkgtypes.WatchEvent {
	data := pkgtypes.WatchEventData{
		Hostname:               doc.Hostname,
		Region:                 doc.Region,
		ObservedTimestamp:      doc.TracerTime,
		ContainerID:            doc.ContainerID,
		ContainerHostname:      doc.ContainerHostname,
		ContainerHostNamespace: doc.ContainerHostNamespace,
		ContainerType:          doc.ContainerType,
		ContainerQos:           doc.ContainerQoS,
		TracerName:             doc.TracerName,
		TracerID:               doc.TracerID,
		TracerRunType:          doc.TracerRunType,
	}
	if includeTracerData {
		data.TracerData = doc.TracerData
	}

	return pkgtypes.WatchEvent{
		SpecVersion:     "1.0",
		ID:              uuid.New().String(),
		Source:          fmt.Sprintf("/huatuo/%s/%s", doc.Hostname, doc.TracerName),
		Type:            "tech.huatuo.kernel.event",
		DataContentType: "application/json",
		Time:            doc.UploadedTime.UTC().Format(time.RFC3339Nano),
		Data:            data,
	}
}
