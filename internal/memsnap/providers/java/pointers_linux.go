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
	"encoding/binary"
)

func (encoding ptrEncoding) headerBytes() uint64 {
	if encoding.compressedKlass {
		return 12
	}
	return 16
}

func (encoding ptrEncoding) klassAddress(raw []byte) (uint64, bool) {
	if encoding.compressedKlass {
		if len(raw) < 12 {
			return 0, false
		}
		narrow := binary.LittleEndian.Uint32(raw[8:12])
		shifted := uint64(narrow) << encoding.klassShift
		address, valid := checkedAdd(encoding.klassBase, shifted)
		return address, narrow != 0 && valid
	}
	if len(raw) < 16 {
		return 0, false
	}
	address := binary.LittleEndian.Uint64(raw[8:16])
	return address, address != 0
}

func pointerEncoding(memory processMemory, metadata *vmMeta) (ptrEncoding, error) {
	encoding := ptrEncoding{compressedKlass: metadata.compressedKlass}
	if !encoding.compressedKlass {
		return encoding, nil
	}
	baseField := firstStruct(metadata, "CompressedKlassPointers::_base",
		"CompressedKlassPointers::_narrow_klass._base",
		"Universe::_narrow_klass._base")
	shiftField := firstStruct(metadata, "CompressedKlassPointers::_shift",
		"CompressedKlassPointers::_narrow_klass._shift",
		"Universe::_narrow_klass._shift")
	if !baseField.isStatic || !shiftField.isStatic {
		return ptrEncoding{}, unsupportedHotSpot(
			"compressed Klass pointer metadata is unavailable")
	}
	base, err := memory.uint64(baseField.address)
	if err != nil {
		return ptrEncoding{}, err
	}
	shift, err := memory.uint32(shiftField.address)
	if err != nil || shift > 16 {
		return ptrEncoding{}, unsupportedHotSpot(
			"compressed Klass shift is invalid")
	}
	encoding.klassBase = base
	encoding.klassShift = uint(shift)
	return encoding, nil
}

func mirrorSizeOffset(memory processMemory,
	metadata *vmMeta,
) (int, error) {
	field, ok := metadata.structs["java_lang_Class::_oop_size_offset"]
	if !ok || !field.isStatic || field.address == 0 {
		// Only java.lang.Class mirrors need this optional VMStruct. Other
		// classes remain safe to size and should still produce a histogram.
		return 0, nil
	}
	value, err := memory.uint32(field.address)
	if err != nil || value > 4096 {
		return 0, unsupportedHotSpot("class mirror size offset is invalid")
	}
	return int(value), nil
}
