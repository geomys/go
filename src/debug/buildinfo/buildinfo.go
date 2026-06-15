// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buildinfo provides access to information embedded in a Go binary
// about how it was built. This includes the Go toolchain version, and the
// set of modules used (for binaries built in module mode).
//
// Build information is available for the currently running binary in
// runtime/debug.ReadBuildInfo.
package buildinfo

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"debug/plan9obj"
	"encoding/binary"
	"errors"
	"fmt"
	"internal/saferio"
	"internal/xcoff"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	_ "unsafe" // for linkname
)

// Type alias for build info. We cannot move the types here, since
// runtime/debug would need to import this package, which would make it
// a much larger dependency.
type BuildInfo = debug.BuildInfo

// errUnrecognizedFormat is returned when a given executable file doesn't
// appear to be in a known format, or it breaks the rules of that format,
// or when there are I/O errors reading the file.
var errUnrecognizedFormat = errors.New("unrecognized file format")

// errNotGoExe is returned when a given executable file is valid but does
// not contain Go build information.
//
// errNotGoExe should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quay/claircore
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname errNotGoExe
var errNotGoExe = errors.New("not a Go executable")

// The build info blob left by the linker is identified by a 32-byte header,
// consisting of buildInfoMagic (14 bytes), followed by version-dependent
// fields.
var buildInfoMagic = []byte("\xff Go buildinf:")

const (
	buildInfoAlign      = 16
	buildInfoHeaderSize = 32
)

// ReadFile returns build information embedded in a Go binary
// file at the given path. Most information is only available for binaries built
// with module support.
func ReadFile(name string) (info *BuildInfo, err error) {
	defer func() {
		if _, ok := errors.AsType[*fs.PathError](err); ok {
			err = fmt.Errorf("could not read Go build info: %w", err)
		} else if err != nil {
			err = fmt.Errorf("could not read Go build info from %s: %w", name, err)
		}
	}()

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read returns build information embedded in a Go binary file
// accessed through the given ReaderAt. Most information is only available for
// binaries built with module support.
func Read(r io.ReaderAt) (*BuildInfo, error) {
	vers, mod, err := readRawBuildInfo(r)
	if err != nil {
		return nil, err
	}
	bi, err := debug.ParseBuildInfo(mod)
	if err != nil {
		return nil, err
	}
	bi.GoVersion = vers
	return bi, nil
}

type exe interface {
	// DataStart returns the virtual address and size of the segment or section that
	// should contain build information. This is either a specially named section
	// or the first writable non-zero data segment.
	DataStart() (uint64, uint64)

	// DataReader returns an io.ReaderAt that reads from addr until the end
	// of segment or section that contains addr.
	DataReader(addr uint64) (io.ReaderAt, error)
}

// readRawBuildInfo extracts the Go toolchain version and module information
// strings from a Go binary. On success, vers should be non-empty. mod
// is empty if the binary was not built with modules enabled.
func readRawBuildInfo(r io.ReaderAt) (vers, mod string, err error) {
	// Read the first bytes of the file to identify the format, then delegate to
	// a format-specific function to load segment and section headers.
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return "", "", errUnrecognizedFormat
	}

	var x exe
	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &elfExe{f}
	case bytes.HasPrefix(ident, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &peExe{f}
	case bytes.HasPrefix(ident, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(ident[1:], []byte("\xFA\xED\xFE")):
		f, err := macho.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &machoExe{f}
	case bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBE")) || bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBF")):
		f, err := macho.NewFatFile(r)
		if err != nil || len(f.Arches) == 0 {
			return "", "", errUnrecognizedFormat
		}
		x = &machoExe{f.Arches[0].File}
	case bytes.HasPrefix(ident, []byte("\x00asm")):
		f, err := newWasmExe(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = f
	case bytes.HasPrefix(ident, []byte{0x01, 0xDF}) || bytes.HasPrefix(ident, []byte{0x01, 0xF7}):
		f, err := xcoff.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &xcoffExe{f}
	case hasPlan9Magic(ident):
		f, err := plan9obj.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &plan9objExe{f}
	default:
		return "", "", errUnrecognizedFormat
	}

	// Read segment or section to find the build info blob.
	// On some platforms, the blob will be in its own section, and DataStart
	// returns the address of that section. On others, it's somewhere in the
	// data segment; the linker puts it near the beginning.
	// See cmd/link/internal/ld.Link.buildinfo.
	dataAddr, dataSize := x.DataStart()
	if dataSize == 0 {
		return "", "", errNotGoExe
	}

	addr, err := searchMagic(x, dataAddr, dataSize)
	if err != nil {
		return "", "", err
	}

	// Read in the full header first.
	header, err := readData(x, addr, buildInfoHeaderSize)
	if err == io.EOF {
		return "", "", errNotGoExe
	} else if err != nil {
		return "", "", err
	}
	if len(header) < buildInfoHeaderSize {
		return "", "", errNotGoExe
	}

	const (
		ptrSizeOffset = 14
		flagsOffset   = 15
		versPtrOffset = 16

		flagsEndianMask   = 0x1
		flagsEndianLittle = 0x0
		flagsEndianBig    = 0x1

		flagsVersionMask = 0x2
		flagsVersionPtr  = 0x0
		flagsVersionInl  = 0x2
	)

	// Decode the blob. The blob is a 32-byte header, optionally followed
	// by 2 varint-prefixed string contents.
	//
	// type buildInfoHeader struct {
	// 	magic       [14]byte
	// 	ptrSize     uint8 // used if flagsVersionPtr
	// 	flags       uint8
	// 	versPtr     targetUintptr // used if flagsVersionPtr
	// 	modPtr      targetUintptr // used if flagsVersionPtr
	// }
	//
	// The version bit of the flags field determines the details of the format.
	//
	// Prior to 1.18, the flags version bit is flagsVersionPtr. In this
	// case, the header includes pointers to the version and modinfo Go
	// strings in the header. The ptrSize field indicates the size of the
	// pointers and the endian bit of the flag indicates the pointer
	// endianness.
	//
	// Since 1.18, the flags version bit is flagsVersionInl. In this case,
	// the header is followed by the string contents inline as
	// length-prefixed (as varint) string contents. First is the version
	// string, followed immediately by the modinfo string.
	flags := header[flagsOffset]
	if flags&flagsVersionMask == flagsVersionInl {
		vers, addr, err = decodeString(x, addr+buildInfoHeaderSize)
		if err != nil {
			return "", "", err
		}
		mod, _, err = decodeString(x, addr)
		if err != nil {
			return "", "", err
		}
	} else {
		// flagsVersionPtr (<1.18)
		ptrSize := int(header[ptrSizeOffset])
		bigEndian := flags&flagsEndianMask == flagsEndianBig
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else if ptrSize == 8 {
			readPtr = bo.Uint64
		} else {
			return "", "", errNotGoExe
		}
		vers = readString(x, ptrSize, readPtr, readPtr(header[versPtrOffset:]))
		mod = readString(x, ptrSize, readPtr, readPtr(header[versPtrOffset+ptrSize:]))
	}
	if vers == "" {
		return "", "", errNotGoExe
	}
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing: sentinel strings delimiting the module info.
		// These are cmd/go/internal/modload.infoStart and infoEnd.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}

	return vers, mod, nil
}

func hasPlan9Magic(magic []byte) bool {
	if len(magic) >= 4 {
		m := binary.BigEndian.Uint32(magic)
		switch m {
		case plan9obj.Magic386, plan9obj.MagicAMD64, plan9obj.MagicARM:
			return true
		}
	}
	return false
}

func decodeString(x exe, addr uint64) (string, uint64, error) {
	// varint length followed by length bytes of data.

	// N.B. ReadData reads _up to_ size bytes from the section containing
	// addr. So we don't need to check that size doesn't overflow the
	// section.
	b, err := readData(x, addr, binary.MaxVarintLen64)
	if err == io.EOF {
		return "", 0, errNotGoExe
	} else if err != nil {
		return "", 0, err
	}

	length, n := binary.Uvarint(b)
	if n <= 0 {
		return "", 0, errNotGoExe
	}
	addr += uint64(n)

	b, err = readData(x, addr, length)
	if err == io.EOF {
		return "", 0, errNotGoExe
	} else if err == io.ErrUnexpectedEOF {
		// Length too large to allocate. Clearly bogus value.
		return "", 0, errNotGoExe
	} else if err != nil {
		return "", 0, err
	}
	if uint64(len(b)) < length {
		// Section ended before we could read the full string.
		return "", 0, errNotGoExe
	}

	return string(b), addr + length, nil
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := readData(x, addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := readData(x, dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

const searchChunkSize = 1 << 20 // 1 MB

// searchMagic returns the aligned first instance of buildInfoMagic in the data
// range [addr, addr+size). Returns false if not found.
func searchMagic(x exe, start, size uint64) (uint64, error) {
	end := start + size
	if end < start {
		// Overflow.
		return 0, errUnrecognizedFormat
	}

	// Round up start; magic can't occur in the initial unaligned portion.
	start = (start + buildInfoAlign - 1) &^ (buildInfoAlign - 1)
	if start >= end {
		return 0, errNotGoExe
	}

	var buf []byte
	for start < end {
		// Read in chunks to avoid consuming too much memory if data is large.
		//
		// Normally it would be somewhat painful to handle the magic crossing a
		// chunk boundary, but since it must be 16-byte aligned we know it will
		// fall within a single chunk.
		remaining := end - start
		chunkSize := uint64(searchChunkSize)
		if chunkSize > remaining {
			chunkSize = remaining
		}

		if buf == nil {
			buf = make([]byte, chunkSize)
		} else {
			// N.B. chunkSize can only decrease, and only on the
			// last chunk.
			buf = buf[:chunkSize]
			clear(buf)
		}

		n, err := readDataInto(x, start, buf)
		if err == io.EOF {
			// EOF before finding the magic; must not be a Go executable.
			return 0, errNotGoExe
		} else if err != nil {
			return 0, err
		}

		data := buf[:n]
		for len(data) > 0 {
			i := bytes.Index(data, buildInfoMagic)
			if i < 0 {
				break
			}
			if remaining-uint64(i) < buildInfoHeaderSize {
				// Found magic, but not enough space left for the full header.
				return 0, errNotGoExe
			}
			if i%buildInfoAlign != 0 {
				// Found magic, but misaligned. Keep searching.
				next := (i + buildInfoAlign - 1) &^ (buildInfoAlign - 1)
				if next > len(data) {
					// Corrupt object file: the remaining
					// count says there is more data,
					// but we didn't read it.
					return 0, errNotGoExe
				}
				data = data[next:]
				continue
			}
			// Good match!
			return start + uint64(i), nil
		}

		start += chunkSize
	}

	return 0, errNotGoExe
}

func readData(x exe, addr, size uint64) ([]byte, error) {
	r, err := x.DataReader(addr)
	if err != nil {
		return nil, err
	}

	b, err := saferio.ReadDataAt(r, size, 0)
	if len(b) > 0 && err == io.EOF {
		err = nil
	}
	return b, err
}

func readDataInto(x exe, addr uint64, b []byte) (int, error) {
	r, err := x.DataReader(addr)
	if err != nil {
		return 0, err
	}

	n, err := r.ReadAt(b, 0)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	f *elf.File
}

func (x *elfExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			remaining := prog.Vaddr + prog.Filesz - addr
			return io.NewSectionReader(prog, int64(addr-prog.Vaddr), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *elfExe) DataStart() (uint64, uint64) {
	for _, s := range x.f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr, s.Size
		}
	}
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr, p.Memsz
		}
	}
	return 0, 0
}

// peExe is the PE (Windows Portable Executable) implementation of the exe interface.
type peExe struct {
	f *pe.File
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) DataReader(addr uint64) (io.ReaderAt, error) {
	addr -= x.imageBase()
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			remaining := uint64(sect.VirtualAddress+sect.Size) - addr
			return io.NewSectionReader(sect, int64(addr-uint64(sect.VirtualAddress)), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *peExe) DataStart() (uint64, uint64) {
	// Assume data is first writable section.
	const (
		IMAGE_SCN_CNT_CODE               = 0x00000020
		IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
		IMAGE_SCN_MEM_EXECUTE            = 0x20000000
		IMAGE_SCN_MEM_READ               = 0x40000000
		IMAGE_SCN_MEM_WRITE              = 0x80000000
		IMAGE_SCN_MEM_DISCARDABLE        = 0x2000000
		IMAGE_SCN_LNK_NRELOC_OVFL        = 0x1000000
		IMAGE_SCN_ALIGN_32BYTES          = 0x600000
	)
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 &&
			sect.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
			return uint64(sect.VirtualAddress) + x.imageBase(), uint64(sect.VirtualSize)
		}
	}
	return 0, 0
}

// machoExe is the Mach-O (Apple macOS/iOS) implementation of the exe interface.
type machoExe struct {
	f *macho.File
}

func (x *machoExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			remaining := seg.Addr + seg.Filesz - addr
			return io.NewSectionReader(seg, int64(addr-seg.Addr), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *machoExe) DataStart() (uint64, uint64) {
	// Look for section named "__go_buildinfo".
	for _, sec := range x.f.Sections {
		if sec.Name == "__go_buildinfo" {
			return sec.Addr, sec.Size
		}
	}
	// Try the first non-empty writable segment.
	const RW = 3
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Addr != 0 && seg.Filesz != 0 && seg.Prot == RW && seg.Maxprot == RW {
			return seg.Addr, seg.Memsz
		}
	}
	return 0, 0
}

// xcoffExe is the XCOFF (AIX eXtended COFF) implementation of the exe interface.
type xcoffExe struct {
	f *xcoff.File
}

func (x *xcoffExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress <= addr && addr <= sect.VirtualAddress+sect.Size-1 {
			remaining := sect.VirtualAddress + sect.Size - addr
			return io.NewSectionReader(sect, int64(addr-sect.VirtualAddress), int64(remaining)), nil
		}
	}
	return nil, errors.New("address not mapped")
}

func (x *xcoffExe) DataStart() (uint64, uint64) {
	if s := x.f.SectionByType(xcoff.STYP_DATA); s != nil {
		return s.VirtualAddress, s.Size
	}
	return 0, 0
}

// plan9objExe is the Plan 9 a.out implementation of the exe interface.
type plan9objExe struct {
	f *plan9obj.File
}

func (x *plan9objExe) DataStart() (uint64, uint64) {
	if s := x.f.Section("data"); s != nil {
		return uint64(s.Offset), uint64(s.Size)
	}
	return 0, 0
}

func (x *plan9objExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, sect := range x.f.Sections {
		if uint64(sect.Offset) <= addr && addr <= uint64(sect.Offset+sect.Size-1) {
			remaining := uint64(sect.Offset+sect.Size) - addr
			return io.NewSectionReader(sect, int64(addr-uint64(sect.Offset)), int64(remaining)), nil
		}
	}
	return nil, errors.New("address not mapped")
}

// wasmExe is the WebAssembly implementation of the exe interface.
//
// A WebAssembly binary has no sections mapped at virtual addresses. Instead,
// the data used to initialize linear memory is stored in the data section as a
// list of segments, each placed at a constant offset in linear memory. The
// build info blob begins a 16-byte-aligned segment, but the linker omits runs
// of zero bytes (see cmd/link/internal/wasm.writeDataSec), so the blob is split
// across segments, including across the unused, elided upper half of its
// header.
//
// newWasmExe finds the blob and reconstructs a contiguous copy of linear memory
// from it onward, filling the gaps with zeros, so that DataStart and DataReader
// can serve the shared scanning and decoding code from a plain byte slice. The
// reconstruction is bounded to wasmBuildInfoLimit, and segment contents are
// streamed straight from the file, so memory use stays bounded regardless of
// the size of the binary.
type wasmExe struct {
	base uint64 // linear-memory address of data
	data []byte
}

const (
	// wasmDataSectionID is the section ID of the data section in a WebAssembly
	// binary. See https://webassembly.github.io/spec/core/binary/modules.html#sections.
	wasmDataSectionID = 11

	// wasmBuildInfoLimit bounds how much linear memory is reconstructed when
	// reading the build info, so segments at distant offsets cannot force a
	// huge allocation. The blob lies at the start of the reconstructed range,
	// and the build info is far smaller than this in practice.
	wasmBuildInfoLimit = 16 << 20
)

func newWasmExe(r io.ReaderAt) (*wasmExe, error) {
	// Find where the build info blob begins, and the highest address reached by
	// any data segment. The blob begins a 16-byte-aligned segment, so this only
	// reads the leading bytes of each segment and retains no segment contents.
	base, maxAddr, found, err := scanWasmBuildInfo(r)
	if err != nil {
		return nil, err
	}

	// If the blob is absent, return an empty exe so that DataStart reports no
	// data and the file is reported as a valid non-Go binary rather than an
	// unrecognized one.
	x := &wasmExe{}
	if !found {
		return x, nil
	}

	// Reconstruct linear memory from the blob onward, filling the gaps between
	// segments with zeros (in particular the elided upper half of the header),
	// up to the limit. Each segment's overlapping bytes are read straight into
	// the reconstruction, so no more than wasmBuildInfoLimit is held at once.
	end := maxAddr
	if end-base > wasmBuildInfoLimit {
		end = base + wasmBuildInfoLimit
	}
	data := make([]byte, end-base)
	err = walkWasmDataSegments(r, func(offset, size uint64, pos int64) error {
		segEnd := offset + size
		if offset >= end || segEnd <= base {
			return nil
		}
		lo, hi := max(offset, base), min(segEnd, end)
		if n, _ := r.ReadAt(data[lo-base:hi-base], pos+int64(lo-offset)); uint64(n) < hi-lo {
			return errUnrecognizedFormat // segment extends past the file
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	x.base = base
	x.data = data
	return x, nil
}

// scanWasmBuildInfo walks the data segments and returns the lowest
// 16-byte-aligned linear-memory address at which a segment begins with the
// build info magic, along with the highest address reached by any segment.
// found is false if no segment begins with the magic.
func scanWasmBuildInfo(r io.ReaderAt) (base, maxAddr uint64, found bool, err error) {
	magic := make([]byte, len(buildInfoMagic))
	err = walkWasmDataSegments(r, func(offset, size uint64, pos int64) error {
		if e := offset + size; e > maxAddr {
			maxAddr = e
		}
		// The blob begins a 16-byte-aligned segment with the magic. Skip any
		// segment that cannot be the lowest such one, so we read no more than
		// necessary.
		if offset%buildInfoAlign != 0 || size < uint64(len(magic)) {
			return nil
		}
		if found && offset >= base {
			return nil
		}
		if n, _ := r.ReadAt(magic, pos); n < len(magic) {
			return errUnrecognizedFormat // segment extends past the file
		}
		if bytes.Equal(magic, buildInfoMagic) {
			base, found = offset, true
		}
		return nil
	})
	return base, maxAddr, found, err
}

// walkWasmDataSegments calls fn for each non-empty active data segment in the
// module, passing the segment's linear-memory offset, its size in bytes, and
// the file position of its data. The Go linker emits only mode 0 (active,
// memory 0) segments; the walk stops at the first segment of any other kind,
// since the file is then a valid non-Go binary.
func walkWasmDataSegments(r io.ReaderAt, fn func(offset, size uint64, pos int64) error) error {
	// A module starts with the magic "\0asm" followed by the version as a
	// little-endian uint32.
	var hdr [8]byte
	if n, _ := r.ReadAt(hdr[:], 0); n < len(hdr) {
		return errUnrecognizedFormat
	}
	if string(hdr[:4]) != "\x00asm" || binary.LittleEndian.Uint32(hdr[4:]) != 1 {
		return errUnrecognizedFormat
	}

	// A module is a sequence of sections, each a one-byte ID, a LEB128 length,
	// and that many content bytes. Walk them, descending into data sections.
	w := wasmReader{r: r, pos: int64(len(hdr))}
	for {
		id, ok := w.readByte()
		if !ok {
			return nil // end of module
		}
		size, ok := w.readUint()
		if !ok {
			return errUnrecognizedFormat
		}
		end := w.pos + int64(size)
		if end < w.pos {
			return errUnrecognizedFormat // overflow
		}
		if id == wasmDataSectionID {
			if err := walkWasmDataSection(&w, end, fn); err != nil {
				return err
			}
		}
		w.pos = end
	}
}

// walkWasmDataSection walks the segments of one data section, whose content
// ends at the file position end, calling fn for each non-empty segment.
func walkWasmDataSection(w *wasmReader, end int64, fn func(offset, size uint64, pos int64) error) error {
	count, ok := w.readUint()
	if !ok {
		return errUnrecognizedFormat
	}
	for i := uint64(0); i < count; i++ {
		// Each segment begins with a mode (see the data segment grammar at
		// https://webassembly.github.io/spec/core/binary/modules.html#data-section).
		// The Go linker emits only mode 0: active, memory 0, with an i32.const
		// offset expression followed by the bytes. Reject anything else.
		mode, ok := w.readUint()
		if !ok {
			return errUnrecognizedFormat
		}
		if mode != 0 {
			// The Go linker emits only mode 0 (active, memory 0) segments. A
			// different segment kind is valid wasm, just not something Go
			// produces, and we can't parse past it without decoding its body.
			// Stop here: the file is reported as a valid non-Go binary (via the
			// empty result) rather than an unrecognized one. This is the last
			// data section, so nothing further is skipped.
			return nil
		}
		offset, ok := w.readOffsetExpr()
		if !ok {
			return errUnrecognizedFormat
		}
		size, ok := w.readUint()
		if !ok || w.pos > end || size > uint64(end-w.pos) {
			return errUnrecognizedFormat
		}
		if size > 0 {
			if err := fn(offset, size, w.pos); err != nil {
				return err
			}
		}
		w.pos += int64(size)
	}
	return nil
}

func (x *wasmExe) DataStart() (uint64, uint64) {
	return x.base, uint64(len(x.data))
}

func (x *wasmExe) DataReader(addr uint64) (io.ReaderAt, error) {
	if addr < x.base || addr-x.base > uint64(len(x.data)) {
		return nil, errNotGoExe
	}
	return bytes.NewReader(x.data[addr-x.base:]), nil
}

// wasmReader reads a WebAssembly binary sequentially through an io.ReaderAt.
type wasmReader struct {
	r   io.ReaderAt
	pos int64
}

func (w *wasmReader) readByte() (byte, bool) {
	var b [1]byte
	if n, _ := w.r.ReadAt(b[:], w.pos); n < 1 {
		return 0, false
	}
	w.pos++
	return b[0], true
}

// readUint reads an unsigned LEB128 integer.
func (w *wasmReader) readUint() (uint64, bool) {
	var result uint64
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, false // too many bytes
		}
		b, ok := w.readByte()
		if !ok {
			return 0, false
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, true
		}
	}
}

// readInt reads a signed LEB128 integer.
func (w *wasmReader) readInt() (int64, bool) {
	var result int64
	var shift uint
	for {
		b, ok := w.readByte()
		if !ok {
			return 0, false
		}
		result |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && b&0x40 != 0 {
				result |= -1 << shift // sign extend
			}
			return result, true
		}
		if shift >= 64 {
			return 0, false // too many bytes
		}
	}
}

// readOffsetExpr reads a constant offset expression of the form
// "i32.const <value> end" and returns the value as a linear-memory offset.
func (w *wasmReader) readOffsetExpr() (uint64, bool) {
	if op, ok := w.readByte(); !ok || op != 0x41 { // i32.const
		return 0, false
	}
	v, ok := w.readInt()
	if !ok {
		return 0, false
	}
	if op, ok := w.readByte(); !ok || op != 0x0b { // end
		return 0, false
	}
	// i32.const holds a 32-bit value, used here as an unsigned address.
	return uint64(uint32(v)), true
}
