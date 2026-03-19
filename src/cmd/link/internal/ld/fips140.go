// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
FIPS-140 Verification Support

See ../../../internal/obj/fips.go for a basic overview.
This file is concerned with computing the hash of the FIPS code+data.
Package obj has taken care of marking the FIPS symbols with the
special types STEXTFIPS, SRODATAFIPS, SNOPTRDATAFIPS, and SDATAFIPS.

# FIPS Symbol Layout

The first order of business is collecting the FIPS symbols into
contiguous sections of the final binary and identifying the start and
end of those sections. The linker already tracks the start and end of
the text section as runtime.text and runtime.etext, and similarly for
other sections, but the implementation of those symbols is tricky and
platform-specific. The problem is that they are zero-length
pseudo-symbols that share addresses with other symbols, which makes
everything harder. For the FIPS sections, we avoid that subtlety by
defining actual non-zero-length symbols bracketing each section and
use those symbols as the boundaries.

Specifically, we define a 1-byte symbol go:textfipsstart of type
STEXTFIPSSTART and a 1-byte symbol go:textfipsend of type STEXTFIPSEND,
and we place those two symbols immediately before and after the
STEXTFIPS symbols. We do the same for SRODATAFIPS, SNOPTRDATAFIPS,
and SDATAFIPS. Because the symbols are real (but otherwise unused) data,
they can be treated as normal symbols for symbol table purposes and
don't need the same kind of special handling that runtime.text and
friends do.

Note that treating the FIPS text as starting at &go:textfipsstart and
ending at &go:textfipsend means that go:textfipsstart is included in
the verified data while go:textfipsend is not. That's fine: they are
only framing and neither strictly needs to be in the hash.

The new special symbols are created by [loadfips].

# FIPS Info Layout

Having collated the FIPS symbols, we need to compute the hash
and then leave both the expected hash and the FIPS address ranges
for the run-time check in crypto/internal/fips140/check.
We do that by creating a special symbol named go:fipsinfo of the form

	struct {
		sum   [32]byte
		self  uintptr // points to start of struct
		sects [4]struct{
			start uintptr
			end   uintptr
		}
	}

The crypto/internal/fips140/check uses linkname to access this symbol,
which is of course not included in the hash.

# FIPS Info Calculation

When using internal linking, [asmbfips] runs after writing the output
binary but before code-signing it. It reads the relevant sections
back from the output file, hashes them, and then writes the go:fipsinfo
content into the output file.

When using external linking, especially with -buildmode=pie, we cannot
predict the specific PLT index references that the linker will insert
into the FIPS code sections, so we must read the final linked executable
after external linking, compute the hash, and then write it back to the
executable in the go:fipsinfo sum field. [hostlinkfips] does this.
It finds go:fipsinfo easily because that symbol is given its own section
(.go.fipsinfo on ELF, __go_fipsinfo on Mach-O), and then it can use the
sections field to find the relevant parts of the executable, hash them,
and fill in sum.

Both [asmbfips] and [hostlinkfips] need the same hash calculation code.
The [fipsObj] type provides that calculation.

# Debugging

It is of course impossible to debug a mismatched hash directly:
two random 32-byte strings differ. For debugging, the linker flag
-fipso can be set to the name of a file (such as /tmp/fips.o)
where the linker will write the “FIPS object” that is being hashed.

There is also commented-out code in crypto/internal/fips140/check that
will write /tmp/fipscheck.o during the run-time verification.

When the hashes differ, the first step is to uncomment the
/tmp/fipscheck.o-writing code and then rebuild with
-ldflags=-fipso=/tmp/fips.o. Then when the hash check fails,
compare /tmp/fips.o and /tmp/fipscheck.o to find the differences.
*/

package ld

import (
	"bufio"
	"bytes"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
)

const enableFIPS = true

// FIPSSyms are the special FIPS section bracketing symbols.
var FIPSSyms = []struct {
	Name string
	Kind sym.SymKind
	Sym  loader.Sym
	Seg  *sym.Segment
}{
	{Name: "go:textfipsstart", Kind: sym.STEXTFIPSSTART, Seg: &Segtext},
	{Name: "go:textfipsend", Kind: sym.STEXTFIPSEND},
	{Name: "go:rodatafipsstart", Kind: sym.SRODATAFIPSSTART, Seg: &Segrodata},
	{Name: "go:rodatafipsend", Kind: sym.SRODATAFIPSEND},
	{Name: "go:noptrdatafipsstart", Kind: sym.SNOPTRDATAFIPSSTART, Seg: &Segdata},
	{Name: "go:noptrdatafipsend", Kind: sym.SNOPTRDATAFIPSEND},
	{Name: "go:datafipsstart", Kind: sym.SDATAFIPSSTART, Seg: &Segdata},
	{Name: "go:datafipsend", Kind: sym.SDATAFIPSEND},
}

// fipsinfo is the loader symbol for go:fipsinfo.
var fipsinfo loader.Sym

var FipsTextBuffer loader.Sym

const (
	fipsMagic    = "\xff Go fipsinfo \xff\x00"
	FIPSMagicLen = 16
	fipsSumLen   = 32
)

// loadfips creates the special bracketing symbols and go:fipsinfo.
func loadfips(ctxt *Link) {
	if !obj.EnableFIPS() {
		return
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return
	}
	// Write the fipsinfo symbol, which crypto/internal/fips140/check uses.
	ldr := ctxt.loader

	// Wasm uses an alternate way of verifying the text bytestream. See [wasmFips] and cmd/link/internal/wasm.asmbfips
	if ctxt.IsWasm() {
		FIPSSyms[0].Seg = &Segdata
		FIPSSyms[0].Kind = sym.SNOPTRBSS
		FIPSSyms[1].Kind = sym.SNOPTRBSS

	}
	// TODO lock down linkname
	info := ldr.CreateSymForUpdate("go:fipsinfo", 0)
	info.SetType(sym.SFIPSINFO)

	data := make([]byte, FIPSMagicLen+fipsSumLen)
	copy(data, fipsMagic)
	info.SetData(data)
	info.SetSize(int64(len(data)))      // magic + checksum, to be filled in
	info.AddAddr(ctxt.Arch, info.Sym()) // self-reference

	for i := range FIPSSyms {
		s := &FIPSSyms[i]
		sb := ldr.CreateSymForUpdate(s.Name, 0)
		sb.SetType(s.Kind)
		sb.SetLocal(true)
		sb.SetSize(1)
		s.Sym = sb.Sym()
		// Grab the start symbol for the shadow text.
		// we will change the size later in [wasmFips]
		if s.Name == "go:textfipsstart" {
			FipsTextBuffer = s.Sym
		}
		info.AddAddr(ctxt.Arch, s.Sym)
		if s.Kind == sym.STEXTFIPSSTART || s.Kind == sym.STEXTFIPSEND {
			ctxt.Textp = append(ctxt.Textp, s.Sym)
		}
	}

	fipsinfo = info.Sym()
}

// fipsObj calculates the fips object hash and optionally writes
// the hashed content to a file for debugging.
type fipsObj struct {
	w   io.Writer
	wf  *os.File
	h   hash.Hash
	tmp [8]byte
}

// newFipsObj creates a fipsObj reading from r and writing to fipso
// (unless fipso is the empty string, in which case it writes nowhere
// and only computes the hash).
func newFipsObj(fipso string) (*fipsObj, error) {
	f := new(fipsObj)
	f.h = hmac.New(sha256.New, make([]byte, 32))
	f.w = f.h
	if fipso != "" {
		wf, err := os.Create(fipso)
		if err != nil {
			return nil, err
		}
		f.wf = wf
		f.w = io.MultiWriter(f.h, wf)
	}

	if _, err := f.w.Write([]byte("go fips object v1\n")); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// addSection adds the section of r (passed to newFipsObj)
// starting at byte offset start and ending before byte offset end
// to the fips object file.
func (f *fipsObj) addSection(r io.ReaderAt, start, end int64) error {
	n := end - start
	binary.BigEndian.PutUint64(f.tmp[:], uint64(n))
	f.w.Write(f.tmp[:])
	_, err := io.Copy(f.w, io.NewSectionReader(r, start, n))
	return err
}

// sum returns the hash of the fips object file.
func (f *fipsObj) sum() []byte {
	return f.h.Sum(nil)
}

// Close closes the fipsObj. In particular it closes the output
// object file specified by fipso in the call to [newFipsObj].
func (f *fipsObj) Close() error {
	if f.wf != nil {
		return f.wf.Close()
	}
	return nil
}

// asmbfips is called from [asmb] to update go:fipsinfo
// when using internal linking.
// See [hostlinkfips] for external linking.
func asmbfips(ctxt *Link, fipso string) {
	if !obj.EnableFIPS() {
		return
	}
	if ctxt.LinkMode == LinkExternal {
		return
	}
	// wasm has its own fips assembly function. See wasmFips below
	// and asmbfips in cmd/link/internal/wasm for more info
	if ctxt.IsWasm() {
		return
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return
	}

	// Create a new FIPS object with data read from our output file.
	out := bytes.NewReader(ctxt.Out.Data())
	secs := make([]*FipsSection, 0, len(FIPSSyms)/2)

	// Add the FIPS sections to the FIPS object.
	ldr := ctxt.loader
	for i := 0; i < len(FIPSSyms); i += 2 {
		start := &FIPSSyms[i]
		end := &FIPSSyms[i+1]
		startAddr := ldr.SymValue(start.Sym)
		endAddr := ldr.SymValue(end.Sym)
		seg := start.Seg
		if seg.Vaddr == 0 && seg == &Segrodata { // some systems use text instead of separate rodata
			seg = &Segtext
		}
		base := int64(seg.Fileoff - seg.Vaddr)
		if !(seg.Vaddr <= uint64(startAddr) && startAddr <= endAddr && uint64(endAddr) <= seg.Vaddr+seg.Filelen) {
			Errorf("asmbfips: %s not in expected segment (%#x..%#x not in %#x..%#x)", start.Name, startAddr, endAddr, seg.Vaddr, seg.Vaddr+seg.Filelen)
			return
		}
		secs = append(secs, &FipsSection{
			Section: out,
			Start:   startAddr + base,
			End:     endAddr + base,
		})

	}
	sum, err := FipsSum(secs, fipso)
	if err != nil {
		Errorf("asmbfips: %v", err)
		return
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	addr := uint64(ldr.SymValue(fipsinfo))
	seg := &Segdata
	if !(seg.Vaddr <= addr && addr+32 < seg.Vaddr+seg.Filelen) {
		Errorf("asmbfips: fipsinfo not in expected segment (%#x..%#x not in %#x..%#x)", addr, addr+32, seg.Vaddr, seg.Vaddr+seg.Filelen)
		return
	}
	ctxt.Out.SeekSet(int64(seg.Fileoff + addr - seg.Vaddr + FIPSMagicLen))
	ctxt.Out.Write(sum)

}

type FipsSection struct {
	Section io.ReaderAt
	Start   int64
	End     int64
}

func FipsSum(sections []*FipsSection, fipso string) ([]byte, error) {
	f, err := newFipsObj(fipso)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	for _, s := range sections {
		err := f.addSection(s.Section, s.Start, s.End)
		if err != nil {
			return nil, err
		}
	}
	return f.sum(), nil
}

// hostlinkfips is called from [hostlink] to update go:fipsinfo
// when using external linking.
// See [asmbfips] for internal linking.
func hostlinkfips(ctxt *Link, exe, fipso string) error {
	if !obj.EnableFIPS() {
		return nil
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return nil
	}
	switch {
	case ctxt.IsElf():
		return elffips(ctxt, exe, fipso)
	case ctxt.HeadType == objabi.Hdarwin:
		return machofips(ctxt, exe, fipso)
	case ctxt.HeadType == objabi.Hwindows:
		return pefips(ctxt, exe, fipso)
	}

	// If we can't do FIPS, leave the output binary alone.
	// If people enable FIPS the init-time check will fail,
	// but the binaries will work otherwise.
	return fmt.Errorf("fips unsupported on %s", ctxt.HeadType)
}

// machofips updates go:fipsinfo after external linking
// on systems using Mach-O (GOOS=darwin, GOOS=ios).
func machofips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading Mach-O and for the fipsObj.
	mf, err := macho.Open(exe)
	if err != nil {
		return err
	}
	defer mf.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	// Find the go:fipsinfo symbol.
	sect := mf.Section("__go_fipsinfo")
	if sect == nil {
		return fmt.Errorf("cannot find __go_fipsinfo")
	}
	data, err := sect.Data()
	if err != nil {
		return err
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// On Mac, the debug/macho package is not reporting any relocations,
	// but the addends are all in the data already, all relative to
	// the same base.
	// Determine the base used for the self pointer, and then apply
	// that base to the other uintptrs.
	// The very high bits of the uint64s seem to be relocation metadata,
	// so clear them.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	const addendMask = 1<<48 - 1
	data = data[FIPSMagicLen+fipsSumLen:]
	self := int64(uptr(data)) & addendMask
	base := int64(sect.Offset) - self
	data = data[ctxt.Arch.PtrSize:]

	secs := make([]*FipsSection, 4)
	for i := 0; i < 4; i++ {
		start := int64(uptr(data[0:]))&addendMask + base
		end := int64(uptr(data[ctxt.Arch.PtrSize:]))&addendMask + base
		data = data[2*ctxt.Arch.PtrSize:]
		secs[i] = &FipsSection{
			Section: wf,
			Start:   start,
			End:     end,
		}
	}
	sum, err := FipsSum(secs, fipso)
	if err != nil {
		return err
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(sum, int64(sect.Offset)+FIPSMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return nil
}

// elffips updates go:fipsinfo after external linking
// on systems using ELF (most Unix systems).
func elffips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading ELF and for the fipsObj.
	ef, err := elf.Open(exe)
	if err != nil {
		return err
	}
	defer ef.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	// Find the go:fipsinfo symbol.
	sect := ef.Section(".go.fipsinfo")
	if sect == nil {
		return fmt.Errorf("cannot find .go.fipsinfo")
	}

	data, err := sect.Data()
	if err != nil {
		return err
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// We expect R_zzz_RELATIVE relocations where the zero-based
	// values are already stored in the data. That is, the addend
	// is in the data itself in addition to being in the relocation tables.
	// So no need to parse the relocation tables unless we find a
	// toolchain that doesn't initialize the data this way.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	data = data[FIPSMagicLen+fipsSumLen:]
	data = data[ctxt.Arch.PtrSize:]

	secs := make([]*FipsSection, 4)
Addrs:
	for i := 0; i < 4; i++ {
		start := uptr(data[0:])
		end := uptr(data[ctxt.Arch.PtrSize:])
		data = data[2*ctxt.Arch.PtrSize:]
		for _, prog := range ef.Progs {
			if prog.Type == elf.PT_LOAD && prog.Vaddr <= start && start <= end && end <= prog.Vaddr+prog.Filesz {
				secs[i] = &FipsSection{
					Section: wf,
					Start:   int64(start + prog.Off - prog.Vaddr),
					End:     int64(end + prog.Off - prog.Vaddr),
				}
				continue Addrs
			}
		}
		return fmt.Errorf("invalid pointers found in .go.fipsinfo")
	}
	sum, err := FipsSum(secs, fipso)
	if err != nil {
		return err
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(sum, int64(sect.Offset)+FIPSMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return nil
}

// pefips updates go:fipsinfo after external linking
// on systems using PE (GOOS=windows).
func pefips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading Mach-O and for the fipsObj.
	pf, err := pe.Open(exe)
	if err != nil {
		return err
	}
	defer pf.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	// Find the go:fipsinfo symbol.
	// PE does not put it in its own section, so we have to scan for it.
	// It is near the start of the data segment, right after go:buildinfo,
	// so we should not have to scan too far.
	const maxScan = 16 << 20
	sect := pf.Section(".data")
	if sect == nil {
		return fmt.Errorf("cannot find .data")
	}
	b := bufio.NewReader(sect.Open())
	off := int64(0)
	data := make([]byte, FIPSMagicLen+fipsSumLen+9*ctxt.Arch.PtrSize)
	for ; ; off += 16 {
		if off >= maxScan {
			break
		}
		if _, err := io.ReadFull(b, data[:FIPSMagicLen]); err != nil {
			return fmt.Errorf("scanning PE for FIPS magic: %v", err)
		}
		if string(data[:FIPSMagicLen]) == fipsMagic {
			if _, err := io.ReadFull(b, data[FIPSMagicLen:]); err != nil {
				return fmt.Errorf("scanning PE for FIPS magic: %v", err)
			}
			break
		}
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// Determine the base used for the self pointer, and then apply
	// that base to the other uintptrs.
	// For pie builds, the addends are in the data.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	data = data[FIPSMagicLen+fipsSumLen:]
	self := int64(uptr(data))
	data = data[ctxt.Arch.PtrSize:]

	// On 64-bit binaries the pointers have extra bits set
	// that don't appear in the actual section headers.
	// For example, one generated test binary looks like:
	//
	//	.data VirtualAddress = 0x2af000
	//	.data (file) Offset = 0x2ac400
	//	.data (file) Size = 0x1fc00
	//	go:fipsinfo found at offset 0x2ac5e0 (off=0x1e0)
	//	go:fipsinfo self pointer = 0x01402af1e0
	//
	// From the section headers, the address of the go:fipsinfo symbol
	// should be 0x2af000 + (0x2ac5e0 - 0x2ac400) = 0x2af1e0,
	// yet in this case its pointer is 0x1402af1e0, meaning the
	// data section's VirtualAddress is really 0x1402af000.
	// This is not (only) a 32-bit truncation problem, since the uint32
	// truncation of that address would be 0x402af000, not 0x2af000.
	// Perhaps there is some 64-bit extension that debug/pe is not
	// reading or is misreading. In any event, we can derive the delta
	// between computed VirtualAddress and listed VirtualAddress
	// and apply it to the rest of the pointers.
	// As a sanity check, the low 12 bits (virtual page offset)
	// must match between our computed address and the actual one.
	peself := int64(sect.VirtualAddress) + off
	if self&0xfff != off&0xfff {
		return fmt.Errorf("corrupt pointer found in go:fipsinfo")
	}
	delta := peself - self

	secs := make([]*FipsSection, 4)
Addrs:
	for i := 0; i < 4; i++ {
		start := int64(uptr(data[0:])) + delta
		end := int64(uptr(data[ctxt.Arch.PtrSize:])) + delta
		data = data[2*ctxt.Arch.PtrSize:]
		for _, sect := range pf.Sections {
			if int64(sect.VirtualAddress) <= start && start <= end && end <= int64(sect.VirtualAddress)+int64(sect.Size) {
				off := int64(sect.Offset) - int64(sect.VirtualAddress)
				secs[i] = &FipsSection{
					Section: wf,
					Start:   start + off,
					End:     end + off,
				}
				continue Addrs
			}
		}
		return fmt.Errorf("invalid pointers found in go:fipsinfo")
	}
	sum, err := FipsSum(secs, fipso)
	if err != nil {
		return err
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(sum, int64(sect.Offset)+off+FIPSMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return nil
}

func wasmFips(ctxt *Link) {
	// The text bytestream needs to be hashed for FIPS140-3
	// support. On other platforms, text gets loaded into the
	// same memory space as data, but on Wasm, we can't inspect our
	// own text. Instead, when a Wasm binary is loaded, we copy the text
	// into a buffer that the verifying process can inspect.
	//
	// Allocating the buffer will change the offsets in the text
	// stream, so we need to allocate it before we start writing
	// out function bodies. Wasm relocations are variable sized,
	// so we won't know how big the buffer will be until we start
	// writing out bodies.
	//
	// Solve this chicken and egg problem by estimating the largest
	// our FIPS text can be. When we get the actual data, we just
	// leave the remainder as zeroes and hash those as well.
	//
	// TODO(dmo): we allocate the fips section last, so the offsets shouldn't
	// change by it changing size after we write out the code segment. We might
	// be able to use a buffer that's exactly right sized.

	// The buffer does have some cost associated with it, so only construct it
	// if we're building a binary with GOFIPS140 set. The go tool sets the fipso
	// flag, so discover it via that.
	if *FlagFipso == "" {
		return
	}

	ldr := ctxt.loader
	size := int64(0)
	const maxUleb128Size = 10
	for _, fn := range ctxt.Textp {
		if ldr.SymType(fn) != sym.STEXTFIPS {
			continue
		}
		// text
		fnsize := int64(len(ldr.Data(fn)))
		// index
		fnsize += maxUleb128Size
		// each relocation
		relocs := ldr.Relocs(fn)
		fnsize += int64(relocs.Count()) * maxUleb128Size
		size += fnsize
	}
	up := ctxt.loader.MakeSymbolUpdater(FipsTextBuffer)
	up.SetSize(size)
}
