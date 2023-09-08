package elf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/andreistan26/golink/pkg/log"
)

//go:generate stringer -type STT,STB,ElfClass,ElfData,ElfOsAbi,ET,SHT_TYPE,SHT_FLAGS -output elf_string.go

/*
   The following structures and interface are documented by https://www.uclibc.org/docs/elf-64-gen.pdf
*/

const (
	SHN_UNDEF = 0

	SHN_LORESERVE = 0
	SHN_ABS       = 0xfff1
	SHN_COMMON    = 0xfff2
	SHN_XINDEX    = 0xffff
)

type STT byte

const (
	STT_NOTYPE  STT = iota // 0
	STT_OBJECT             // 1
	STT_FUNC               // 2
	STT_SECTION            // 3
	STT_FILE               // 4

	STT_LOOS   STT = 10
	STT_HIOS   STT = 12
	STT_LOPROC STT = 13
	STT_HIPROC STT = 15
)

type STB byte

const (
	STB_LOCAL  STB = iota // 0
	STB_GLOBAL            // 1
	STB_WEAK              // 2
	STB_LOOS   STB = 10   // 10
	STB_HIOS   STB = 12   // 12
	STB_LOPROC STB = 13   // 13
	STB_HIPROC STB = 15   // 15
)

const (
	EI_MAG0       = 0
	EI_MAG1       = 1
	EI_MAG2       = 2
	EI_MAG3       = 3
	EI_CLASS      = 4
	EI_DATA       = 5
	EI_VERSION    = 6
	EI_OSABI      = 7
	EI_ABIVERSION = 8
	EI_PAD        = 9
	EI_NIDENT     = 16
)

type ElfClass uint32

const (
	ELFCLASS32 ElfClass = iota + 1 // 1
	ELFCLASS64                     // 2
)

type ElfData uint32

const (
	ELFDATA2LSB ElfData = iota + 1 // 1
	ELFDATA2MSB                    // 2
)

type ElfOsAbi byte

const (
	ELFOSABI_SYSV ElfOsAbi = iota
	ELFOSABI_HPUX
	ELFOSABI_STANDALONE ElfOsAbi = 255
)

// Type of ELF file
type ET uint32

const (
	ET_NONE ET = iota

	// Relocatable object file
	ET_REL // 1

	// Executable file
	ET_EXEC // 2

	// Shared object file
	ET_DYN // 3

	ET_CORE      // 4
	ET_LOOS   ET = 0xFE00
	ET_HIOS   ET = 0xFEFF
	ET_LOPROC ET = 0xFF00
	ET_HIPROC ET = 0xFFFF
)

type SHT_TYPE uint32

const (
	SHT_NULL     SHT_TYPE = iota // 0
	SHT_PROGBITS                 // 1
	SHT_SYMTAB                   // 2
	SHT_STRTAB                   // 3
	SHT_RELA                     // 4
	SHT_HASH                     // 5
	SHT_DYNAMIC                  // 6
	SHT_NOTE                     // 7
	SHT_NOBITS                   // 8
	SHT_REL                      // 9
	SHT_SHLIB                    // 10
	SHT_DYNSYM                   // 11
	SHT_LOOS     SHT_TYPE = 0x60000000
	SHT_HIOS     SHT_TYPE = 0x6FFFFFFF
	SHT_LOPROC   SHT_TYPE = 0x70000000
	SHT_HIPROC   SHT_TYPE = 0x70000000
)

type SHT_FLAGS uint64

const (
	SHF_WRITE            SHT_FLAGS = 1 << iota //0x1
	SHF_ALLOC                                  // 0x2
	SHF_EXECINSTR                              // 0x4
	SHF_MERGE                                  // 0x10
	SHF_STRINGS                                // 0x20
	SHF_INFO_LINK                              // 0x40
	SHF_LINK_ORDER                             // 0x80
	SHF_OS_NONCONFORMING                       // 0x100
	SHF_GROUP                                  // 0x200
	SHF_TLS                                    // 0x400

	SHF_MASKOS   SHT_FLAGS = 0x0F000000
	SHF_MASKPROC SHT_FLAGS = 0xF0000000
)

const (
	PT_NULL    = 0
	PT_LOAD    = 1
	PT_DYNAMIC = 2
	PT_INTERP  = 3
	PT_NOTE    = 4
	PT_SHLIB   = 5
	PT_PHDR    = 6
	PT_LOOS    = 0x60000000
	PT_HIOS    = 0x6FFFFFFF
	PT_LOPROC  = 0x70000000
	PT_HIPROC  = 0x7FFFFFFF
)

const (
	PF_X        = 0x1
	PF_W        = 0x2
	PF_R        = 0x4
	PF_MASKOS   = 0x00FF0000
	PF_MASKPROC = 0xFF000000
)

var (
	InvalidMagicErr = errors.New("Invalid magic in ELF file.")
	UnparsedELFErr  = errors.New("ELF header was not parsed.")
)

type ELF64Sym struct {
	// string table offset
	StName uint32

	// Type and Binding
	StInfo byte

	// Padding
	StOther byte

	// section header index
	StShNdx uint16

	// offset within the section refered to StShNdx
	StValue uint64

	// object size
	StSize uint64
}

func (sym *ELF64Sym) IsSpecialSection() bool {
	return find[uint16]([]uint16{SHN_ABS, SHN_COMMON, SHN_LORESERVE, SHN_XINDEX}, sym.StShNdx) != -1
}

func (sym ELF64Sym) String() string {
	return fmt.Sprintf(
		"StName:    %v\n"+
			"StInfo:    %v\n"+
			"Binding:   %v\n"+
			"Type:      %v\n"+
			"StOther:   %v\n"+
			"StShNdx:   %v\n"+
			"StValue:   %v\n"+
			"StSize:    %v\n",
		sym.StName, sym.StInfo,
		sym.GetBinding(), sym.GetType(),
		sym.StOther, sym.StShNdx,
		sym.StValue, sym.StSize,
	)
}

type ELF64Ehdr struct {
	Ident     [16]byte // ELF identification
	Type      ET       // Object file type
	Machine   uint16   // Machine type
	Version   uint32   // Object file version
	Entry     uint64   // Entry point address
	PhOff     uint64   // Program Header offset
	ShOff     uint64   // Section Header offset
	Flags     uint32   // Processor specific flags
	EhSize    uint16   // ELF Header size
	PhEntSize uint16   // Size of Program Header
	PhNum     uint16   // Number of program header entries
	ShEntSize uint16   // Size of the Section Header entry
	ShNum     uint16   // Number of Section Header entries
	ShStrNdx  uint16   // Section name String Table index
}

func (ehdr ELF64Ehdr) String() string {
	return fmt.Sprintf(
		"Ident:     %v\n"+
			"Type:      %v\n"+
			"Machine:   %v\n"+
			"Version:   %v\n"+
			"Entry:     %v\n"+
			"PhOff:     %v\n"+
			"ShOff:     %v\n"+
			"Flags:     %v\n"+
			"EhSize:    %v\n"+
			"PhEntSize: %v\n"+
			"PhNum:     %v\n"+
			"ShEntSize: %v\n"+
			"ShNum:     %v\n"+
			"ShStrNdx:  %v\n",
		ehdr.Ident, ehdr.Type, ehdr.Machine,
		ehdr.Version, ehdr.Entry, ehdr.PhOff,
		ehdr.ShOff, ehdr.Flags, ehdr.EhSize,
		ehdr.PhEntSize, ehdr.PhNum, ehdr.ShEntSize,
		ehdr.ShNum, ehdr.ShStrNdx,
	)
}

func (shdr ELF64Shdr) String() string {
	return fmt.Sprintf(
		"Addr:      %v\n"+
			"AddrAlign: %v\n"+
			"EntSize:   %v\n"+
			"Flags:     %v\n"+
			"Info:      %v\n"+
			"Link:      %v\n"+
			"Name:      %v\n"+
			"Off:       %v\n"+
			"Size:      %v\n"+
			"Type:      %v\n",
		shdr.ShAddr, shdr.ShAddrAlign, shdr.ShEntSize,
		shdr.ShFlags, shdr.ShInfo, shdr.ShLink,
		shdr.ShName, shdr.ShOff, shdr.ShSize, shdr.ShType,
	)
}

func (elf64Ehdr *ELF64Ehdr) VerifyMagic() error {
	if !reflect.DeepEqual(elf64Ehdr.Ident[EI_MAG0:EI_CLASS], []byte{'\x7f', 'E', 'L', 'F'}) {
		return InvalidMagicErr
	}

	return nil
}

func (elf64Ehdr *ELF64Ehdr) Parse(elfDump []byte) error {
	const ELF_64_EHdr_SIZE = 64

	if len(elfDump) < ELF_64_EHdr_SIZE {
		return errors.New("ELF Header size is bigger than the data provided")
	}

	*elf64Ehdr = ELF64Ehdr{
		Type:      ET(binary.LittleEndian.Uint16(elfDump[0x10:0x12])),
		Machine:   binary.LittleEndian.Uint16(elfDump[0x12:0x14]),
		Version:   binary.LittleEndian.Uint32(elfDump[0x14:0x18]),
		Entry:     binary.LittleEndian.Uint64(elfDump[0x18:0x20]),
		PhOff:     binary.LittleEndian.Uint64(elfDump[0x20:0x28]),
		ShOff:     binary.LittleEndian.Uint64(elfDump[0x28:0x30]),
		Flags:     binary.LittleEndian.Uint32(elfDump[0x30:0x34]),
		EhSize:    binary.LittleEndian.Uint16(elfDump[0x34:0x36]),
		PhEntSize: binary.LittleEndian.Uint16(elfDump[0x36:0x38]),
		PhNum:     binary.LittleEndian.Uint16(elfDump[0x38:0x3a]),
		ShEntSize: binary.LittleEndian.Uint16(elfDump[0x3a:0x3c]),
		ShNum:     binary.LittleEndian.Uint16(elfDump[0x3c:0x3e]),
		ShStrNdx:  binary.LittleEndian.Uint16(elfDump[0x3e:0x40]),
	}

	copy(elf64Ehdr.Ident[:], elfDump[0:16])

	return nil
}

func (elf64Ehdr *ELF64Ehdr) checkParsed() error {
	if len(elf64Ehdr.Ident) != 16 {
		return UnparsedELFErr
	}

	return nil
}

func (elf64Ehdr *ELF64Ehdr) GetClass() (ElfClass, error) {
	if err := elf64Ehdr.checkParsed(); err != nil {
		return 0, err
	}

	if elf64Ehdr.Ident[EI_CLASS] == 1 {
		return 0, errors.New("ELF32 is not supported.")
	}

	return ELFCLASS64, nil
}

func (elf64Ehdr *ELF64Ehdr) GetEndianess() (ElfData, error) {
	if err := elf64Ehdr.checkParsed(); err != nil {
		return 0, err
	}

	if elf64Ehdr.Ident[EI_DATA] == 1 {
		return 0, errors.New("Big endianess not supported")
	}

	return ELFDATA2LSB, nil
}

func (elf64Ehdr *ELF64Ehdr) GetVersion() (uint32, error) {
	if err := elf64Ehdr.checkParsed(); err != nil {
		return 0, err
	}

	return uint32(elf64Ehdr.Ident[EI_VERSION]), nil
}

func (elf64Ehdr *ELF64Ehdr) GetOsABI() (ElfOsAbi, error) {
	if err := elf64Ehdr.checkParsed(); err != nil {
		return 0, err
	}

	return ElfOsAbi(elf64Ehdr.Ident[EI_OSABI]), nil
}

func (elf64Ehdr *ELF64Ehdr) GetABIVersion() (uint32, error) {
	if err := elf64Ehdr.checkParsed(); err != nil {
		return 0, err
	}

	return uint32(elf64Ehdr.Ident[EI_ABIVERSION]), nil
}

// Section header entries
type ELF64Shdr struct {
	ShName      uint32    // offset to the section name relative to section name table
	ShType      SHT_TYPE  // section type
	ShFlags     SHT_FLAGS //
	ShAddr      uint64
	ShOff       uint64
	ShSize      uint64
	ShLink      uint32
	ShInfo      uint32
	ShAddrAlign uint64
	ShEntSize   uint64
}

func (entry ELF64Shdr) StringFlag() string {
	str := ""
	for i := uint64(1); i <= uint64(SHF_MASKPROC); i = i << 1 {
		if i&uint64(entry.ShFlags) != 0 {
			str = fmt.Sprintf("%s%v", str, SHT_FLAGS(i))
		}
	}
	return str
}

type ELF64Rel struct {
	Offset uint64
	Info   uint64
}

type ELF64Rela struct {
	Offset uint64
	Info   uint64
	Addend uint64
}

type ELF64Phdr struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64 // padding
	FileSz uint64
	MemSz  uint64
	Align  uint64
}

type Symbol struct {
	BaseSymbol *ELF64Sym
	Name       string
}

type Section struct {
	SectionEntry *ELF64Shdr
	Data         []byte
	Symbols      []*Symbol
	Name         string
}

type ELF64 struct {
	Filename string
	File     *os.File

	Header      ELF64Ehdr
	PhdrEntries []ELF64Phdr

	Symbols  []*Symbol
	Sections []*Section
}

func (elf *ELF64) ParseShdr(elfDump []byte) error {
	if err := elf.Header.checkParsed(); err != nil {
		return err
	}

	entryOffset := elf.Header.ShOff

	// Section Header String Table offset
	strTabEntOff := 0x40*uint64(elf.Header.ShStrNdx) + entryOffset
	off := binary.LittleEndian.Uint64(elfDump[strTabEntOff+0x18 : strTabEntOff+0x20])

	// The first section is always null
	for entryNdx := uint16(0); entryNdx <= elf.Header.ShNum; entryNdx++ {
		entry := &ELF64Shdr{}
		entry.ShName = binary.LittleEndian.Uint32(elfDump[entryOffset : entryOffset+4])
		entry.ShType = SHT_TYPE(binary.LittleEndian.Uint32(elfDump[entryOffset+0x04 : entryOffset+0x08]))
		entry.ShFlags = SHT_FLAGS(binary.LittleEndian.Uint64(elfDump[entryOffset+0x08 : entryOffset+0x10]))
		entry.ShAddr = binary.LittleEndian.Uint64(elfDump[entryOffset+0x10 : entryOffset+0x18])
		entry.ShOff = binary.LittleEndian.Uint64(elfDump[entryOffset+0x18 : entryOffset+0x20])
		entry.ShSize = binary.LittleEndian.Uint64(elfDump[entryOffset+0x20 : entryOffset+0x28])
		entry.ShLink = binary.LittleEndian.Uint32(elfDump[entryOffset+0x28 : entryOffset+0x2c])
		entry.ShInfo = binary.LittleEndian.Uint32(elfDump[entryOffset+0x2c : entryOffset+0x30])
		entry.ShAddrAlign = binary.LittleEndian.Uint64(elfDump[entryOffset+0x30 : entryOffset+0x38])
		entry.ShEntSize = binary.LittleEndian.Uint64(elfDump[entryOffset+0x38 : entryOffset+0x40])

		nullByteNdx := find[byte](elfDump[off+uint64(entry.ShName):], 0)
		sectionName := string(elfDump[off+uint64(entry.ShName) : off+uint64(entry.ShName)+uint64(nullByteNdx)])

		entryData := make([]byte, entry.ShSize)
		copy(entryData, elfDump[entry.ShOff:entry.ShOff+entry.ShSize])
		sectionDump := &Section{
			SectionEntry: entry,
			Data:         entryData,
			Symbols:      []*Symbol{},
			Name:         sectionName,
		}

		elf.Sections = append(elf.Sections, sectionDump)

		log.Debugf("%s: %s\n", sectionName, entry.StringFlag())

		entryOffset += 0x40
	}

	return nil
}

func find[T comparable](s []T, x T) int {
	for ndx, val := range s {
		if x == val {
			return ndx
		}
	}

	return -1
}

func (sym *Symbol) IsLocal() bool {
	return sym.BaseSymbol.GetBinding() == STB_LOCAL
}

func (elf *ELF64) ParseSymTable(elfDump []byte) error {
	var symtab *ELF64Shdr
	var strtab *ELF64Shdr

	// find string table
	for _, section := range elf.Sections {
		if section.SectionEntry.ShType == SHT_SYMTAB {
			symtab = section.SectionEntry
		} else if section.Name == ".strtab" {
			strtab = section.SectionEntry
		}
	}

	if symtab == nil {
		return errors.New("No symbol table found")
	}

	if strtab == nil {
		return errors.New("No string table found")
	}

	// parse each symbol
	for offset := symtab.ShOff; offset < symtab.ShOff+symtab.ShSize; offset += 0x18 {
		symbol := &Symbol{}
		symbol.BaseSymbol = &ELF64Sym{
			StName:  binary.LittleEndian.Uint32(elfDump[offset : offset+0x04]),
			StInfo:  elfDump[offset+0x04],
			StOther: elfDump[offset+0x05],
			StShNdx: binary.LittleEndian.Uint16(elfDump[offset+0x06 : offset+0x08]),
			StValue: binary.LittleEndian.Uint64(elfDump[offset+0x08 : offset+0x10]),
			StSize:  binary.LittleEndian.Uint64(elfDump[offset+0x10 : offset+0x18]),
		}

		// search for the nullbyte
		nullByteNdx := find[byte](elfDump[strtab.ShOff+uint64(symbol.BaseSymbol.StName):], 0)

		if nullByteNdx != -1 {
			symbol.Name = string(elfDump[strtab.ShOff+uint64(symbol.BaseSymbol.StName) : uint64(strtab.ShOff)+uint64(symbol.BaseSymbol.StName)+uint64(nullByteNdx)])
		}

		if !symbol.BaseSymbol.IsSpecialSection() {
			elf.Sections[symbol.BaseSymbol.StShNdx].Symbols = append(elf.Sections[symbol.BaseSymbol.StShNdx].Symbols, symbol)
		}
		elf.Symbols = append(elf.Symbols, symbol)
	}

	return nil
}

func (sym ELF64Sym) GetType() STT {
	return STT(sym.StInfo & 0x0f)
}

func (sym ELF64Sym) GetBinding() STB {
	return STB(sym.StInfo&0xf0) >> 4
}

func NewELF(filepath string) (*ELF64, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1024*1024*1024)
	_, err = file.Read(buffer)
	if err != nil {
		return nil, err
	}

	elf := &ELF64{
		Filename: filepath,
		File:     file,
	}

	// Parse ELF header
	err = elf.Header.Parse(buffer)
	if err != nil {
		return nil, err
	}

	// Parse Section Header
	err = elf.ParseShdr(buffer)
	if err != nil {
		return nil, err
	}

	// Parse Symbol Table
	elf.ParseSymTable(buffer)
	if err != nil {
		return nil, err
	}

	return elf, nil
}
