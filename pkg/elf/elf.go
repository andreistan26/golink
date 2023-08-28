package elf

import (
	"encoding/binary"
	"errors"
	"reflect"
    "os"
)

/*
   The following structures and interface are documented by https://www.uclibc.org/docs/elf-64-gen.pdf
*/

type ELF64Sym struct {
    // string table offset
    StName  uint32

    // Type and Binding
    StInfo  byte
    
    // Padding
    StOther byte

    // section header index
    StShNdx uint16

    // section offset
    StValue uint64

    // object size
    StSize uint64
}

const (
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_LOOS = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15
)

const (
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_LOOS = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15
)

type ELF64Ehdr struct {
    Ident       [16]byte    // ELF identification
    Type        uint16      // Object file type
    Machine     uint16      // Machine type
    Version     uint32      // Object file version
    Entry       uint64      // Entry point address
    PhOff       uint64      // Program Header offset
    ShOff       uint64      // Section Header offset
    Flags       uint32      // Processor specific flags
    EhSize      uint16      // ELF Header size
    PhEntSize   uint16      // Size of Program Header
    PhNum       uint16      // Number of program header entries
    ShEntSize   uint16      // Size of the Section Header entry
    ShNum       uint16      // Number of Section Header entries
    ShStrNdx    uint16      // Section name String Table index
}

const (
    EI_MAG0         = 0
    EI_MAG1         = 1
    EI_MAG2         = 2
    EI_MAG3         = 3
    EI_CLASS        = 4 
    EI_DATA         = 5
    EI_VERSION      = 6
    EI_OSABI        = 7
    EI_ABIVERSION   = 8
    EI_PAD          = 9
    EI_NIDENT       = 16
)

var (
    InvalidMagicErr = errors.New("Invalid magic in ELF file.")
    UnparsedELFErr = errors.New("ELF header was not parsed.")
)

func (elf64Ehdr *ELF64Ehdr) VerifyMagic() error {
    if !reflect.DeepEqual(elf64Ehdr.Ident[EI_MAG0:EI_CLASS], []byte {'\x7f', 'E', 'L', 'F'}) {
        return InvalidMagicErr 
    }

    return nil
}

func ParseHeader(elfDump []byte) (ELF64Ehdr, error) {
    const ELF_64_EHdr_SIZE = 64

    if len(elfDump) < ELF_64_EHdr_SIZE {
        return ELF64Ehdr{}, errors.New("ELF Header size is bigger than the data provided")
    }
    
    elf64Ehdr := ELF64Ehdr {
        Type: binary.LittleEndian.Uint16(elfDump[0x10:0x12]),
        Machine: binary.LittleEndian.Uint16(elfDump[0x12:0x14]),   
        Version: binary.LittleEndian.Uint32(elfDump[0x14:0x18]),
        Entry: binary.LittleEndian.Uint64(elfDump[0x18:0x20]),
        PhOff: binary.LittleEndian.Uint64(elfDump[0x20:0x28]),
        ShOff: binary.LittleEndian.Uint64(elfDump[0x28:0x30]),
        Flags: binary.LittleEndian.Uint32(elfDump[0x30:0x34]),
        EhSize: binary.LittleEndian.Uint16(elfDump[0x34:0x36]),
        PhEntSize: binary.LittleEndian.Uint16(elfDump[0x36:0x38]),
        PhNum: binary.LittleEndian.Uint16(elfDump[0x38:0x3a]),
        ShEntSize: binary.LittleEndian.Uint16(elfDump[0x3a:0x3c]),
        ShNum:binary.LittleEndian.Uint16(elfDump[0x3c:0x3e]),
        ShStrNdx: binary.LittleEndian.Uint16(elfDump[0x3e:0x40]),
    }

    copy(elf64Ehdr.Ident[:], elfDump[0:16])

    return elf64Ehdr, nil
}

const (
    ELFCLASS32 uint32 = 1
    ELFCLASS64 = 2
)

const (
    ELFDATA2LSB uint32 = 1
    ELFDATA2MSB = 2
)

const (
    ELFOSABI_SYSV = 0
    ELFOSABI_HPUX = 1
    ELFOSABI_STANDALONE = 255
)

// Type of ELF file
const (
    ET_NONE uint32 = 0

    // Relocatable object file
    ET_REL      = 1

    // Executable file
    ET_EXEC     = 2

    // Shared object file
    ET_DYN      = 3

    ET_CORE     = 4
    ET_LOOS     = 0xFE00
    ET_HIOS     = 0xFEFF
    ET_LOPROC   = 0xFF00
    ET_HIPROC   = 0xFFFF
)

func (elf64Ehdr *ELF64Ehdr) checkParsed() (error) {
    if len(elf64Ehdr.Ident) != 16 {
        return UnparsedELFErr
    }

    return nil
}

func (elf64Ehdr *ELF64Ehdr) GetClass() (uint32, error) {
    if err := elf64Ehdr.checkParsed(); err != nil {
        return 0, err
    }

    if elf64Ehdr.Ident[EI_CLASS] == 1 {
        return 0, errors.New("ELF32 is not supported.")
    }

    return ELFCLASS64, nil    
}

func (elf64Ehdr *ELF64Ehdr) GetEndianess() (uint32, error) {
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

func (elf64Ehdr *ELF64Ehdr) GetOsABI() (uint32, error) {
    if err := elf64Ehdr.checkParsed(); err != nil {
        return 0, err
    }

    return uint32(elf64Ehdr.Ident[EI_OSABI]), nil
}

func (elf64Ehdr *ELF64Ehdr) GetABIVersion() (uint32, error) {
    if err := elf64Ehdr.checkParsed(); err != nil {
        return 0, err
    }

    return uint32(elf64Ehdr.Ident[EI_ABIVERSION]), nil 
}

// Section header entries
type ELF64Shdr struct {
    ShName  uint32 // offset to the section name relative to section name table
    ShType  uint32 // section type
    ShFlags uint64 // 
    ShAddr  uint64
    ShOff   uint64
    ShSize  uint64
    ShLink  uint32
    ShInfo  uint32
    ShAddrAlign uint64
    ShEntSize   uint64
}

const (
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_LOOS = 0x60000000
    SHT_HIOS = 0x6FFFFFFF
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x70000000
)

const (
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MASKOS = 0x0F000000
    SHF_MASKPROC = 0xF0000000
)

type ELF64Rel struct {
    Offset  uint64
    Info    uint64
}

type ELF64Rela struct {
    Offset  uint64
    Info    uint64
    Addend  uint64
}

type ELF64Phdr struct {
    Type    uint32
    Flags   uint32
    Offset  uint64
    Vaddr   uint64
    Paddr   uint64 // padding
    FileSz  uint64
    MemSz   uint64
    Align   uint64
}

const (
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4 
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_LOOS = 0x60000000
    PT_HIOS = 0x6FFFFFFF
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7FFFFFFF
)

const (
    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4
    PF_MASKOS = 0x00FF0000
    PF_MASKPROC = 0xFF000000
)

type ELF64 struct {
    Filename string
    File    *os.File

    Header ELF64Ehdr
    
    ShdrEntries [](*ELF64Shdr)
    PhdrEntries []ELF64Phdr

    Symbols     [](*ELF64Sym)
}

func (elf *ELF64) ParseShdr(elfDump []byte) error {
    if err := elf.Header.checkParsed(); err != nil {
        return err
    }

    entryOffset := elf.Header.ShOff + 0x40
    // The first section is always null
    for entryNdx := uint16(1) ; entryNdx < elf.Header.ShNum; entryNdx ++ {
        entry := &ELF64Shdr{}
        entry.ShName = binary.LittleEndian.Uint32(elfDump[entryOffset:entryOffset + 4])
        entry.ShType = binary.LittleEndian.Uint32(elfDump[entryOffset+0x04:entryOffset+0x08])
        entry.ShFlags = binary.LittleEndian.Uint64(elfDump[entryOffset+0x08:entryOffset+0x10])
        entry.ShAddr = binary.LittleEndian.Uint64(elfDump[entryOffset+0x10:entryOffset+0x18])
        entry.ShOff = binary.LittleEndian.Uint64(elfDump[entryOffset+0x18:entryOffset+0x20])
        entry.ShSize = binary.LittleEndian.Uint64(elfDump[entryOffset+0x20:entryOffset+0x28])
        entry.ShLink = binary.LittleEndian.Uint32(elfDump[entryOffset+0x28:entryOffset+0x2c])
        entry.ShInfo = binary.LittleEndian.Uint32(elfDump[entryOffset+0x2c:entryOffset+0x30])
        entry.ShAddrAlign = binary.LittleEndian.Uint64(elfDump[entryOffset+0x30:entryOffset+0x38])
        entry.ShEntSize = binary.LittleEndian.Uint64(elfDump[entryOffset+0x38:entryOffset+0x40])
        elf.ShdrEntries = append(elf.ShdrEntries, entry)
        entryOffset += 0x40
    }

    return nil
}

func (elf *ELF64) ParseSymTable(elfDump []byte) error {
    var symtab *ELF64Shdr

    for _, section := range elf.ShdrEntries {
        if section.ShType == SHT_SYMTAB {
            symtab = section
            break
        }
    }

    if symtab != nil {
        return errors.New("No symbol table found")
    }

    // parse each symbol
    for offset := symtab.ShOff; offset < symtab.ShOff + symtab.ShSize; offset += 0x18 {
        symbol := ELF64Sym {
            StName: binary.LittleEndian.Uint32(elfDump[offset:offset+0x04]),
            StInfo: elfDump[offset+0x04],
            StOther: elfDump[offset+0x05],
            StShNdx: binary.LittleEndian.Uint16(elfDump[offset+0x06:offset+0x08]),
            StValue: binary.LittleEndian.Uint64(elfDump[offset+0x08:offset+0x10]),
            StSize: binary.LittleEndian.Uint64(elfDump[offset+0x10:offset+0x18]),
        }

        elf.Symbols = append(elf.Symbols, &symbol)
    }

    return nil
}

func (sym ELF64Sym) GetType() byte {
    return sym.StInfo & 0x0f
}

func (sym ELF64Sym) GetBinding() byte {
    return sym.StInfo & 0xf0
}


