package elf

import (
	"os"
	"reflect"
	"testing"
    "fmt"

	"github.com/stretchr/testify/assert"
)

func TestVerifyMagic(t *testing.T) {
    file, err := os.Open("../../data/sample_relocatable_elf64.o")
    if err != nil {
        t.Errorf("Object file not found")
    }

    objFileData := make([]byte, 1024 * 1024)
    _, err = file.Read(objFileData)
    if err != nil {
        t.Errorf("%v", err)
    }

    elf64Ehdr := ELF64Ehdr{}
    copy(elf64Ehdr.Ident[:], objFileData[0:16])

    assert.True(t, elf64Ehdr.VerifyMagic() == nil, "The elf should have a valid magic")
}

func TestELF64HeaderParse(t *testing.T) {
    file, err := os.Open("../../data/sample_relocatable_elf64.o")
    if err != nil {
        t.Errorf("Object file not found")
    }

    objFileData := make([]byte, 1024 * 1024)
    _, err = file.Read(objFileData)
    if err != nil {
        t.Errorf("%v", err)
    }
    
    header, err := ParseHeader(objFileData)

    refHeader := ELF64Ehdr{
        Ident: [16]byte {
            '\x7f', '\x45', '\x4c', '\x46',
            '\x02', '\x01', '\x01', '\x00',
            '\x00', '\x00', '\x00', '\x00',
            '\x00', '\x00', '\x00', '\x00',
        },
        Type: ET_REL,
        Machine: 0x3E,
        Version: 1,
        Entry: 0,
        PhOff: 0,
        ShOff: 456,
        Flags: 0,
        EhSize: 64,
        PhEntSize: 0,
        PhNum: 0,
        ShEntSize: 64,
        ShNum: 12,
        ShStrNdx: 11,
    }

    assert.True(t, reflect.DeepEqual(refHeader, header), "ELF Header parsing failed")
}

func TestELF64SectionTable(t *testing.T) {
    file, err := os.Open("../../data/sample_relocatable_elf64.o")
    if err != nil {
        t.Errorf("Object file not found")
    }

    objFileData := make([]byte, 1024 * 1024)
    _, err = file.Read(objFileData)
    if err != nil {
        t.Errorf("%v", err)
    }
    
    header, err := ParseHeader(objFileData)
    elf := &ELF64 {
        Header: header,
    }

    elf.ParseShdr(objFileData)
    fmt.Printf("%v", elf.ShdrEntries[0])
}
