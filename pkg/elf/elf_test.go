package elf

import (
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyMagic(t *testing.T) {
	file, err := os.Open("../../data/sample_relocatable_elf64.o")
	if err != nil {
		t.Errorf("Object file not found")
	}

	objFileData := make([]byte, 1024*1024)
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

	objFileData := make([]byte, 1024*1024)
	_, err = file.Read(objFileData)
	if err != nil {
		t.Errorf("%v", err)
	}

	elf := ELF64{}

	elf.Header.Parse(objFileData)

	refHeader := ELF64Ehdr{
		Ident: [16]byte{
			'\x7f', '\x45', '\x4c', '\x46',
			'\x02', '\x01', '\x01', '\x00',
			'\x00', '\x00', '\x00', '\x00',
			'\x00', '\x00', '\x00', '\x00',
		},
		Type:      ET_REL,
		Machine:   0x3E,
		Version:   1,
		Entry:     0,
		PhOff:     0,
		ShOff:     456,
		Flags:     0,
		EhSize:    64,
		PhEntSize: 0,
		PhNum:     0,
		ShEntSize: 64,
		ShNum:     12,
		ShStrNdx:  11,
	}

	assert.True(t, reflect.DeepEqual(refHeader, elf.Header), "ELF Header parsing failed")
}

func TestELF64SectionTable(t *testing.T) {
	file, err := os.Open("../../data/sample_relocatable_elf64.o")
	if err != nil {
		t.Errorf("Object file not found")
	}

	objFileData := make([]byte, 1024*1024)
	_, err = file.Read(objFileData)
	if err != nil {
		t.Errorf("%v", err)
	}

	elf := ELF64{}

	err = elf.Header.Parse(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Header")
	}

	err = elf.ParseShdr(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Section header")
	}

	assert.True(t, elf.ShdrEntriesMapped[".text"] != nil, "Second section should be .data")
	assert.True(t, elf.ShdrEntriesMapped[".data"].ShType == SHT_PROGBITS, "8th section should be of type RELA")
	assert.True(t, elf.ShdrEntriesMapped[".rela.eh_frame"].ShSize == 0x18, "8th section should have size 0x18")
}

func TestELF64SymbolTable(t *testing.T) {
	file, err := os.Open("../../data/sample_relocatable_symbols.o")
	if err != nil {
		t.Errorf("Object file not found")
	}

	objFileData := make([]byte, 1024*1024)
	_, err = file.Read(objFileData)
	if err != nil {
		t.Errorf("%v", err)
	}

	elf := ELF64{}

	err = elf.Header.Parse(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Header %v", err)
	}

	err = elf.ParseShdr(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Section Header table %v", err)
	}

	err = elf.ParseSymTable(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Symbol table: %v", err)
	}

	refSyms := map[string]int{
		"a_i":    1,
		"a_ci":   1,
		"main":   1,
		"a_ei":   1,
		"":       1,
		"foo_e":  1,
		"bar_i":  1,
		"main.c": 1,
	}

	assert.True(t, int(elf.ShdrEntriesMapped[".symtab"].ShSize)/0x18 == len(elf.Symbols), "Mismatch between ref and actual")

	for _, namedSymbol := range elf.Symbols {
		if _, ok := refSyms[namedSymbol.Name]; !ok {
			t.Errorf("%v not found", namedSymbol.Name)
		}
	}
}
