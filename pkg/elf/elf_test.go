package elf

import (
	"fmt"
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

	elf := &ELF64{}

	err = elf.Header.Parse(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Header")
	}

	err = elf.ParseShdr(objFileData)
	if err != nil {
		t.Errorf("Error when parsing Section header")
	}

	assert.True(t, findSectionByName(".text", elf) != nil, "Second section should be .data")
	assert.True(t, findSectionByName(".data", elf).SectionEntry.ShType == SHT_PROGBITS, "8th section should be of type RELA")
	assert.True(t, findSectionByName(".rela.eh_frame", elf).SectionEntry.ShSize == 0x18, "8th section should have size 0x18")
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

	for _, namedSymbol := range elf.Symbols {
		if _, ok := refSyms[namedSymbol.Name]; !ok {
			t.Errorf("%v not found", namedSymbol.Name)
		}
	}
}

func TestSymbolsBySection(t *testing.T) {
	filename := "../../data/sample_relocatable_symbols_defs.o"

	elf, err := NewELF(filename)
	if err != nil {
		t.Errorf(err.Error())
	}

	textSection := findSectionByName(".text", elf)

	refSymbols := make(map[string]*Symbol)

	refSymbols[".text"] = &Symbol{
		BaseSymbol: &ELF64Sym{
			StShNdx: 1,
			StValue: 0,
			StSize:  0,
		},
		Name: ".text",
	}
	refSymbols["bar_i"] = &Symbol{
		BaseSymbol: &ELF64Sym{
			StShNdx: 1,
			StValue: 0,
			StSize:  14,
		},
		Name: "bar_i",
	}

	refSymbols["foo_e"] = &Symbol{
		BaseSymbol: &ELF64Sym{
			StShNdx: 1,
			StValue: 0xe,
			StSize:  11,
		},
		Name: "foo_e",
	}

	equalSym := func(got, want *Symbol) bool {
		return got.Name == want.Name &&
			got.BaseSymbol.StSize == want.BaseSymbol.StSize &&
			got.BaseSymbol.StShNdx == want.BaseSymbol.StShNdx &&
			got.BaseSymbol.StValue == want.BaseSymbol.StValue
	}

	for _, sym := range textSection.Symbols {
		symWant, found := refSymbols[sym.Name]
		if found {
			assert.True(t, equalSym(sym, symWant), fmt.Sprintf("symbol %s", sym.Name))
		}
	}

}

func findSectionByName(name string, elf *ELF64) *Section {
	for _, section := range elf.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
}
