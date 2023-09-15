package linker

import (
	"reflect"
	"testing"

	"github.com/andreistan26/golink/pkg/elf"
	"github.com/andreistan26/golink/pkg/helpers"
	"github.com/stretchr/testify/assert"
)

func TestLinkerSymbolResolution(t *testing.T) {
	filenames := []string{
		"../../data/sample_relocatable_symbols.o",
		"../../data/sample_relocatable_symbols_defs.o",
	}

	l := NewLinker(LinkerInputs{Filenames: filenames})

	for _, inputFile := range l.LinkerInputs.Filenames {
		l.NewFile(inputFile)
	}

	refSymbols := []string{"a_ei", "bar_i", "foo_e", "a_i", "a_ci"}

	for _, refSym := range refSymbols {
		connectedSym, found := l.Symbols[refSym]
		assert.Truef(t, found, "Symbol not found in map %s", refSym)
		assert.Truef(t, connectedSym.DefinedSymbol != nil, "No defined sym for symbol %s", refSym)
	}

	for k, sr := range l.Symbols {
		t.Logf("%v: %v\n", k, sr)
	}

}

func TestLinkerFillSectionDefinedSymbols(t *testing.T) {
	filenames := []string{
		"../../data/sample_relocatable_symbols.o",
		"../../data/sample_relocatable_symbols_defs.o",
	}

	l := NewLinker(LinkerInputs{Filenames: filenames})

	for _, inputFile := range l.LinkerInputs.Filenames {
		l.NewFile(inputFile)
	}

	l.fillSectionDefinedSymbols()

	findSymbolByName := func(seek string, haystack []*ConnectedSymbol) bool {
		for _, sym := range haystack {
			if sym.Symbol.Name == seek {
				return true
			}
		}
		return false
	}

	refMap := make(map[*elf.ELF64Shdr][]string)

	refMap[l.InputObjects[0].Sections[5].SectionEntry] = []string{"a_ci"}
	refMap[l.InputObjects[0].Sections[4].SectionEntry] = []string{"a_i"}

	refMap[l.InputObjects[1].Sections[1].SectionEntry] = []string{"foo_e", "bar_i"}
	refMap[l.InputObjects[1].Sections[2].SectionEntry] = []string{"a_ei"}

	for es, v := range l.SectionDefinedSymbols {
		t.Logf("%v:", es)
		for _, cs := range v {
			t.Logf("%v, ", cs.Symbol.Name)
		}
		t.Logf("\n")
	}

	for k, values := range refMap {
		for _, v := range values {
			assert.Truef(t, findSymbolByName(v, l.SectionDefinedSymbols[k]), " Symbols %s not found", v)
		}
	}
}

func TestLinkerMergeSections(t *testing.T) {
	filenames := []string{
		"../../data/sample_relocatable_symbols.o",
		"../../data/sample_relocatable_symbols_defs.o",
	}

	l := NewLinker(LinkerInputs{Filenames: filenames})

	for _, inputFile := range l.LinkerInputs.Filenames {
		l.NewFile(inputFile)
	}

	l.fillSectionDefinedSymbols()

	objA, objB := l.InputObjects[0], l.InputObjects[1]

	refTextSectionDump := []byte{}
	refTextSectionDump = append(refTextSectionDump, objA.Sections[1].Data...)
	refTextSectionDump = append(refTextSectionDump, objB.Sections[1].Data...)

	for _, inputElf := range l.InputObjects {
		l.MergeElf(inputElf)
	}

	l.UpdateMergedExecutable()

	printSections := func(sections []*elf.Section) {
		for _, section := range sections {
			t.Logf("%v\n", section)
		}
		t.Logf("\n")
	}

	printSections(objA.Sections)
	printSections(objB.Sections)
	printSections(l.Executable.Sections)

	// input: file A, B
	// Check if the copy of data is good:
	//      A.text + B.text = C.text
	assert.Truef(t, reflect.DeepEqual(l.Executable.MappedSections[".text"].Data, refTextSectionDump),
		"text sections merged correctly")

	// Check if C symbols are all defined and by sections
	for _, sym := range l.Executable.Symbols {
		t.Logf("Verifying symbol sets izomophic proprety(all syms and by section) of %s\n", sym.Name)
		assert.Truef(t, helpers.Find[*elf.Symbol](l.Executable.Sections[sym.BaseSymbol.StShNdx].Symbols, sym) != -1,
			"symbol %s in Executable set of symbol but not in its section's set", sym.Name)
	}

	// Check if all C symbols are defined
	// Check the offsets and sizes such that they match the actual sizes
	for _, section := range l.Executable.Sections {
		t.Logf("%v\n", section.SectionEntry)
	}

	shdrStrSection := l.Executable.MappedSections[".shstrtab"]
	strtab := l.Executable.MappedSections[".strtab"]

	// Verify section names
	for _, section := range l.Executable.Sections {
		sectionName := helpers.GetString(shdrStrSection.Data[section.SectionEntry.ShName:])
		assert.Truef(t, sectionName == section.Name, "Section name is not correct in section string table: got=%s want=%s", sectionName, section.Name)
	}

	// Verify symbol names
	for _, symbol := range l.Executable.Symbols {
		symbolName := helpers.GetString(strtab.Data[symbol.BaseSymbol.StName:])
		assert.Truef(t, symbolName == symbol.Name, "Symbol name is not correct in symbol string table: got=%s want=%s", symbol, symbol.Name)
	}
}

func TestProgramHeaders(t *testing.T) {
	filenames := []string{
		"../../data/sample_relocatable_symbols.o",
	}

	l, _ := Link(LinkerInputs{Filenames: filenames})
	l.Executable.PhdrEntries
}
