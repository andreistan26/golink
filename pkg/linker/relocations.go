package linker

import (
	"errors"
	"fmt"
	"strings"

	"github.com/andreistan26/golink/pkg/elf"
	"github.com/andreistan26/golink/pkg/log"
)

type MergeUnit struct {
	Section   *elf.SectionDump
	SourceELF *elf.ELF64
	Name      string
}

// This is the method that handles section merging.
// A merge unit is a bundle of a section header + section data + section source *ELF
// Sections like data and text are merged as is, copy pasted with their offsets modified such that
// they reference the output section header
func (linker *Linker) MergeSection(target *elf.ELF64, name string) error {
	mergeableNames := []string{
		"", ".text", ".data", ".bss", ".strtab", ".rodata", ".symtab", ".shstrtab",
	}

	if sectionDump, ok := target.ShdrEntriesMapped[name]; ok {
		if Contains(name, mergeableNames) == true || strings.Index(name, ".rel") == 0 {
			err := linker.mergeUnit(&MergeUnit{
				Section:   sectionDump,
				SourceELF: target,
				Name:      name,
			})
			return err
		}
		return errors.New(fmt.Sprintf("Section %s not found in target ELF: %s", name, target.Filename))
	}

	return nil
}

// Here we merge sections, Since we keep track of all data in memory we actually dont
// need to update the offsets of the sections at all times, we just do a final pass
// at the end end we build the ELF from nothing to an executable
// So here we just merge sections as they are and update the offsets of the symbols
// So we have a set of defined symbols, we iterate
func (linker *Linker) mergeUnit(target *MergeUnit) error {
	destSection, found := linker.Executable.ShdrEntriesMapped[target.Name]
	if !found {
		// TODO: update this at the end with all sections target.Section.SectionEntry.ShName

		// update section header entry
		linker.Executable.ShdrEntries = append(linker.Executable.ShdrEntries, target.Section)
		linker.Executable.ShdrEntriesMapped[target.Name] = target.Section

		// update elf header
		linker.Executable.Header.ShOff += target.Section.SectionEntry.ShSize
		if target.Name == ".shstrtab" || target.Name == ".strtab" {
			linker.Executable.Header.ShStrNdx = linker.Executable.Header.ShNum
			linker.Executable.Header.ShOff -= target.Section.SectionEntry.ShSize
			// this will be manually set at the end
			target.Section.Data = []byte{}
			target.Section.SectionEntry.ShSize = 0
		}
		target.Section.Index = int(linker.Executable.Header.ShNum)
		linker.Executable.Header.ShNum++
	} else {
		// copy data to target
		if target.Name != ".shstrtab" && target.Name != ".strtab" {
			destSection.Data = append(destSection.Data, target.Section.Data...)
			destSection.SectionEntry.ShSize += target.Section.SectionEntry.ShSize

			// used to update symbols
			target.Section.Index = destSection.Index
		}
	}

	linker.mergeSymbols(target, found)

	return nil
}

func (linker *Linker) mergeSymbols(target *MergeUnit, isFirstSection bool) {
	destSection, ok := linker.Executable.ShdrEntriesMapped[target.Name]
	if !ok {
		log.Errorf("This should not be possible, something very wrong")
		panic(errors.New("WTF"))
	}

	definedSymbols, ok := linker.SectionDefinedSymbols[target.Section.SectionEntry]
	if !ok {
		return
	}

	for _, definedSymbol := range definedSymbols {
		if isFirstSection {
			definedSymbol.Symbol.Sym.StValue += destSection.SectionEntry.ShSize
		}
		definedSymbol.Symbol.Sym.StShNdx = uint16(target.Section.Index)
		destSection.Symbols = append(destSection.Symbols, definedSymbol.Symbol)
		linker.Executable.Symbols = append(linker.Executable.Symbols, definedSymbol.Symbol)
	}
}

// This is called right after we have merged all sections into one ex
func (linker *Linker) UpdateMergedExecutable() error {
	currentSectionOffset := uint64(0)

	// TODO:OPTIMIZATION this really should not be its own pass
	for _, section := range linker.Executable.ShdrEntries {
		// add current section to the section string table
		shstrSection := linker.Executable.ShdrEntries[linker.Executable.Header.ShStrNdx]
		shstrSection.Data = append(linker.Executable.ShdrEntries[linker.Executable.Header.ShStrNdx].Data, []byte(section.Name)...)
		shstrSection.SectionEntry.ShSize += uint64(len(section.Name) + 1)

		// update current symbols
	}

	for _, section := range linker.Executable.ShdrEntries {
		// update offset of current section
		section.SectionEntry.ShOff = currentSectionOffset
		currentSectionOffset += section.SectionEntry.ShSize

	}
	return nil
}
