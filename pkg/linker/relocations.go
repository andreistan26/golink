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
func (linker *Linker) MergeElf(target *elf.ELF64) error {
	mergeableNames := []string{
		"", ".text", ".data", ".bss", ".strtab", ".rodata", ".symtab", ".shstrtab",
	}

	for _, section := range target.ShdrEntries {
		if sectionDump, ok := target.ShdrEntriesMapped[section.Name]; ok {
			if Contains(section.Name, mergeableNames) == true || strings.Index(section.Name, ".rel") == 0 {
				err := linker.mergeUnit(&MergeUnit{
					Section:   sectionDump,
					SourceELF: target,
					Name:      section.Name,
				})
				return err
			}
			return errors.New(fmt.Sprintf("Section %s not found in target ELF: %s", section.Name, target.Filename))
		}
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
		//target.Section.Index = int(linker.Executable.Header.ShNum)
		linker.Executable.Header.ShNum++
		// this might free the memory of the symbols tho free and malloc instead of malloc
		target.Section.Symbols = make([]*elf.NamedSymbol, 0)
	} else {
		// copy data to target
		if target.Name != ".shstrtab" && target.Name != ".strtab" {
			destSection.Data = append(destSection.Data, target.Section.Data...)
			destSection.SectionEntry.ShSize += target.Section.SectionEntry.ShSize

			// used to update symbols
			//target.Section.Index = destSection.Index
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

	// get all symbol definitions from this section
	definedSymbols, ok := linker.SectionDefinedSymbols[target.Section.SectionEntry]
	if !ok {
		return
	}

	for _, definedSymbol := range definedSymbols {
		if !isFirstSection {
			definedSymbol.Symbol.Sym.StValue += destSection.SectionEntry.ShSize - target.Section.SectionEntry.ShSize
		}
		destSection.Symbols = append(destSection.Symbols, definedSymbol.Symbol)
		linker.Executable.Symbols = append(linker.Executable.Symbols, definedSymbol.Symbol)
	}
}

// This is called right after we have merged all sections into one ex
func (linker *Linker) UpdateMergedExecutable() error {
	currentSectionOffset := uint64(0)

	strtab := linker.Executable.ShdrEntriesMapped[".strtab"]
	shstrtab := linker.Executable.ShdrEntries[linker.Executable.Header.ShStrNdx]
	// TODO:OPTIMIZATION this really should not be its own pass
	for idx, section := range linker.Executable.ShdrEntries {
		// add current section to the section string table
		shstrtab.Data = append(linker.Executable.ShdrEntries[linker.Executable.Header.ShStrNdx].Data, []byte(section.Name)...)

		// update this sections symbols
		for _, sym := range section.Symbols {
			sym.Sym.StName = uint32(len(strtab.Data))
			strtab.Data = append(strtab.Data, []byte(sym.Name)...)
			sym.Sym.StShNdx = uint16(idx)
		}
	}

	strtab.SectionEntry.ShSize = uint64(len(strtab.Data))
	shstrtab.SectionEntry.ShSize = uint64(len(shstrtab.Data))

	for _, section := range linker.Executable.ShdrEntries {
		// update offset of current section
		section.SectionEntry.ShOff = currentSectionOffset
		currentSectionOffset += section.SectionEntry.ShSize

	}
	return nil
}
