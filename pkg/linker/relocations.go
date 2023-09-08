package linker

import (
	"errors"
	"strings"

	"github.com/andreistan26/golink/pkg/elf"
	"github.com/andreistan26/golink/pkg/helpers"
	"github.com/andreistan26/golink/pkg/log"
)

type MergeUnit struct {
	Section   *elf.Section
	SourceELF *elf.ELF64
}

// This is the method that handles section merging.
// A merge unit is a bundle of a section header + section data + section source *ELF
// Sections like data and text are merged as is, copy pasted with their offsets modified such that
// they reference the output section header
func (linker *Linker) MergeElf(target *elf.ELF64) error {
	mergeableNames := []string{
		"", ".text", ".data", ".bss", ".strtab", ".rodata", ".shstrtab",
	}

	for _, section := range target.Sections {
		if Contains(section.Name, mergeableNames) == true || strings.Index(section.Name, ".rel") == 0 {
			err := linker.mergeUnit(&MergeUnit{
				Section:   section,
				SourceELF: target,
			})
			if err != nil {
				log.Errorf(err.Error())
			}
		} else {
			log.Debugf("Section was skipped because it's name was not in the mergeableNames: %s", section.Name)
		}
	}

	return nil
}

func (linker *Linker) mergeUnit(target *MergeUnit) error {
	outputSection, isNewSection := linker.Executable.MappedSections[target.Section.Name]
	if !isNewSection {
		// update section header entry
		linker.Executable.Sections = append(linker.Executable.Sections, target.Section)
		linker.Executable.MappedSections[target.Section.Name] = target.Section

		// update elf header
		linker.Executable.Header.ShOff += target.Section.SectionEntry.ShSize
		if target.Section.Name == ".shstrtab" || target.Section.Name == ".strtab" {
			linker.Executable.Header.ShStrNdx = linker.Executable.Header.ShNum
			linker.Executable.Header.ShOff -= target.Section.SectionEntry.ShSize
			// this will be manually set at the end
			target.Section.Data = []byte{}
			target.Section.SectionEntry.ShSize = 0
		}
		linker.Executable.Header.ShNum++

		// This might free the memory of the symbols tho free and malloc instead of malloc!!!!
		// if this fails then we need to make a new section entity for each section found that is not mapped
		target.Section.Symbols = make([]*elf.Symbol, 0)
	} else {
		// copy data to target
		if target.Section.Name != ".shstrtab" && target.Section.Name != ".strtab" {
			outputSection.Data = append(outputSection.Data, target.Section.Data...)
			linker.updateRelocations(target, outputSection.SectionEntry.ShSize)
			outputSection.SectionEntry.ShSize += target.Section.SectionEntry.ShSize
		}
	}

	linker.mergeSymbols(target, isNewSection)
	return nil
}

func (linker *Linker) mergeSymbols(target *MergeUnit, isFirstSection bool) {
	destSection, ok := linker.Executable.MappedSections[target.Section.Name]
	if !ok {
		log.Errorf("This should not be possible, something very wrong")
		panic(errors.New("WTF"))
	}

	// get all symbol definitions from this section
	definedSymbols, ok := linker.SectionDefinedSymbols[target.Section.SectionEntry]
	if !ok {
		log.Debugf("No defined symbols found in section %s of file %s", target.Section.Name, target.SourceELF.Filename)
		return
	}

	for _, definedSymbol := range definedSymbols {
		if !isFirstSection {
			definedSymbol.Symbol.BaseSymbol.StValue += destSection.SectionEntry.ShSize - target.Section.SectionEntry.ShSize
		}
		destSection.Symbols = append(destSection.Symbols, definedSymbol.Symbol)
		linker.Executable.Symbols = append(linker.Executable.Symbols, definedSymbol.Symbol)
	}
}

// TODO test this
func (linker *Linker) updateRelocations(target *MergeUnit, offset uint64) {
	if len(target.Section.Relocations) == 0 {
		return
	}

	for _, relocation := range target.Section.Relocations {
		relocation.Offset += offset
	}

	refSection, _ := linker.Executable.MappedSections[target.Section.Name]
	refSection.Relocations = append(refSection.Relocations, target.Section.Relocations...)
}

// This is called right after we have merged all sections into one ex
func (linker *Linker) UpdateMergedExecutable() error {

	strtab := linker.Executable.MappedSections[".strtab"]
	shstrtab := linker.Executable.Sections[linker.Executable.Header.ShStrNdx]
	for idx, section := range linker.Executable.Sections {
		// add current section to the section string table
		section.SectionEntry.ShName = uint32(len(shstrtab.Data))
		shstrtab.Data = append(shstrtab.Data, helpers.String2Bytes(section.Name)...)
		// update this sections symbols
		for _, sym := range section.Symbols {
			sym.BaseSymbol.StName = uint32(len(strtab.Data))
			strtab.Data = append(strtab.Data, helpers.String2Bytes(sym.Name)...)
			sym.BaseSymbol.StShNdx = uint16(idx)
		}
	}

	strtab.SectionEntry.ShSize = uint64(len(strtab.Data))
	shstrtab.SectionEntry.ShSize = uint64(len(shstrtab.Data))

	currentSectionOffset := uint64(0)
	for _, section := range linker.Executable.Sections {
		// update offset of current section
		section.SectionEntry.ShOff = currentSectionOffset
		currentSectionOffset += section.SectionEntry.ShSize
	}

	return nil
}
