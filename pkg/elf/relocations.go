package elf

import (
	"errors"
	"fmt"
)

type MergeUnit struct {
	Section   *SectionDump
	SourceELF *ELF64
	Name      string
}

// This is the method that handles section merging.
// A merge unit is a bundle of a section header + section data + section source *ELF
// Sections like data and text are merged as is, copy pasted with their offsets modified such that
// they reference the output section header
func (dest *ELF64) MergeSection(target *ELF64, name string) error {
	if sectionDump, ok := target.ShdrEntriesMapped[name]; ok {
		err := dest.mergeUnit(&MergeUnit{
			Section:   sectionDump,
			SourceELF: target,
			Name:      name,
		})
		return err
	}

	return errors.New(fmt.Sprintf("Section %s not found in target ELF: %s", name, target.Filename))
}

// When merging sections, from the perspective of dest i just modify its section header(offsets, size)
// every section below the modified section does not care about the modified section
// since we are starting with a raw executable elf the symbol table will be copied before the relocation tables
// such that we will get the symbol required(name) and then find its index
func (dest *ELF64) mergeUnit(target *MergeUnit) error {

	return nil
}
