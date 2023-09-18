package linker

import (
	"errors"

	"github.com/andreistan26/golink/pkg/elf"
	"github.com/andreistan26/golink/pkg/helpers"
	"github.com/andreistan26/golink/pkg/log"
)

const (
	SYM_UNDEF uint32 = 1
	SYM_DEF          = 2
	SYM_WEAK         = 3
)

type LinkerInputs struct {
	Filenames      []string
	ExecutableName string
}

type ConnectedSymbol struct {
	Symbol *elf.Symbol
	Elf    *elf.ELF64
}

type SymbolRouter struct {
	SymbolType uint32

	// pointer to the definition of the symbol
	DefinedSymbol *ConnectedSymbol
}

type OutputELF struct {
	elf.ELF64
	MappedSections map[string]*elf.Section
}

type Linker struct {
	LinkerInputs LinkerInputs
	InputObjects []*elf.ELF64

	Executable OutputELF
	// We index symbols by name and we need
	// multiple (at least 2) symbols to define
	Symbols               map[string]*SymbolRouter
	SectionDefinedSymbols map[*elf.ELF64Shdr][]*ConnectedSymbol

	// set of all the undefined symbols
	UndefinedSymbols map[string]struct{}
}

func NewLinker(inputs LinkerInputs) *Linker {
	linker := &Linker{
		LinkerInputs:          inputs,
		InputObjects:          []*elf.ELF64{},
		Executable:            OutputELF{MappedSections: make(map[string]*elf.Section)},
		Symbols:               make(map[string]*SymbolRouter),
		UndefinedSymbols:      make(map[string]struct{}),
		SectionDefinedSymbols: make(map[*elf.ELF64Shdr][]*ConnectedSymbol),
	}

	if inputs.ExecutableName == "" {
		inputs.ExecutableName = "a.out"
	}

	linker.Executable.Filename = inputs.ExecutableName

	return linker
}

func Link(inputs LinkerInputs) (*Linker, error) {
	linker := NewLinker(inputs)

	log.Debugf("Linker input files received %v", inputs.Filenames)

	for _, inputFile := range linker.LinkerInputs.Filenames {
		linker.NewFile(inputFile)
	}

	linker.fillSectionDefinedSymbols()

	for _, inputElf := range linker.InputObjects {
		linker.MergeElf(inputElf)
	}

	linker.Executable.SortSections()

	linker.UpdateMergedExecutable()

	linker.fillProgramHeader()

	linker.fillExecutableHeader()

	linker.ApplyRelocations()

	err := linker.Executable.WriteELF()
	if err != nil {
		panic(err)
	}

	log.Debugf("%s\n", linker.Executable.String())

	return linker, nil
}

func (linker *Linker) NewFile(filepath string) error {
	objFile, err := elf.NewELF(filepath)
	if err != nil {
		return err
	}

	linker.InputObjects = append(linker.InputObjects, objFile)

	// Now update symbol hashtable with symbols
	for _, sym := range objFile.Symbols {
		err := linker.UpdateSymbol(sym, objFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func (linker *Linker) UpdateSymbol(namedSymbol *elf.Symbol, objFile *elf.ELF64) error {
	// We skip symbols that dont matter to resolution
	if helpers.Find[elf.STT]([]elf.STT{elf.STT_NOTYPE, elf.STT_FUNC, elf.STT_OBJECT}, namedSymbol.BaseSymbol.GetType()) == -1 ||
		namedSymbol.Name == "" {
		return nil
	}

	router, found := linker.Symbols[namedSymbol.Name]

	log.Debugf("Named Symbol in update %v", namedSymbol)
	entry := &ConnectedSymbol{
		Symbol: namedSymbol,
		Elf:    objFile,
	}

	if !found {
		// add a new entry into symbol hashtable
		router = &SymbolRouter{
			SymbolType:    SYM_UNDEF,
			DefinedSymbol: nil,
		}

		linker.Symbols[namedSymbol.Name] = router
	}

	if router.DefinedSymbol == nil {
		if entry.Symbol.BaseSymbol.GetType() != elf.STT_NOTYPE {
			router.DefinedSymbol = entry
			delete(linker.UndefinedSymbols, namedSymbol.Name)
			log.Debugf("Added as defined symbol")
		} else {
			linker.UndefinedSymbols[namedSymbol.Name] = struct{}{}
		}
		return nil
	} else {
		log.Debugf("This entry has a defined symbol")
		if entry.Symbol.BaseSymbol.GetType() != elf.STT_NOTYPE {
			if router.DefinedSymbol.Symbol.BaseSymbol.GetBinding() == elf.STB_WEAK {
				// TODO remove the previous defined symbol from the list as it is a weak and we found a strong
				router.DefinedSymbol.Symbol = entry.Symbol
			} else {
				return errors.New("Two strong symbols with same name.")
			}
		} else {
			// update reference(entry) with the found definition
			log.Debugf("Found a definition: %v for the reference %v", router.DefinedSymbol.Symbol,
				entry.Symbol)
			return nil
		}
	}

	return nil
}

func (linker *Linker) fillSectionDefinedSymbols() {
	for _, router := range linker.Symbols {
		definedSymbol := router.DefinedSymbol
		definedSymbolSection := definedSymbol.Elf.Sections[definedSymbol.Symbol.BaseSymbol.StShNdx]
		linker.addSectionDefinedSymbol(definedSymbol, definedSymbolSection.SectionEntry)
	}
}

func (linker *Linker) addSectionDefinedSymbol(symbol *ConnectedSymbol, section *elf.ELF64Shdr) {
	_, found := linker.SectionDefinedSymbols[section]
	if !found {
		linker.SectionDefinedSymbols[section] = []*ConnectedSymbol{symbol}
	} else {
		linker.SectionDefinedSymbols[section] = append(linker.SectionDefinedSymbols[section], symbol)
	}
}

func (linker *Linker) fillProgramHeader() {
	// find data segment offset
	writableNdx := helpers.FindIf[*elf.Section](linker.Executable.Sections, func(section *elf.Section) bool {
		return section.SectionEntry.IsWritable()
	})

	rxSegSize := 0
	for i := 0; i < writableNdx; i++ {
		rxSegSize += int(linker.Executable.Sections[i].SectionEntry.ShSize)
	}

	linker.Executable.PhdrEntries = append(linker.Executable.PhdrEntries, elf.ELF64Phdr{
		Type:   elf.PT_LOAD,
		Flags:  elf.PF_R | elf.PF_X,
		Offset: linker.Executable.Sections[0].SectionEntry.ShOff,
		Vaddr:  0x400000 + linker.Executable.Sections[0].SectionEntry.ShOff,
		Paddr:  0x400000 + linker.Executable.Sections[0].SectionEntry.ShOff,
		FileSz: uint64(rxSegSize),
		MemSz:  uint64(rxSegSize),
		Align:  0x1000, // change pls
	})

	rwSegSize := 0
	for i := writableNdx; i < len(linker.Executable.Sections); i++ {
		rwSegSize += int(linker.Executable.Sections[i].SectionEntry.ShSize)
	}

	linker.Executable.PhdrEntries = append(linker.Executable.PhdrEntries, elf.ELF64Phdr{
		Type:   elf.PT_LOAD,
		Flags:  elf.PF_R | elf.PF_W,
		Offset: linker.Executable.Sections[writableNdx].SectionEntry.ShOff,
		Vaddr:  0x400000 + linker.Executable.Sections[writableNdx].SectionEntry.ShOff,
		Paddr:  0x400000 + linker.Executable.Sections[writableNdx].SectionEntry.ShOff,
		FileSz: uint64(rwSegSize),
		MemSz:  uint64(rwSegSize),
		Align:  0x1000, // change pls
	})

	linker.Executable.Header.PhNum = 2

	phdrSize := uint64(56*2) + 64
	// iterate all sections and offset them
	for _, section := range linker.Executable.Sections {
		section.SectionEntry.ShOff += phdrSize
	}
}

func (linker *Linker) fillExecutableHeader() {
	linker.Executable.Header.FillIdentExecutable()
	linker.Executable.Header.Type = elf.ET_EXEC
	linker.Executable.Header.Machine = 0x3E
	linker.Executable.Header.Version = 1
	linker.Executable.Header.EhSize = 0x40
	linker.Executable.Header.ShEntSize = 0x40

	lastSection := linker.Executable.Sections[len(linker.Executable.Sections)-1]
	linker.Executable.Header.ShOff = lastSection.SectionEntry.ShOff + lastSection.SectionEntry.ShSize
	linker.Executable.Header.ShEntSize = 0x40

	linker.Executable.Header.PhOff = 0x40
	linker.Executable.Header.PhEntSize = 0x38
	linker.Executable.Header.Entry = linker.GetSectionVirtAddress(linker.Executable.MappedSections[".text"]) + 4

	for idx, section := range linker.Executable.Sections {
		if section.Name == ".shstrtab" {
			linker.Executable.Header.ShStrNdx = uint16(idx)
		}
	}
}

func (linker *Linker) GetSectionVirtAddress(section *elf.Section) uint64 {
	phdrNdx := 0
	if section.SectionEntry.IsWritable() {
		phdrNdx = 1
	}

	return section.SectionEntry.ShOff + linker.Executable.PhdrEntries[phdrNdx].Vaddr
}

func (linker *Linker) GetSymbolVirtAddress(symbol *elf.Symbol) uint64 {
	return linker.GetSectionVirtAddress(linker.Executable.Sections[symbol.BaseSymbol.StShNdx]) + symbol.BaseSymbol.StValue
}
