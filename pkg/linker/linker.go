package linker

import (
	"errors"
	"github.com/andreistan26/golink/pkg/log"

	"github.com/andreistan26/golink/pkg/elf"
)

const (
	SYM_UNDEF uint32 = 1
	SYM_DEF          = 2
	SYM_WEAK         = 3
)

type LinkerInputs struct {
	Filenames []string
}

type ConnectedSymbol struct {
	Symbol *elf.ELF64Sym
	Elf    *elf.ELF64
}

type SymbolRouter struct {
	// pointers to all appearances of this symbol
	RelatedSymbols []*ConnectedSymbol

	// pointer to the definition of the symbol
	DefinedSymbol *ConnectedSymbol
}

type Linker struct {
	LinkerInputs LinkerInputs
	Elfs         []*elf.ELF64

	Executable *elf.ELF64
	// We index symbols by name and we need
	// multiple (at least 2) symbols to define
	Symbols map[string]*SymbolRouter

	// set of all the undefined symbols
	UndefinedSymbols map[string]struct{}
}

func Link(inputs LinkerInputs) (*elf.ELF64, error) {
	linker := &Linker{
		LinkerInputs:     inputs,
		Elfs:             []*elf.ELF64{},
		Symbols:          make(map[string]*SymbolRouter),
		UndefinedSymbols: make(map[string]struct{}),
	}

	log.Debugf("Linker input files received %v", inputs.Filenames)

	for _, inputFile := range linker.LinkerInputs.Filenames {
		linker.NewFile(inputFile)
	}

	return nil, nil
}

func (linker *Linker) NewFile(filepath string) error {
	objFile, err := elf.New(filepath)
	if err != nil {
		return err
	}

	// Now update symbol hashtable with symbols
	for _, sym := range objFile.Symbols {
		err := linker.UpdateSymbol(sym, objFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func contains[T comparable](needle T, haystack []T) bool {
	for _, el := range haystack {
		if needle == el {
			return true
		}
	}

	return false
}

func (linker *Linker) UpdateSymbol(namedSymbol *elf.NamedSymbol, objFile *elf.ELF64) error {
	// We skip symbols that dont matter to resolution
	if !contains(namedSymbol.Sym.GetType(), []elf.STT{elf.STT_NOTYPE, elf.STT_FUNC, elf.STT_OBJECT}) ||
		namedSymbol.Name == "" {
		return nil
	}

	router, found := linker.Symbols[namedSymbol.Name]

	log.Debugf("Named Symbol in update %v", namedSymbol)
	entry := &ConnectedSymbol{
		Symbol: namedSymbol.Sym,
		Elf:    objFile,
	}

	if !found {
		// add a new entry into symbol hashtable
		router = &SymbolRouter{
			RelatedSymbols: []*ConnectedSymbol{},
			DefinedSymbol:  nil,
		}

		linker.Symbols[namedSymbol.Name] = router
	}

	if router.DefinedSymbol == nil {
		router.RelatedSymbols = append(router.RelatedSymbols, entry)
		if entry.Symbol.GetType() != elf.STT_NOTYPE {
			router.DefinedSymbol = entry
			delete(linker.UndefinedSymbols, namedSymbol.Name)
			log.Debugf("Added as defined symbol")
		} else {
			linker.UndefinedSymbols[namedSymbol.Name] = struct{}{}
		}
		return nil
	} else {
		log.Debugf("This entry has a defined symbol")
		if entry.Symbol.GetType() != elf.STT_NOTYPE {
			if router.DefinedSymbol.Symbol.GetBinding() == elf.STB_WEAK {
				// TODO remove the previous defined symbol from the list as it is a weak and we found a strong
				router.DefinedSymbol.Symbol = entry.Symbol
				router.RelatedSymbols = append(router.RelatedSymbols, entry)
			} else {
				return errors.New("Two strong symbols with same name.")
			}
		} else {
			// update reference(entry) with the found definition
			log.Debugf("Found a definition: %v for the reference %v", router.DefinedSymbol.Symbol,
				entry.Symbol)
			router.RelatedSymbols = append(router.RelatedSymbols, entry)
			return nil
		}
	}

	return nil
}
