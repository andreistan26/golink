package linker

import (
	"github.com/andreistan26/golink/pkg/elf"
    "errors"
    "log"
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
    Symbol  *elf.ELF64Sym
    Elf     *elf.ELF64
}

type SymbolRouter struct {
    // pointers to all appearances of this symbol
    RelatedSymbols []*ConnectedSymbol

    // pointer to the definition of the symbol
    DefinedSymbol *ConnectedSymbol
}

type Linker struct {
    LinkerInputs    LinkerInputs
    Elfs            []*elf.ELF64
    
    // We index symbols by name and we need
    // multiple (at least 2) symbols to define
    Symbols             map[string]*SymbolRouter

    // set of all the undefined symbols
    UndefinedSymbols    map[string]struct{}
}

func New(inputs LinkerInputs) error {
    linker := &Linker{
        LinkerInputs: inputs,
        Elfs: []*elf.ELF64{},
        Symbols: make(map[string]*SymbolRouter),
        UndefinedSymbols: make(map[string]struct{}),
    }

    for _, inputFile := range linker.LinkerInputs.Filenames {
        linker.NewFile(inputFile)
    }

    return nil
}

func (linker *Linker) NewFile(filepath string) error {
    objFile, err := elf.New(filepath)
    if err != nil {
        return err
    }

    // Now update symbol hashtable with symbols
    for _, sym := range objFile.Symbols {
        linker.UpdateSymbol(sym, objFile)
    }
    return nil
}

func (linker *Linker) UpdateSymbol(namedSymbol *elf.NamedSymbol, objFile *elf.ELF64) error {
    router, found := linker.Symbols[namedSymbol.Name]
    entry := &ConnectedSymbol{
        Symbol: namedSymbol.Sym,
        Elf: objFile,
    }

    if !found {
        // add a new entry into symbol hashtable
        linker.Symbols[namedSymbol.Name] = &SymbolRouter{
            RelatedSymbols: []*ConnectedSymbol {},
            DefinedSymbol: nil,
        }
    }

    if router.DefinedSymbol == nil {
        router.RelatedSymbols = append(router.RelatedSymbols, entry)
        if entry.Symbol.GetType() != elf.STT_NOTYPE {
            router.DefinedSymbol = entry
        }
        return nil
    } else {
        if entry.Symbol.GetBinding() == router.DefinedSymbol.Symbol.GetBinding() {
            if entry.Symbol.GetType() == elf.STB_GLOBAL {
                return errors.New("Two strong symbols with same name.")
            } else {
                // probably entry is weak and definition is weak
                router.RelatedSymbols = append(router.RelatedSymbols, entry)
                return nil
            }
        }

        if entry.Symbol.GetBinding() == elf.STB_WEAK {
            // ignore the symbol, definition is strong
            return nil
        }

        if entry.Symbol.GetType() == elf.STT_NOTYPE {
            // update reference(entry) with the found definition
            router.RelatedSymbols = append(router.RelatedSymbols, entry)
            
            return nil
        }
        log.Println("Should have not ended up here")
    }

    return nil
}
