// Code generated by "stringer -type STT,STB,ElfClass,ElfData,ElfOsAbi,ET,SHT_TYPE,SHT_FLAGS -output elf_string.go"; DO NOT EDIT.

package elf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[STT_NOTYPE-0]
	_ = x[STT_OBJECT-1]
	_ = x[STT_FUNC-2]
	_ = x[STT_SECTION-3]
	_ = x[STT_FILE-4]
	_ = x[STT_LOOS-10]
	_ = x[STT_HIOS-12]
	_ = x[STT_LOPROC-13]
	_ = x[STT_HIPROC-15]
}

const (
	_STT_name_0 = "STT_NOTYPESTT_OBJECTSTT_FUNCSTT_SECTIONSTT_FILE"
	_STT_name_1 = "STT_LOOS"
	_STT_name_2 = "STT_HIOSSTT_LOPROC"
	_STT_name_3 = "STT_HIPROC"
)

var (
	_STT_index_0 = [...]uint8{0, 10, 20, 28, 39, 47}
	_STT_index_2 = [...]uint8{0, 8, 18}
)

func (i STT) String() string {
	switch {
	case i <= 4:
		return _STT_name_0[_STT_index_0[i]:_STT_index_0[i+1]]
	case i == 10:
		return _STT_name_1
	case 12 <= i && i <= 13:
		i -= 12
		return _STT_name_2[_STT_index_2[i]:_STT_index_2[i+1]]
	case i == 15:
		return _STT_name_3
	default:
		return "STT(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[STB_LOCAL-0]
	_ = x[STB_GLOBAL-1]
	_ = x[STB_WEAK-2]
	_ = x[STB_LOOS-10]
	_ = x[STB_HIOS-12]
	_ = x[STB_LOPROC-13]
	_ = x[STB_HIPROC-15]
}

const (
	_STB_name_0 = "STB_LOCALSTB_GLOBALSTB_WEAK"
	_STB_name_1 = "STB_LOOS"
	_STB_name_2 = "STB_HIOSSTB_LOPROC"
	_STB_name_3 = "STB_HIPROC"
)

var (
	_STB_index_0 = [...]uint8{0, 9, 19, 27}
	_STB_index_2 = [...]uint8{0, 8, 18}
)

func (i STB) String() string {
	switch {
	case i <= 2:
		return _STB_name_0[_STB_index_0[i]:_STB_index_0[i+1]]
	case i == 10:
		return _STB_name_1
	case 12 <= i && i <= 13:
		i -= 12
		return _STB_name_2[_STB_index_2[i]:_STB_index_2[i+1]]
	case i == 15:
		return _STB_name_3
	default:
		return "STB(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ELFCLASS32-1]
	_ = x[ELFCLASS64-2]
}

const _ElfClass_name = "ELFCLASS32ELFCLASS64"

var _ElfClass_index = [...]uint8{0, 10, 20}

func (i ElfClass) String() string {
	i -= 1
	if i >= ElfClass(len(_ElfClass_index)-1) {
		return "ElfClass(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ElfClass_name[_ElfClass_index[i]:_ElfClass_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ELFDATA2LSB-1]
	_ = x[ELFDATA2MSB-2]
}

const _ElfData_name = "ELFDATA2LSBELFDATA2MSB"

var _ElfData_index = [...]uint8{0, 11, 22}

func (i ElfData) String() string {
	i -= 1
	if i >= ElfData(len(_ElfData_index)-1) {
		return "ElfData(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ElfData_name[_ElfData_index[i]:_ElfData_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ELFOSABI_SYSV-0]
	_ = x[ELFOSABI_HPUX-1]
	_ = x[ELFOSABI_STANDALONE-255]
}

const (
	_ElfOsAbi_name_0 = "ELFOSABI_SYSVELFOSABI_HPUX"
	_ElfOsAbi_name_1 = "ELFOSABI_STANDALONE"
)

var (
	_ElfOsAbi_index_0 = [...]uint8{0, 13, 26}
)

func (i ElfOsAbi) String() string {
	switch {
	case i <= 1:
		return _ElfOsAbi_name_0[_ElfOsAbi_index_0[i]:_ElfOsAbi_index_0[i+1]]
	case i == 255:
		return _ElfOsAbi_name_1
	default:
		return "ElfOsAbi(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ET_NONE-0]
	_ = x[ET_REL-1]
	_ = x[ET_EXEC-2]
	_ = x[ET_DYN-3]
	_ = x[ET_CORE-4]
	_ = x[ET_LOOS-65024]
	_ = x[ET_HIOS-65279]
	_ = x[ET_LOPROC-65280]
	_ = x[ET_HIPROC-65535]
}

const (
	_ET_name_0 = "ET_NONEET_RELET_EXECET_DYNET_CORE"
	_ET_name_1 = "ET_LOOS"
	_ET_name_2 = "ET_HIOSET_LOPROC"
	_ET_name_3 = "ET_HIPROC"
)

var (
	_ET_index_0 = [...]uint8{0, 7, 13, 20, 26, 33}
	_ET_index_2 = [...]uint8{0, 7, 16}
)

func (i ET) String() string {
	switch {
	case i <= 4:
		return _ET_name_0[_ET_index_0[i]:_ET_index_0[i+1]]
	case i == 65024:
		return _ET_name_1
	case 65279 <= i && i <= 65280:
		i -= 65279
		return _ET_name_2[_ET_index_2[i]:_ET_index_2[i+1]]
	case i == 65535:
		return _ET_name_3
	default:
		return "ET(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[SHT_NULL-0]
	_ = x[SHT_PROGBITS-1]
	_ = x[SHT_SYMTAB-2]
	_ = x[SHT_STRTAB-3]
	_ = x[SHT_RELA-4]
	_ = x[SHT_HASH-5]
	_ = x[SHT_DYNAMIC-6]
	_ = x[SHT_NOTE-7]
	_ = x[SHT_NOBITS-8]
	_ = x[SHT_REL-9]
	_ = x[SHT_SHLIB-10]
	_ = x[SHT_DYNSYM-11]
	_ = x[SHT_LOOS-1610612736]
	_ = x[SHT_HIOS-1879048191]
	_ = x[SHT_LOPROC-1879048192]
	_ = x[SHT_HIPROC-1879048192]
}

const (
	_SHT_TYPE_name_0 = "SHT_NULLSHT_PROGBITSSHT_SYMTABSHT_STRTABSHT_RELASHT_HASHSHT_DYNAMICSHT_NOTESHT_NOBITSSHT_RELSHT_SHLIBSHT_DYNSYM"
	_SHT_TYPE_name_1 = "SHT_LOOS"
	_SHT_TYPE_name_2 = "SHT_HIOSSHT_LOPROC"
)

var (
	_SHT_TYPE_index_0 = [...]uint8{0, 8, 20, 30, 40, 48, 56, 67, 75, 85, 92, 101, 111}
	_SHT_TYPE_index_2 = [...]uint8{0, 8, 18}
)

func (i SHT_TYPE) String() string {
	switch {
	case i <= 11:
		return _SHT_TYPE_name_0[_SHT_TYPE_index_0[i]:_SHT_TYPE_index_0[i+1]]
	case i == 1610612736:
		return _SHT_TYPE_name_1
	case 1879048191 <= i && i <= 1879048192:
		i -= 1879048191
		return _SHT_TYPE_name_2[_SHT_TYPE_index_2[i]:_SHT_TYPE_index_2[i+1]]
	default:
		return "SHT_TYPE(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[SHF_WRITE-1]
	_ = x[SHF_ALLOC-2]
	_ = x[SHF_EXECINSTR-4]
}

const (
	_SHT_FLAGS_name_0 = "SHF_WRITESHF_ALLOC"
	_SHT_FLAGS_name_1 = "SHF_EXECINSTR"
)

var (
	_SHT_FLAGS_index_0 = [...]uint8{0, 9, 18}
)

func (i SHT_FLAGS) String() string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _SHT_FLAGS_name_0[_SHT_FLAGS_index_0[i]:_SHT_FLAGS_index_0[i+1]]
	case i == 4:
		return _SHT_FLAGS_name_1
	default:
		return "SHT_FLAGS(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}