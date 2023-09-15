package helpers

// Convert from string to null terminated byte slice
func String2Bytes(str string) []byte {
	bytes := []byte(str)
	bytes = append(bytes, '\x00')

	return bytes
}

// Find item in slice and return it's index, if none found return -1
func Find[T comparable](haystack []T, needle T) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}

	return -1
}

// Get the first string from a byte stream
func GetString(bytes []byte) string {
	for i, v := range bytes {
		if v == '\x00' {
			return string(bytes[:i])
		}
	}

	return ""
}

func Insert[T any](s []T, ndx int, new_el T) []T {
	s = append(s, make([]T, 1)...)
	copy(s[ndx:len(s)-1], s[ndx+1:len(s)-1])
	s[ndx] = new_el
	return s
}

// Find item in slice and return it's index, if none found return -1
func FindIf[T any](haystack []T, eq func(el T) bool) int {
	for i, v := range haystack {
		if eq(v) {
			return i
		}
	}

	return -1
}
