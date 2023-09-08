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
