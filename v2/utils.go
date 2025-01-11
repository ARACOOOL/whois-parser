package v2

import (
	"strings"
	"time"
)

// cleanValue removes the key and trims excess spaces from the value.
func cleanValue(line, key string) string {
	return strings.TrimSpace(strings.Replace(line, key, "", 1))
}

// parseDate parses a date string using the provided format and returns a time.Time pointer.
func parseDate(format, dateStr string) *time.Time {
	t, err := time.Parse(format, dateStr)
	if err != nil {
		return nil
	}
	return &t
}
