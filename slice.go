package main

import "strings"

func sliceQuotedString(str string) []string {
	var quote []rune
	var escape bool
	return strings.FieldsFunc(strings.TrimSpace(str),
		func(r rune) bool {
			if len(quote) > 0 {
				m1 := len(quote) - 1
				if r == quote[m1] {
					quote = quote[:m1]
					return false
				}
			}
			// Escape char sequence
			if r == '\\' {
				escape = !escape
				return false
			}
			// Skipping an escape char
			if escape {
				escape = false
				return false
			}
			// Nested quote
			if len(quote) > 0 && (quote[len(quote)-1] == '"' || quote[len(quote)-1] == '\'') {
				return false
			}
			// Opening q quote section
			switch {
			case r == '"', r == '\'':
				quote = append(quote, r)
				return false
			case r == '{':
				quote = append(quote, '}')
				return false
			}
			return len(quote) == 0 && (r == ' ' || r == ',' || r == '\t' || r == ';' || r == '\n')
		})
}
