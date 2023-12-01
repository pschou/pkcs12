package main

import (
	"crypto/x509/pkix"
	"regexp"
	"strings"
)

type matcher struct {
	negate     bool
	reg        *regexp.Regexp
	field, str string
}

func newMatcher(str string) *matcher {
	//if str[len(str)-1] == '"' {
	//	str = str[:len(str)]
	for i := 0; ; i++ {
		switch {
		case i < len(str)-1 && str[i:i+2] == "=~":
			if r, err := regexp.Compile(unquote(str[i+2:])); err == nil {
				return &matcher{field: str[:i], reg: r}
			} else if err != nil {
				FailF("Invalid regexp %q", str[i+2:])
			}
		case str[i:i+1] == "=":
			return &matcher{field: str[:i], str: unquote(str[i+1:])}
		case i == len(str)-1:
			break
		case str[i:i+2] == "!=":
			return &matcher{field: str[:i], str: unquote(str[i+2:]), negate: true}
		case str[i:i+2] == "!~":
			if r, err := regexp.Compile(unquote(str[i+2:])); err == nil {
				return &matcher{field: str[:i], reg: r, negate: true}
			} else if err != nil {
				FailF("Invalid regexp %q", str[i+2:])
			}
		}
	}
	//}
	FailF("Invalid matching expression %q", str)
	return nil
}

func unquote(str string) string {
	if len(str) < 2 {
		return str
	}
	if a, z := str[0], str[len(str)-1]; (a == '"' && z == '"') || (a == '\'' || z == '\'') {
		return str[1 : len(str)-1]
	}
	return str
}

// Encode a certificate into a string using RFC2253
func matchNames(tests []*matcher, subject, issuer pkix.Name) (ret bool) {
	// loop over the certificate fields
	for i := range subject.Names {
		parts := strings.SplitN(pkix.RDNSequence([]pkix.RelativeDistinguishedNameSET{subject.Names[i : i+1]}).String(), "=", 2)
		//fmt.Println("filter match called for", parts)
		for _, t := range tests {
			//fmt.Printf("test: %#v\n", t)
			if strings.EqualFold(parts[0], t.field) {
				if t.reg == nil {
					if t.str == parts[1] && !t.negate {
						ret = true
					} else {
						return false
					}
				} else {
					// regex match
					if t.reg.MatchString(parts[1]) && !t.negate {
						ret = true
					} else {
						return false
					}
				}
			}
		}
	}

	// loop over the issuer fields
	for i := range issuer.Names {
		parts := strings.SplitN(pkix.RDNSequence([]pkix.RelativeDistinguishedNameSET{issuer.Names[i : i+1]}).String(), "=", 2)
		parts[0] = "issuer_" + parts[0]
		for _, t := range tests {
			if strings.EqualFold(parts[0], t.field) {
				if t.reg == nil {
					if t.str == parts[1] && !t.negate {
						ret = true
					} else {
						return false
					}
				} else {
					// regex match
					if t.reg.MatchString(parts[1]) && !t.negate {
						ret = true
					} else {
						return false
					}
				}
			}
		}
	}
	return
}
