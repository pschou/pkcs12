package main

import (
	"crypto/x509/pkix"
	"strings"
)

// Encode a certificate into a string using RFC2253
func PKIString(name pkix.Name) string {
	var ret []string
	for i := len(name.Names) - 1; i >= 0; i-- {
		ret = append(ret,
			pkix.RDNSequence([]pkix.RelativeDistinguishedNameSET{name.Names[i : i+1]}).String())
	}
	return strings.Join(ret, ",")
}
