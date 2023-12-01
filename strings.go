package main

import "net"

func stringsJoin(s []string, delim, indent string, l int) string {
	var ret, line string
	for i, v := range s {
		if i > 0 {
			line += delim
		}
		if len(line)+len(v)+len(delim)*2 < l {
			line += v
		} else {
			ret += line + "\n"
			line = indent + v
		}
	}
	ret += line
	return ret
}

func JoinIP(in []net.IP, sep string) string {
	var ret string
	for i, ip := range in {
		if i > 0 {
			ret += sep
		}
		ret += ip.String()
	}
	return ret
}
