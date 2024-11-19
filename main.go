package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	jks "github.com/lwithers/minijks/jks"
	pkcs12 "github.com/pschou/go-pkcs12"
	"golang.org/x/term"
)

var (
	passwordIn = flag.String("inpass", "", "Provide password for reading encrypted file (ignored if not encrypted)\n"+
		"Read from file: \"file:passfile.txt\" environment: \"env:PASSWORD\" cmd flag: \"pass:pa55w0rd\"")
	passwordOut = flag.String("outpass", "same-as-in", "Provide output password for written files\n"+
		"Read from file: \"file:passfile.txt\" environment: \"env:PASSWORD\" cmd flag: \"pass:pa55w0rd\"\n"+
		"If omitted, the input password is used as the output password.")
	certAlgorithm = flag.String("certAlgorithm", "PBES2", "Certificate Algorithm")
	matchString   = flag.String("match", "", "Include only certificates matching an expression.\n"+
		"Example: 'cn=my.domain' or for matching two 'cn=~test.*,o=\"my org\"'\n"+
		"= equal, =~ regex match, != not equal, !~ regex doesn't match\n"+
		"To match issuer use issuer_cn=\"my.ca\"")
	keyAlgorithm       = flag.String("keyAlgorithm", "PBES2", "Key Algorithm")
	macAlgorithm       = flag.String("macAlgorithm", "SHA256", "Key Algorithm")
	pbes2HmacAlgorithm = flag.String("pbes2-hmac", "SHA256", "Key Algorithm")
	pbes2EncAlgorithm  = flag.String("pbes2-enc", "AES256CBC", "PBE2 Encryption Algorithm")
	saltLength         = flag.Int("saltLength", 20, "Define the length of the salt")
	iterations         = flag.Int("iterations", 10000, "Define the number of iterations")
	ignoreExpired      = flag.Bool("ignore-expired", false, "Drop any expired certificates")
	dedup              = flag.Bool("dedup", true, "Drop any duplicate certificates")
	dropSHA1           = flag.Bool("drop-SHA1", false, "Drop any SHA1 signed certificates")
	version            string

	matchers []*matcher
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "pkcs, Version", version, "(https://github.com/pschou/pkcs)")
		_, exec := path.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "Usage:\n  "+exec+" [flags] in_file.p12 [out_file.p12 out_file.jks ...]\n  "+
			exec+" [flags] in_file.jks [out_file.jks out_file.p12...]\n  "+
			exec+" [flags] in_crt.pem,in_key.pem [out_file.jks out_file.p12...]  # for a pair of pem files\n"+
			"Note: Input and output can be the same name for an in place conversion.\n"+
			"Flags:\n")
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "Output formats can be set by a prefix (ie crt:myfile) or suffix (myfile.crt).\n",
			"Available prefixes:\n  pkcs8key key pkcs8ukey ukey pkcs1ukey pkcs1key pkcs7cert cert pkcs7cert8ukey both pkcs7cert8key pkcs12 jks\n",
			"Available Suffixes:\n  cert cer crt p12 pfx key ukey jks\n",
		)
		fmt.Fprint(os.Stderr, "PBE Algorithms Available:\n  ", stringsJoin(mapToSlice(pkcs12.PBE_Algorithms_Available), ", ", "  ", 100), "\n")
		fmt.Fprint(os.Stderr, "PBE MACs Available:\n  ", stringsJoin(mapToSlice(pkcs12.PBE_MACs_Available), ", ", "  ", 100), "\n")
		fmt.Fprint(os.Stderr, "PBES2 Ciphers Available:\n  ", stringsJoin(mapToSlice(pkcs12.PBES2_Ciphers_Available), ", ", "  ", 100), "\n")
		fmt.Fprint(os.Stderr, "PBES2 HMACs Available:\n  ", stringsJoin(mapToSlice(pkcs12.PBES2_HMACs_Available), ", ", "  ", 100), "\n")
	}
	flag.Parse()
	files := flag.Args()
	switch len(files) {
	case 0:
		flag.Usage()
		os.Exit(0)
	case 1:
		FailF("Must provide an input file and at least one output file")
	}

	encoder := &pkcs12.P12{
		MACAlgorithm:         pkcs12.PBE_MACs_Available[*macAlgorithm],
		CertBagAlgorithm:     pkcs12.PBE_Algorithms_Available[*certAlgorithm],
		KeyBagAlgorithm:      pkcs12.PBE_Algorithms_Available[*keyAlgorithm],
		MACIterations:        uint(*iterations),
		EncryptionIterations: uint(*iterations),
	}

	{ // compile matchers
		matchSlice := sliceQuotedString(*matchString)
		for _, s := range matchSlice {
			m := newMatcher(s)
			matchers = append(matchers, m)
		}
	}

	// check algorithms
	if v, ok := pkcs12.PBE_MACs_Available[*macAlgorithm]; !ok {
		FailF("Invalid MAC PBE Algorithm: %q", *macAlgorithm)
	} else {
		encoder.MACAlgorithm = v
	}
	if v, ok := pkcs12.PBE_Algorithms_Available[*certAlgorithm]; !ok {
		FailF("Invalid Cert PBE Algorithm: %q", *certAlgorithm)
	} else {
		encoder.CertBagAlgorithm = v
	}
	if v, ok := pkcs12.PBE_Algorithms_Available[*keyAlgorithm]; !ok {
		FailF("Invalid Key Algorithm: %q", *keyAlgorithm)
	} else {
		encoder.KeyBagAlgorithm = v
	}
	if v, ok := pkcs12.PBES2_HMACs_Available[*pbes2HmacAlgorithm]; !ok {
		FailF("Invalid PBES2 HMAC Algorithm: %q", *pbes2HmacAlgorithm)
	} else {
		encoder.PBES2_HMACAlgorithm = v
	}
	pcs8Algo := x509.PEMCipherAES256
	if v, ok := pkcs12.PBES2_Ciphers_Available[*pbes2EncAlgorithm]; !ok {
		FailF("Invalid PBES2 Cipher Algorithm: %q", *pbes2EncAlgorithm)
	} else {
		encoder.PBES2_EncryptionAlgorithm = v
		for i, c := range []string{"DES-CBC", "DES-EDE3-CBC", "AES128CBC", "AES192CBC", "AES256CBC"} {
			if c == *pbes2EncAlgorithm {
				pcs8Algo = x509.PEMCipher(i + 1)
			}
		}
	}

	/*
	 * Parse out the input password
	 */
	if *passwordIn == "" {
		fmt.Fprintf(os.Stderr, "Enter Password for %q: ", files[0])
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			FailF("Error reading password: %v", err)
		}
		*passwordIn = strings.TrimSpace(string(bytePassword))
	} else {
		parts := strings.SplitN(*passwordIn, ":", 2)
		if len(parts) < 2 {
			FailF("Invalied password parameter")
		}
		switch parts[0] {
		case "pass":
			*passwordIn = parts[1]
		case "file":
			dat, err := os.ReadFile(parts[1])
			if err != nil {
				FailF("Error reading password file: %v", err)
			}
			*passwordIn = strings.TrimSpace(string(dat))
		case "env":
			*passwordIn = os.Getenv(parts[1])
		default:
			FailF("Invalid password input format")
		}
	}

	/*
	 * Parse out the output password
	 */
	if *passwordOut == "same-as-in" {
		*passwordOut = *passwordIn
	} else if *passwordOut == "" {
		fmt.Fprintf(os.Stderr, "Enter Password for %q: ", files[0])
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			FailF("Error reading password: %v", err)
		}
		*passwordOut = strings.TrimSpace(string(bytePassword))
	} else {
		parts := strings.SplitN(*passwordOut, ":", 2)
		if len(parts) < 2 {
			FailF("Invalied password parameter")
		}
		switch parts[0] {
		case "pass":
			*passwordOut = parts[1]
		case "file":
			dat, err := os.ReadFile(parts[1])
			if err != nil {
				FailF("Error reading password file: %v", err)
			}
			*passwordOut = strings.TrimSpace(string(dat))
		case "env":
			*passwordOut = os.Getenv(parts[1])
		default:
			FailF("Invalid password input format")
		}
	}

	encoder.Password = []rune(*passwordOut)

	dat, err := os.ReadFile(files[0])
	if err != nil {
		err = nil
		if parts := strings.Split(files[0], ","); len(parts) == 2 {
			dat0, err := os.ReadFile(parts[0])
			if err != nil {
				FailF("Error reading file: %v", err)
			}
			dat1, err := os.ReadFile(parts[1])
			if err != nil {
				FailF("Error reading file: %v", err)
			}
			dat = append(append(dat0, '\n'), dat1...)
		}
	}
	if err != nil {
		FailF("Error reading file: %v", err)
	} else if len(dat) < 100 {
		FailF("Too small of file")
	}

	var keys []interface{}
	var certs []*x509.Certificate
	var ks *jks.Keystore

	/*
	 * Try reading PEM file
	 */
	for block, remain := pem.Decode(dat); block != nil; block, remain = pem.Decode(remain) {
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			var pkey []byte
			if x509.IsEncryptedPEMBlock(block) {
				pkey, err = x509.DecryptPEMBlock(block, []byte(*passwordIn))
				if err != nil {
					FailF("Error decoding PEM key: %v", err)
				}
			} else if block.Type == "ENCRYPTED PRIVATE KEY" {
				var info encryptedContentInfo
				trailing, err := asn1.Unmarshal(block.Bytes, &info)
				if err != nil {
					FailF("Error decoding private key: %v", err)
				}
				if len(trailing) != 0 {
					FailF("Trailing bytes at end of encrypted private key")
				}
				pkey, _, _, _, err = pkcs12.BagDecrypt(info, []rune(*passwordIn))
				if err != nil {
					FailF("Error decoding private key: %v", err)
				}
			} else {
				pkey = block.Bytes
				//fmt.Printf("blocks: %02x  %d\n", pkey, len(pkey))
			}
			if priv, err := parsePrivateKey(pkey); err != nil {
				FailF("Unable to parse private key: %v", err)
			} else {
				keys = append(keys, priv)
			}
		} else if block.Type == "CERTIFICATE" {
			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				FailF("Invalid cert: %v", err)
			}
			certs = append(certs, x509Cert)
		}
	}
	/*
		for i, c := range chain {
			if findCert(c, privateKey) == nil {
				cert = c
				chain = append(chain[:i], chain[i+1:]...)
				break
			}
		}
	*/

	/*
	 * Try reading a JKS file
	 */
	if len(certs) == 0 && len(keys) == 0 && bytes.Equal(dat[:4], []byte{0xFE, 0xED, 0xFE, 0xED}) {
		// Try reading JKS file
		ks, err = jks.Parse(dat, &jks.Options{Password: *passwordIn})
		if err != nil {
			FailF("Error reading JKS file %q: %v", files[0], err)
		}
		for _, c := range ks.Certs {
			if c.Cert != nil {
				certs = append(certs, c.Cert)
			}
		}
		for _, k := range ks.Keypairs {
			keys = append(keys, k.PrivateKey)
			for _, c := range k.CertChain {
				if c.Cert != nil {
					certs = append(certs, c.Cert)
				}
			}
		}
	}

	if len(certs) == 0 && len(keys) == 0 {
		// Try reading p12 file
		P12 := &pkcs12.P12{Password: []rune(*passwordIn)}

		// Make sure the file is in binary format, if the p12 is in base64, convert to binary first
		if dec, err := base64.StdEncoding.DecodeString(string(dat)); err == nil {
			dat = []byte(dec)
		}

		err = pkcs12.Unmarshal(dat, P12)
		if err == nil {
			for _, k := range P12.KeyEntries {
				keys = append(keys, k.Key)
			}
			for _, c := range P12.CertEntries {
				certs = append(certs, c.Cert)
			}
			/*	var ksChain []keystore.Certificate
				for _, c := range P12.CertEntries {
					if findCert(c, k.Key) == nil {
						ksChain = append(ksChain, keystore.Certificate{
							Type:    "X.509",
							Content: c.Cert.Raw,
						})
					}
				}

				privateDER, err := x509.MarshalPKCS8PrivateKey(k.Key)
				if err != nil {
					FailF("Error marshalling private key: %v", err)
				}
				ks.SetPrivateKeyEntry(fmt.Sprintf("%d", i+1), keystore.PrivateKeyEntry{
					CreationTime:     time.Now(),
					PrivateKey:       privateDER,
					CertificateChain: ksChain,
				}, []byte(password))
			}*/
		}
	}

	/*
	 * Try reading BER/DER file
	 */
	if len(certs) == 0 && len(keys) == 0 {
		// Attempt to read one from the file, TODO: Test reading in more than one
		for test := dat; false; {
			var elm asn1.RawContent
			next, err := asn1.Unmarshal(test, &elm)
			if err != nil || len(next) == 0 {
				break
			}
			if x509Cert, err := x509.ParseCertificate(elm); err == nil {
				certs = append(certs, x509Cert)
				test = next
			} else if pkey, err := parsePrivateKey(elm); err == nil {
				keys = append(keys, pkey)
				test = next
			} else {
				var info encryptedContentInfo
				trailing, err := asn1.Unmarshal(test, &info)
				if err != nil {
					break
				}
				if len(trailing) != 0 {
					break
				}
				pkey, _, _, _, err = pkcs12.BagDecrypt(info, []rune(*passwordIn))
				if err != nil {
					break
				}
				keys = append(keys, pkey)
				test = trailing
				continue
			}
		}
	}

	if *dedup {
		dedupMap := make(map[string]struct{})
		var new_certs []*x509.Certificate
		for _, x509Cert := range certs {
			if _, ok := dedupMap[string(x509Cert.Raw)]; !ok {
				dedupMap[string(x509Cert.Raw)] = struct{}{}
				new_certs = append(new_certs, x509Cert)
			}
		}
		certs = new_certs
	}

	if *dropSHA1 {
		var new_certs []*x509.Certificate
		for _, x509Cert := range certs {
			if x509Cert.SignatureAlgorithm == x509.SHA1WithRSA {
				continue
			}
			new_certs = append(new_certs, x509Cert)
		}
		certs = new_certs
	}

	if *ignoreExpired {
		var new_certs []*x509.Certificate
		for _, x509Cert := range certs {
			if time.Now().After(x509Cert.NotAfter) {
				continue
			}
			if time.Now().Before(x509Cert.NotBefore) {
				continue
			}
			new_certs = append(new_certs, x509Cert)
		}
		certs = new_certs
	}

	var p12Dat, jksDat []byte

	if len(certs) == 0 {
		fmt.Println("Warning: No certificate found.  Cannot generate stores.")
	} else {
		// If a key was provided, loop over the keys and build the certificate chains
		if len(keys) > 0 {
			ks = &jks.Keystore{}
			var dedup_certs = make(map[*x509.Certificate]struct{})

		key_loop:
			for _, key := range keys {
				keypair := &jks.Keypair{PrivateKey: key}
				for _, c := range certs {
					if findCert(c, key) == nil {
						//fmt.Println("common name", c.Subject.CommonName, include.MatchString(c.Subject.CommonName), (exclude != nil && exclude.MatchString(c.Subject.CommonName)))
						if len(matchers) > 0 && !matchNames(matchers, c.Subject, c.Issuer) {
							continue key_loop
						}
						cn := c.Subject.CommonName
						if cn == "" {
							cn = PKIString(c.Subject)
						}
						keypair.CertChain = []*jks.KeypairCert{&jks.KeypairCert{
							Cert: c,
							Raw:  c.Raw,
						}}
						keypair.Alias = cn
						keypair.Timestamp = time.Now()

						keyentry := pkcs12.KeyEntry{
							Key:          key,
							FriendlyName: cn,
						}

						// Update the entries
						encoder.KeyEntries = append(encoder.KeyEntries, keyentry)
						encoder.CertEntries = append(encoder.CertEntries, pkcs12.CertEntry{
							Cert:         c,
							FriendlyName: cn,
						})
						ks.Keypairs = append(ks.Keypairs, keypair)

						// add the cert only if needed
						if _, ok := dedup_certs[c]; !ok {
							encoder.CertEntries = append(encoder.CertEntries, pkcs12.CertEntry{
								Cert:         c,
								FriendlyName: cn,
							})
							dedup_certs[c] = struct{}{}
						}
						for i := findNext(c, certs); i != nil; i = findNext(i, certs) {
							keypair.CertChain = append(keypair.CertChain, &jks.KeypairCert{Raw: i.Raw, Cert: i})
							// add the cert only if needed
							if _, ok := dedup_certs[i]; !ok {
								encoder.CertEntries = append(encoder.CertEntries, pkcs12.CertEntry{
									Cert:         c,
									FriendlyName: cn,
								})
								dedup_certs[i] = struct{}{}
							}
						}

						break
					}
				}
			}
			encoder.GenerateSalts(*saltLength)

			// Build P12 blob
			p12Dat, err = pkcs12.Marshal(encoder)
			if err != nil {
				FailF("Error encoding pkcs12: %v", err)
			}

			// Build JKS blob
			jksDat, err = ks.Pack(&jks.Options{Password: *passwordOut})
			if err != nil {
				FailF("Error building KS: %v", err)
			}
		} else {
			ts := &pkcs12.TrustStore{
				MACAlgorithm:              encoder.MACAlgorithm,
				CertBagAlgorithm:          encoder.CertBagAlgorithm,
				Password:                  encoder.Password,
				MACIterations:             encoder.MACIterations,
				EncryptionIterations:      encoder.EncryptionIterations,
				PBES2_EncryptionAlgorithm: encoder.PBES2_EncryptionAlgorithm,
				PBES2_HMACAlgorithm:       encoder.PBES2_HMACAlgorithm,
			}
			ts.GenerateSalts(*saltLength)
			var new_certs []*x509.Certificate
			for _, c := range certs {
				if len(matchers) > 0 && !matchNames(matchers, c.Subject, c.Issuer) {
					continue
				}
				new_certs = append(new_certs, c)
				cn := c.Subject.CommonName
				if cn == "" {
					cn = PKIString(c.Subject)
				}
				ts.Entries = append(ts.Entries, pkcs12.TrustStoreEntry{
					FriendlyName: cn,
					Cert:         c,
				})
			}
			certs = new_certs

			// Build P12 blob
			p12Dat, err = pkcs12.MarshalTrustStore(ts)
			if err != nil {
				FailF("Error encoding pkcs12: %v", err)
			}
			jksDat = p12Dat
		}
	}

	// Loop over outputs and write out results
	for _, outFile := range files[1:] {
		var outType string
		parts := strings.SplitN(outFile, ":", 2)
		if len(parts) == 2 {
			switch parts[0] {
			case "pkcs8key", "key":
				outType, outFile = parts[0], parts[1]
			case "pkcs8ukey", "ukey":
				outType, outFile = parts[0], parts[1]
			case "pkcs1ukey":
				outType, outFile = parts[0], parts[1]
			case "pkcs1key":
				outType, outFile = parts[0], parts[1]
			case "pkcs7cert", "cert":
				outType, outFile = "pkcs7cert", parts[1]
			case "pkcs7cert8ukey", "both":
				outType, outFile = "pkcs7cert8ukey", parts[1]
			case "pkcs7cert8key":
				outType, outFile = parts[0], parts[1]
			case "pkcs12":
				outType, outFile = parts[0], parts[1]
			case "jks":
				outType, outFile = parts[0], parts[1]
			}
		}
		if outType == "" {
			switch {
			case strings.HasSuffix(outFile, ".cert") || strings.HasSuffix(outFile, ".crt") || strings.HasSuffix(outFile, ".cer"):
				outType = "pkcs7cert"
			case strings.HasSuffix(outFile, ".p12") || strings.HasSuffix(outFile, ".pfx"):
				outType = "pkcs12"
			case strings.HasSuffix(outFile, ".jks"):
				outType = "jks"
			case strings.HasSuffix(outFile, ".key"):
				outType = "pkcs8key"
			case strings.HasSuffix(outFile, ".ukey"):
				outType = "pkcs8ukey"
			}
		}
		if outType == "" {
			FailF("Unable to determine file type for %q.", outFile)
		}

		var toWrite []byte
		switch outType {
		case "pkcs12":
			toWrite = p12Dat
		case "jks":
			toWrite = jksDat
		case "pkcs8ukey":
			for _, key := range keys {
				privateDER, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: privateDER, Type: keyKind(key)})...)
			}
		case "pkcs8key":
			for _, key := range keys {

				salt := make([]byte, *saltLength)
				if _, err = rand.Read(salt); err != nil {
					FailF("Couldn't get random: %v", err)
				}
				encryptedDER, err := pkcs12.EncodePkcs8ShroudedKeyBagWithPassword(rand.Reader, key, []rune(*passwordIn),
					encoder.KeyBagAlgorithm, encoder.PBES2_HMACAlgorithm, encoder.PBES2_EncryptionAlgorithm, encoder.MACIterations, salt)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: encryptedDER, Type: "ENCRYPTED PRIVATE KEY"})...)
			}
		case "pkcs1key":
			for _, key := range keys {
				if rsakey, ok := key.(*rsa.PrivateKey); ok {
					privateDER := x509.MarshalPKCS1PrivateKey(rsakey)
					encrypted, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privateDER, []byte(*passwordOut), pcs8Algo)
					toWrite = append(toWrite, pem.EncodeToMemory(encrypted)...)
				}
			}
		case "pkcs1ukey":
			for _, key := range keys {
				if rsakey, ok := key.(*rsa.PrivateKey); ok {
					privateDER := x509.MarshalPKCS1PrivateKey(rsakey)
					toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: privateDER, Type: "RSA PRIVATE KEY"})...)
				}
			}
		case "pkcs7cert", "pkcs1cert":
			for _, c := range certs {
				toWrite = append(toWrite, []byte(fmt.Sprintf("subject=%s\n", PKIString(c.Subject)))...)
				if len(c.DNSNames) > 0 {
					toWrite = append(toWrite, []byte("san_dns="+strings.Join(c.DNSNames, ",")+"\n")...)
				}
				if len(c.IPAddresses) > 0 {
					toWrite = append(toWrite, []byte("san_ip="+JoinIP(c.IPAddresses, ",")+"\n")...)
				}
				if PKIString(c.Subject) != PKIString(c.Issuer) {
					toWrite = append(toWrite, []byte(fmt.Sprintf("issuer=%s\n", PKIString(c.Issuer)))...)
				}
				toWrite = append(toWrite, []byte(fmt.Sprintf("created=%s\n", c.NotBefore))...)
				toWrite = append(toWrite, []byte(fmt.Sprintf("expires=%s\n", c.NotAfter))...)
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: c.Raw, Type: "CERTIFICATE"})...)
			}
		case "pkcs7cert8key", "pkcs1cert8key":
			for _, c := range certs {
				toWrite = append(toWrite, []byte(fmt.Sprintf("subject=%s\n", PKIString(c.Subject)))...)
				if len(c.DNSNames) > 0 {
					toWrite = append(toWrite, []byte("san_dns="+strings.Join(c.DNSNames, ",")+"\n")...)
				}
				if len(c.IPAddresses) > 0 {
					toWrite = append(toWrite, []byte("san_ip="+JoinIP(c.IPAddresses, ",")+"\n")...)
				}
				if PKIString(c.Subject) != PKIString(c.Issuer) {
					toWrite = append(toWrite, []byte(fmt.Sprintf("issuer=%s\n", PKIString(c.Issuer)))...)
				}
				toWrite = append(toWrite, []byte(fmt.Sprintf("created=%s\n", c.NotBefore))...)
				toWrite = append(toWrite, []byte(fmt.Sprintf("expires=%s\n", c.NotAfter))...)
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: c.Raw, Type: "CERTIFICATE"})...)
			}
			for _, key := range keys {
				salt := make([]byte, 8)
				if _, err = rand.Read(salt); err != nil {
					FailF("Couldn't get random: %v", err)
				}
				encryptedDER, err := pkcs12.EncodePkcs8ShroudedKeyBagWithPassword(rand.Reader, key, []rune(*passwordIn),
					encoder.KeyBagAlgorithm, encoder.PBES2_HMACAlgorithm, encoder.PBES2_EncryptionAlgorithm, encoder.MACIterations, salt)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: encryptedDER, Type: "ENCRYPTED PRIVATE KEY"})...)
			}
		case "pkcs7cert8ukey", "pkcs1cert8ukey":
			for _, key := range keys {
				privateDER, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: privateDER, Type: keyKind(key)})...)
			}
			for _, c := range certs {
				toWrite = append(toWrite, []byte(fmt.Sprintf("subject=%s\n", PKIString(c.Subject)))...)
				if PKIString(c.Subject) != PKIString(c.Issuer) {
					toWrite = append(toWrite, []byte(fmt.Sprintf("issuer=%s\n", PKIString(c.Issuer)))...)
				}
				toWrite = append(toWrite, []byte(fmt.Sprintf("created=%s\n", c.NotBefore))...)
				toWrite = append(toWrite, []byte(fmt.Sprintf("expires=%s\n", c.NotAfter))...)
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: c.Raw, Type: "CERTIFICATE"})...)
			}
		}
		fh, err := os.Create(outFile)
		if err != nil {
			FailF("Error writing to file: %v", err)
		}
		io.Copy(fh, bytes.NewReader(toWrite))
		fh.Close()
	}

	//fmt.Printf("keystore: %#v\n", ks)
	//fmt.Printf("key: %#v\ncert: %#v\nca: %#v\n", privateKey, cert, chain)
}

func mapToSlice(in map[string]asn1.ObjectIdentifier) (out []string) {
	for v, _ := range in {
		out = append(out, v)
	}
	sort.Strings(out)
	return
}

type Encoder struct {
	macAlgorithm         asn1.ObjectIdentifier
	certAlgorithm        asn1.ObjectIdentifier
	keyAlgorithm         asn1.ObjectIdentifier
	macIterations        int
	encryptionIterations int
	saltLen              int
	rand                 io.Reader
}

func FailF(s string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	os.Exit(1)
}

func keyKind(key crypto.PrivateKey) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		return "EC PRIVATE KEY"
	case ed25519.PrivateKey:
	}
	return "PRIVATE KEY"
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func findNext(pub *x509.Certificate, list []*x509.Certificate) (next *x509.Certificate) {
	if pub.Subject.String() == pub.Issuer.String() {
		return nil
	}
	for _, c := range list {
		if c == pub {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(c)
		opts := x509.VerifyOptions{Roots: roots}
		if _, err := pub.Verify(opts); err == nil {
			return c
		}
	}
	return nil
}
func findCert(pub *x509.Certificate, priv interface{}) error {
	switch pub := pub.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return errors.New("tls: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return errors.New("tls: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("tls: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return errors.New("tls: private key does not match public key")
		}
	case ed25519.PublicKey:
		priv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return errors.New("tls: private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return errors.New("tls: private key does not match public key")
		}
	default:
		return errors.New("tls: unknown public key algorithm")
	}
	return nil
}
