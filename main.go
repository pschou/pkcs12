package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
		"Read from file: \"file:passfile.txt\" environment: \"env:PASSWORD\" cmd flag: \"pass:pa55w0rd\"")
	certAlgorithm = flag.String("certAlgorithm", "PBES2", "Certificate Algorithm")
	matchString   = flag.String("match", "cn~=.*", "Include only certificates matching an expression.\n"+
		"Example: 'cn=my.domain' or for matching two 'cn~=test.*,o=\"my org\"'\n"+
		"To match issuer use issuer_cn=\"my.ca\"")
	keyAlgorithm       = flag.String("keyAlgorithm", "PBES2", "Key Algorithm")
	macAlgorithm       = flag.String("macAlgorithm", "SHA256", "Key Algorithm")
	pbes2HmacAlgorithm = flag.String("pbes2-hmac", "SHA256", "Key Algorithm")
	pbes2EncAlgorithm  = flag.String("pbes2-enc", "AES256CBC", "PBE2 Encryption Algorithm")
	saltLength         = flag.Int("saltLength", 20, "Define the length of the salt")
	iterations         = flag.Int("iterations", 10000, "Define the number of iterations")
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
		fmt.Fprint(os.Stderr, "Output formats can be set by a prefix (ie crt:myfile) or suffix (myfile.crt).\n  ",
			"cert    - only certificates\n  ",
			"ukey    - unencrypted key\n  ",
			"p12 pfx - pkcs12 encoded key\n  ",
			"jks     - java keystore key\n  ",
			"both:   - prefix to indicate both the private and public key in one file\n",
		)
		fmt.Fprint(os.Stderr, "PBE Algorithms Available:\n  ", strings.Join(mapToSlice(pkcs12.PBE_Algorithms_Available), ", "), "\n")
		fmt.Fprint(os.Stderr, "PBE MACs Available:\n  ", strings.Join(mapToSlice(pkcs12.PBE_MACs_Available), ", "), "\n")
		fmt.Fprint(os.Stderr, "PBES2 Ciphers Available:\n  ", strings.Join(mapToSlice(pkcs12.PBES2_Ciphers_Available), ", "), "\n")
		fmt.Fprint(os.Stderr, "PBES2 HMACs Available:\n  ", strings.Join(mapToSlice(pkcs12.PBES2_HMACs_Available), ", "), "\n")
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
	if v, ok := pkcs12.PBES2_Ciphers_Available[*pbes2EncAlgorithm]; !ok {
		FailF("Invalid PBES2 Cipher Algorithm: %q", *pbes2EncAlgorithm)
	} else {
		encoder.PBES2_EncryptionAlgorithm = v
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
	if err != nil || len(dat) < 100 {
		FailF("Error reading file: %v", err)
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
			} else {
				pkey = block.Bytes
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
	if len(certs) == 0 && bytes.Equal(dat[:4], []byte{0xFE, 0xED, 0xFE, 0xED}) {
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

	if len(certs) == 0 {
		P12 := &pkcs12.P12{Password: []rune(*passwordIn)}
		// Try reading p12 file
		if dec, err := base64.StdEncoding.DecodeString(string(dat)); err == nil {
			dat = []byte(dec)
		}
		err = pkcs12.Unmarshal(dat, P12)
		if err != nil {
			FailF("Error reading P12 file %q: %v", files[0], err)
		}

		//fmt.Printf("p12: %#v\n", P12)

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

	if len(certs) == 0 {
		FailF("No certificate found.")
	}

	var p12Dat, jksDat []byte
	// If a key was provided, loop over the keys and build the certificate chains
	if len(keys) > 0 {
		ks = &jks.Keystore{}
		var new_certs []*x509.Certificate
		var dedup_certs = make(map[*x509.Certificate]struct{})

	key_loop:
		for _, key := range keys {
			keypair := &jks.Keypair{PrivateKey: key}
			keyentry := pkcs12.KeyEntry{Key: key}
			certentry := pkcs12.CertEntry{}
			for _, c := range certs {
				if findCert(c, key) == nil {
					//fmt.Println("common name", c.Subject.CommonName, include.MatchString(c.Subject.CommonName), (exclude != nil && exclude.MatchString(c.Subject.CommonName)))
					if !matchNames(matchers, c.Subject, c.Issuer) {
						continue key_loop
					}
					keypair.CertChain = []*jks.KeypairCert{&jks.KeypairCert{
						Cert: c,
						Raw:  c.Raw,
					}}
					keypair.Alias = c.Subject.CommonName
					keypair.Timestamp = time.Now()
					keyentry.FriendlyName = c.Subject.CommonName
					certentry.Cert = c
					certentry.FriendlyName = c.Subject.CommonName
					// add the cert only if needed
					if _, ok := dedup_certs[c]; !ok {
						new_certs = append(new_certs, c)
						dedup_certs[c] = struct{}{}
					}
					for i := findNext(c, certs); i != nil; i = findNext(i, certs) {
						keypair.CertChain = append(keypair.CertChain, &jks.KeypairCert{Raw: i.Raw, Cert: i})
						// add the cert only if needed
						if _, ok := dedup_certs[i]; !ok {
							new_certs = append(new_certs, i)
							dedup_certs[i] = struct{}{}
						}
					}
					break
				}
			}
			certs = new_certs
			encoder.KeyEntries = append(encoder.KeyEntries, keyentry)
			encoder.CertEntries = append(encoder.CertEntries, certentry)
			ks.Keypairs = append(ks.Keypairs, keypair)
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
			if !matchNames(matchers, c.Subject, c.Issuer) {
				continue
			}
			new_certs = append(new_certs, c)
			ts.Entries = append(ts.Entries, pkcs12.TrustStoreEntry{
				FriendlyName: c.Subject.CommonName,
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

	// Loop over outputs and write out results
	for _, outFile := range files[1:] {
		var toWrite []byte
		if strings.HasPrefix(outFile, "p12:") || strings.HasPrefix(outFile, "pfx:") {
			outFile = outFile[4:]
			toWrite = p12Dat
		} else if strings.HasPrefix(outFile, "jks:") {
			outFile = outFile[4:]
			toWrite = jksDat
		} else if pre := strings.HasPrefix(outFile, "ukey:"); pre || strings.HasSuffix(outFile, ".ukey") {
			if pre {
				outFile = outFile[5:]
			}
			for _, key := range keys {
				privateDER, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: privateDER, Type: "PRIVATE KEY"})...)
			}
		} else if pre := strings.HasPrefix(outFile, "cert:"); pre || strings.HasSuffix(outFile, ".cert") || strings.HasSuffix(outFile, ".crt") {
			if pre {
				outFile = outFile[5:]
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
		} else if strings.HasPrefix(outFile, "both:") {
			outFile = outFile[5:]
			for _, key := range keys {
				privateDER, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					FailF("Error encoding key: %v", err)
				}
				toWrite = append(toWrite, pem.EncodeToMemory(&pem.Block{Bytes: privateDER, Type: "PRIVATE KEY"})...)
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
		} else if strings.HasSuffix(outFile, ".p12") || strings.HasSuffix(outFile, ".pfx") {
			toWrite = p12Dat
		} else if strings.HasSuffix(outFile, ".jks") {
			toWrite = jksDat
		} else {
			FailF("Unable to determine file type for %q.", outFile)
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
