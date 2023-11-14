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
	"unsafe"

	"github.com/pavel-v-chernykh/keystore-go/v4"
	"golang.org/x/term"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	passwordIn    = flag.String("pass", "", "Provide password from alternate source\nFor example: file:passfile.txt env:PASSWORD str:'pa55w0rd')")
	certAlgorithm = flag.String("certAlgorithm", "PBES2", "Certificate Algorithm")
	keyAlgorithm  = flag.String("keyAlgorithm", "PBES2", "Key Algorithm")
	macAlgorithm  = flag.String("macAlgorithm", "SHA256", "Key Algorithm")
	version       string
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "pkcs12, Version", version, "(https://github.com/pschou/pkcs12)")
		_, exec := path.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "Usage:\n  "+exec+" [flags] in_file.p12 [out_file.p12 out_file.jks ...]\n  "+
			exec+" [flags] in_file.jks [out_file.jks out_file.p12...]\n"+
			"Note: Input and output can be the same name for an in place conversion.\n"+
			"Flags:\n")
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "Hashes available:\n  ", strings.Join(mapToSlice(hashMap), "\n  "), "\n")
		fmt.Fprint(os.Stderr, "Algorithms available:\n  ", strings.Join(mapToSlice(algoMap), "\n  "), "\n")
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

	encoder := Encoder{
		macAlgorithm:         hashMap[*macAlgorithm],
		certAlgorithm:        algoMap[*certAlgorithm],
		keyAlgorithm:         algoMap[*keyAlgorithm],
		macIterations:        2048,
		encryptionIterations: 2048,
		saltLen:              16,
		rand:                 rand.Reader,
	}
	switch {
	case encoder.macAlgorithm == nil:
		FailF("Invalid MAC Algorithm: %q", *macAlgorithm)
	case encoder.certAlgorithm == nil:
		FailF("Invalid Cert Algorithm: %q", *macAlgorithm)
	case encoder.keyAlgorithm == nil:
		FailF("Invalid Key Algorithm: %q", *macAlgorithm)
	}

	var password string
	if *passwordIn == "" {
		fmt.Fprintf(os.Stderr, "Enter Password for %q: ", files[0])
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			FailF("Error reading password: %v", err)
		}
		password = strings.TrimSuffix(string(bytePassword), "\n")
	} else {
		parts := strings.SplitN(*passwordIn, ":", 2)
		if len(parts) < 2 {
			FailF("Invalied password parameter")
		}
		switch parts[0] {
		case "str":
			password = parts[1]
		case "file":
			dat, err := os.ReadFile(parts[1])
			if err != nil {
				FailF("Error reading password file: %v", err)
			}
			password = strings.TrimSpace(string(dat))
		case "env":
			password = os.Getenv(parts[1])
		}
	}

	dat, err := os.ReadFile(files[0])
	if err != nil || len(dat) < 100 {
		FailF("Error reading file: %v", err)
	}

	var privateKey interface{}
	var chain []*x509.Certificate
	var cert *x509.Certificate
	var ks = keystore.New()

	//	fmt.Printf("%02x\n", dat[:4])
	// Try reading JKS file
	if bytes.Equal(dat[:4], []byte{0xfe, 0xed, 0xfe, 0xed}) {
		err = ks.Load(bytes.NewReader(dat), []byte(password))
		if err != nil {
			FailF("Error reading JKS file %q: %v", files[0], err)
		}
		//var privateKey keystore.PrivateKeyEntry
		for _, alias := range ks.Aliases() {
			if ks.IsPrivateKeyEntry(alias) {
				PrivateKeyEntry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
				if err != nil {
					FailF("Error decoding private key %q", files[0])
				}
				//fmt.Printf("key: %#v\n", PrivateKeyEntry)

				if privateKey, err = parsePrivateKey(PrivateKeyEntry.PrivateKey); err != nil {
					FailF("Unable to parse private key: %v", err)
				}
				for _, c := range PrivateKeyEntry.CertificateChain {
					if c.Type != "X.509" {
						FailF("Unknown cert type: %q", c.Type)
					}
					x509Cert, err := x509.ParseCertificate(c.Content)
					if err != nil {
						FailF("Invalid cert: %v", err)
					}

					if findCert(x509Cert, privateKey) == nil {
						cert = x509Cert
					} else {
						chain = append(chain, x509Cert)
					}
				}
			}
		}
	} else {
		// Try reading p12 file
		if dec, err := base64.StdEncoding.DecodeString(string(dat)); err == nil {
			dat = []byte(dec)
		}
		privateKey, cert, chain, err = pkcs12.DecodeChain(dat, password)
		if err != nil {
			FailF("Error reading P12 file %q: %v", files[0], err)
		}
		if err = findCert(cert, privateKey); err != nil {
			FailF("Key - Certificate matching error: %v", err)
		}

		privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			FailF("Error marshalling private key: %v", err)
		}
		var ksChain []keystore.Certificate
		for _, c := range append([]*x509.Certificate{cert}, chain...) {
			ksChain = append(ksChain, keystore.Certificate{
				Type:    "X.509",
				Content: c.Raw,
			})
		}

		ks.SetPrivateKeyEntry("1", keystore.PrivateKeyEntry{
			CreationTime:     time.Now(),
			PrivateKey:       privateDER,
			CertificateChain: ksChain,
		}, []byte(password))
	}

	if cert == nil {
		FailF("No certificate found.")
	}

	// Build JKS blob
	var buf bytes.Buffer
	err = ks.Store(&buf, []byte(password))
	if err != nil {
		FailF("Error building KS: %v", err)
	}
	jksDat := buf.Bytes()

	// Build P12 blob
	p12Dat, err := (*pkcs12.Encoder)(unsafe.Pointer(&encoder)).Encode(privateKey, cert, chain, password)
	if err != nil {
		FailF("Error encoding pkcs12: %v", err)
	}

	for _, outFile := range files[1:] {
		var toWrite []byte
		if strings.HasPrefix(outFile, "p12:") || strings.HasPrefix(outFile, "pfx:") {
			outFile = outFile[4:]
			toWrite = p12Dat
		} else if strings.HasPrefix(outFile, "jks:") {
			outFile = outFile[4:]
			toWrite = jksDat
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

var algoMap = map[string]asn1.ObjectIdentifier{
	"PBEWithSHAAnd3KeyTripleDESCBC": asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3}),
	"PBEWithSHAAnd128BitRC2CBC":     asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 5}),
	"PBEWithSHAAnd40BitRC2CBC":      asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6}),
	"PBES2":                         asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 13}),
	"PBKDF2":                        asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 12}),
	"HmacWithSHA1":                  asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 7}),
	"HmacWithSHA256":                asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 9}),
	"AES128CBC":                     asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 2}),
	"AES192CBC":                     asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 22}),
	"AES256CBC":                     asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 42}),
}
var hashMap = map[string]asn1.ObjectIdentifier{
	"SHA1":   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	"SHA256": asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
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
