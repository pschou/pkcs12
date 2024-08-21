# pkcs12
Generic PKCS conversion tool

```
$ ./pkcs -h
pkcs, Version 0.1.############# (https://github.com/pschou/pkcs)
Usage:
  pkcs [flags] in_file.p12 [out_file.p12 out_file.jks ...]
  pkcs [flags] in_file.jks [out_file.jks out_file.p12...]
  pkcs [flags] in_crt.pem,in_key.pem [out_file.jks out_file.p12...]  # for a pair of pem files
Note: Input and output can be the same name for an in place conversion.
Flags:
  -certAlgorithm string
        Certificate Algorithm (default "PBES2")
  -dedup
        Drop any duplicate certificates
  -drop-SHA1
        Drop any SHA1 signed certificates
  -ignore-expired
        Drop any expired certificates
  -inpass string
        Provide password for reading encrypted file (ignored if not encrypted)
        Read from file: "file:passfile.txt" environment: "env:PASSWORD" cmd flag: "pass:pa55w0rd"
  -iterations int
        Define the number of iterations (default 10000)
  -keyAlgorithm string
        Key Algorithm (default "PBES2")
  -macAlgorithm string
        Key Algorithm (default "SHA256")
  -match string
        Include only certificates matching an expression.
        Example: 'cn=my.domain' or for matching two 'cn=~test.*,o="my org"'
        = equal, =~ regex match, != not equal, !~ regex doesn't match
        To match issuer use issuer_cn="my.ca"
  -outpass string
        Provide output password for written files
        Read from file: "file:passfile.txt" environment: "env:PASSWORD" cmd flag: "pass:pa55w0rd"
        If omitted, the input password is used as the output password. (default "same-as-in")
  -pbes2-enc string
        PBE2 Encryption Algorithm (default "AES256CBC")
  -pbes2-hmac string
        Key Algorithm (default "SHA256")
  -saltLength int
        Define the length of the salt (default 20)
Output formats can be set by a prefix (ie crt:myfile) or suffix (myfile.crt).
Available prefixes:
  pkcs8key key pkcs8ukey ukey pkcs1ukey pkcs1key pkcs7cert cert pkcs7cert8ukey both pkcs7cert8key pkcs12 jks
Available Suffixes:
  cert cer crt p12 pfx key ukey jks
PBE Algorithms Available:
  None, PBES2, PBEWithSHAAnd128BitRC2CBC, PBEWithSHAAnd128BitRC4, PBEWithSHAAnd2KeyTripleDESCBC,
  PBEWithSHAAnd3KeyTripleDESCBC, PBEWithSHAAnd40BitRC2CBC, PBEWithSHAAnd40BitRC4
PBE MACs Available:
  GOST3411_256, GOST3411_512, MD2, MD4, MD5, SHA1, SHA256, SHA256_224, SHA384, SHA3_224, SHA3_256,
  SHA3_384, SHA3_512, SHA3_SHAKE128, SHA3_SHAKE256, SHA512, SHA512_224, SHA512_256
PBES2 Ciphers Available:
  AES128CBC, AES192CBC, AES256CBC, DES-CBC, DES-EDE3-CBC
PBES2 HMACs Available:
  GOST3411_256, GOST3411_512, MD5, SHA1, SHA256, SHA256_224, SHA3_224, SHA3_256, SHA3_384,
  SHA3_512, SHA512, SHA512_224, SHA512_256, SHA512_384
```
