package main

import (
	"crypto/x509/pkix"
)

type encryptedContentInfo struct {
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte {
	//fmt.Printf("data: %#v\n", i.EncryptedContent)
	return i.EncryptedContent
}

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }
