package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

var errUnpaddingFailed = errors.New("decrypt failed, perhaps you are using different keys to encrypt and decrypt")

// pkcs7Padding use PKCS7 to fill data blcok
// https://tools.ietf.org/html/rfc5652#section-6.3
func pkcs7Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

// pkcs7Unpadding use PKCS7 to unpad data blcok
func pkcs7Unpadding(text []byte) ([]byte, error) {
	length := len(text)
	unpadding := int(text[length-1])
	var rest = length - unpadding
	if rest < 0 {
		return text, errUnpaddingFailed
	}
	return text[:rest], nil
}

func main() {

	msg := "changeme"
	passwd := "qwerty"
	size := 32

	pwsalt := []byte{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}
	key := pbkdf2.Key([]byte(passwd), pwsalt, 14, size, sha256.New)
	fmt.Printf("Password:\t%s\n", passwd)
	fmt.Printf("Password Salt:\t%x\n", pwsalt)
	fmt.Printf("Key:\t\t%x\n", key)

	block, _ := aes.NewCipher(key)
	fmt.Printf("block size: %d\n", block.BlockSize())

	var res []byte
	var plaintext []byte
	var ciphertext []byte

	plaintext = []byte(msg)

	// Block cipher
	res = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)
	ciphertext = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)

	salt := []byte{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}
	fmt.Printf("salt: %v\n", salt)

	padtext := pkcs7Padding(plaintext, aes.BlockSize)
	fmt.Printf("padtext: %v\n", padtext)

	blk := cipher.NewCBCEncrypter(block, salt)
	blk.CryptBlocks(ciphertext, padtext)

	blk = cipher.NewCBCDecrypter(block, salt)
	blk.CryptBlocks(res, ciphertext)
	fmt.Printf("res with pad: %v\n", res)

	res, _ = pkcs7Unpadding(res)
	fmt.Printf("res without pad: %v\n", res)

	// fmt.Printf("Key size:\t%d bits\n", size*8)
	fmt.Printf("Message:\t%s\n", msg)

	fmt.Printf("\nCipher:\t\t%x\n", ciphertext) // 908d7f287f548a8c93e12e8204332862

	fmt.Printf("\nDecrypted:\t%s\n", res)
}
