package main

import (
	"crypto/aes"
	"crypto/cipher"

	//"crypto/rand"
	"crypto/sha256"
	"fmt"

	//"io"

	"github.com/enceve/crypto/pad"
	"golang.org/x/crypto/pbkdf2"
)

func main() {

	msg := "changeme"
	passwd := "qwerty"
	size := 32

	// pwsalt := getSalt(16) // 96 bits for nonce/IV
	pwsalt := []byte{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}
	key := pbkdf2.Key([]byte(passwd), pwsalt, 14, size, sha256.New)
	fmt.Printf("passwd %s, pwsalt %s,key: %v\n", passwd, pwsalt, key)

	block, _ := aes.NewCipher(key)
	fmt.Printf("block size: %d\n", block.BlockSize())
	var plain []byte
	var ciphertext []byte

	plaintext := []byte(msg)

	// Block cipher
	plain = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)
	ciphertext = make([]byte, (len(plaintext)/16+1)*aes.BlockSize)
	salt := []byte{'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}
	fmt.Printf("salt: %v\n", salt)
	pkcs7 := pad.NewPKCS7(aes.BlockSize)
	pad1 := pkcs7.Pad(plaintext)
	fmt.Printf("pad1: %v\n", pad1)

	blk := cipher.NewCBCEncrypter(block, salt)
	blk.CryptBlocks(ciphertext, pad1)
	blk = cipher.NewCBCDecrypter(block, salt)
	blk.CryptBlocks(plain, ciphertext)
	plain, _ = pkcs7.Unpad(plain)

	fmt.Printf("Key size:\t%d bits\n", size*8)
	fmt.Printf("Message:\t%s\n", msg)

	fmt.Printf("Password:\t%s\n", passwd)
	fmt.Printf("Password Salt:\t%x\n", pwsalt)
	fmt.Printf("\nKey:\t\t%x\n", key)
	fmt.Printf("\nCipher:\t\t%x\n", ciphertext) // 908d7f287f548a8c93e12e8204332862

	fmt.Printf("Salt:\t\t%x\n", salt)
	fmt.Printf("\nDecrypted:\t%s\n", plain)
}
