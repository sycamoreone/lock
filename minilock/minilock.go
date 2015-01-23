// Package minilock implements the minilock encrypted file format.
package minilock

import (
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"

	"github.com/sycamoreone/base58"
	"github.com/sycamoreone/blake2s"
)

var (
	ErrEncryption            = err{1, "General encryption error"}
	ErrDecryption            = err{2, "General decryption error"}
	ErrParseHeader           = err{3, "Could not parse header"}
	ErrHeaderVersion         = err{4, "Invalid header version"}
	ErrInvalidSenderID       = err{5, "Could not validate sender ID"}
	ErrInvalidRecipient      = err{6, "File is not encrypted for this recipient"}
	ErrInvalidCiphertextHash = err{7, "Could not validate ciphertext hash"}
)

type err struct {
	code int
	str  string
}

func (e err) Error() string {
	return fmt.Sprint(e.str)
}

var magicBytes = [8]byte{0x6d, 0x69, 0x6e, 0x69, 0x4c, 0x6f, 0x63, 0x6b}

func DeriveKeys(passwd, mail []byte) (pk, sk *[32]byte, err error) {
	pk = new([32]byte)
	sk = new([32]byte)
	sum := blake2s.Sum256(passwd)
	skBuf, err := scrypt.Key(sum[:], mail, 1<<17, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	copy(sk[:], skBuf)
	curve25519.ScalarBaseMult(pk, sk)
	return
}

func ID(pk *[32]byte) string {
	config := &blake2s.Config{Size: 1}
	hash, err := blake2s.New(config)
	if err != nil {
		panic(err)
	}

	id := make([]byte, 33)
	copy(id, pk[:])
	hash.Write(pk[:])
	id[32] = hash.Sum(nil)[0]

	return base58.Encode(id)
}
