// Package minilock implements the minilock encrypted file format.
package minilock

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
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

// header is used to unmarshal the JSON header of a minilock file.
type header struct {
	Version     int               `json:"version"`
	Ephemeral   []byte       `json:"ephemeral"`
	EncryptedDecryptInfo   map[string][]byte `json:"decryptInfo"`
	decryptInfo     `json:"-"`
}

type decryptInfo struct {
	SenderID    string `json:"senderID"`
	RecipientID string `json:"recipientID"`
	EncryptedFileInfo []byte `json:"fileInfo"`

	nonce *[24]byte `json:"-"`
	fileInfo `json:"-"`
}

type fileInfo struct {
	FileKey   []byte `json:"fileKey"`
	FileNonce []byte `json:"fileNonce"`
	FileHash  []byte `json:"fileHash"`
}

func parseHeader(r io.Reader) (*header, error) {
	buf := make([]byte, 8)
	_, err := io.ReadAtLeast(r, buf, 8)
	if err != nil {
		return nil, ErrParseHeader
	}
	if !bytes.Equal(buf, magicBytes[:]) {
		return nil, ErrParseHeader
	}

	buf = buf[:4]
	_, err = io.ReadAtLeast(r, buf, 4)
	if err != nil {
		return nil, ErrParseHeader
	}
	hdrLen := int(binary.LittleEndian.Uint32(buf))

	buf = make([]byte, hdrLen)
	_, err = io.ReadAtLeast(r, buf, hdrLen)
	if err != nil {
		return nil, ErrParseHeader
	}

	var hdr header
	err = json.Unmarshal(buf, &hdr)
	return &hdr, err
}

func decodeBase64(s string) ([]byte, error) {
	len := base64.StdEncoding.DecodedLen(len(s))
	buf := make([]byte, len)
	n, err := base64.StdEncoding.Decode(buf, []byte(s))
	return buf[:n], err
}

func IDToPublic(s string) (*[32]byte, error) {
	buf, err := base58.Decode(s)
	if err != nil {
		return nil, err
	}
	return sliceTo32Bytes(buf), nil
}

func sliceTo32Bytes(b []byte) *[32]byte {
	if len(b) < 32 {
		panic("sliceTo32Bytes got passed a to short slice")
	}
	r := new([32]byte)
	copy(r[:], b)
	return r
}

func sliceTo24Bytes(b []byte) *[24]byte {
	if len(b) < 24 {
		panic("sliceTo24Bytes got passed a to short slice")
	}
	r := new([24]byte)
	copy(r[:], b)
	return r
}

func fullNonce(fileNonce []byte, chunkNumber uint64) *[24]byte {
	nonce := new([24]byte)
	copy(nonce[:], fileNonce)
	binary.LittleEndian.PutUint64(nonce[16:], chunkNumber)
	return nonce
}

// TODO Find a better API for the chunking.
// This function should also return the number of bytes used from the slice, and if it is the lastChunk or not.
// This will simplify the code in Open()
func decryptChunk(out, chunk []byte, fullNonce *[24]byte, fileKey *[32]byte) ([]byte, bool) {
	len := binary.LittleEndian.Uint32(chunk)
	if len > uint32(1048576) {
		return out, false
	}
	chunk = chunk[4:]
	out, ok := secretbox.Open(out, chunk[:len+secretbox.Overhead], fullNonce, fileKey)
	return out, ok
}

// Open decrypts a minilock encrypted file and returns the filename and the contents of the file.
func Open(r io.Reader, pk, sk *[32]byte) (filename string, content []byte, err error) {
	// TODO: Open could return a io.Reader and do streaming decryption of chunks in a goroutine.
	// Not sure if this is necessary, but this is why there are chunks in the format to begin with.
	hdr, err := parseHeader(r)
	if err != nil {
		return "", nil, err
	}

	// TODO: A lot of the code below should go into a decryptHeader(hdr *header) function.
	for n, c := range hdr.EncryptedDecryptInfo {
		buf, err := decodeBase64(n)
		if err != nil {
			return "", nil, err
		}
		nonce := sliceTo24Bytes(buf)
		ephemeral := sliceTo32Bytes(hdr.Ephemeral)
		if m, ok := box.Open(nil, c, nonce, ephemeral, sk); ok {
			hdr.nonce = nonce
			err = json.Unmarshal(m, &hdr.decryptInfo)
			if err != nil {
				return "", nil, err
			}
			break
		}
	}

	senderPublic, err := IDToPublic(hdr.SenderID)
	if err != nil {
		return "", nil, err
	}
	buf, ok := box.Open(nil, hdr.EncryptedFileInfo, hdr.nonce, senderPublic, sk)
	if !ok {
		return "", nil, ErrDecryption
	}
	err = json.Unmarshal(buf, &hdr.fileInfo)
	if err != nil {
		return "", nil, ErrParseHeader
	}

	ourID := []byte(ID(pk))
	if subtle.ConstantTimeCompare([]byte(hdr.RecipientID), ourID) != 1 {
		return "", nil, ErrInvalidRecipient
	}

	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return "", nil, err
	}

	hash := blake2s.Sum256(ciphertext)
	if subtle.ConstantTimeCompare(hash[:], hdr.FileHash) != 1 {
		return  "", nil, ErrInvalidCiphertextHash
	}

	content = make([]byte, 0, len(ciphertext))
	fileKey := sliceTo32Bytes(hdr.FileKey)
	
	nonce := fullNonce(hdr.FileNonce, 0)
	name, ok := decryptChunk(nil, ciphertext, nonce, fileKey)
	if !ok {
		return "", nil, ErrDecryption
	}
	filename = string(name[:bytes.IndexByte(name, 0)])
	ciphertext = ciphertext[256 + 4 + secretbox.Overhead:]

	for n, lastChunk := uint64(1), false; lastChunk != true; n++ {
		if len(ciphertext) < 1048576+4+secretbox.Overhead {	// TODO: Use more constants!
			n = n | 1<<63 // Set the most significant bit.
			lastChunk = true
		}
		nonce := fullNonce(hdr.FileNonce, n)
		content, ok = decryptChunk(content, ciphertext, nonce, fileKey)
		if !ok {
			return "", nil, ErrDecryption
		}
		if !lastChunk {
			ciphertext = ciphertext[1048576+4+secretbox.Overhead:]
		}
	}

	return string(filename), content, nil
}
