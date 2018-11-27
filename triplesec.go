// The design and name of TripleSec is (C) Keybase 2013
// This Go implementation is (C) Filippo Valsorda 2014
// Use of this source code is governed by the MIT License

// Package triplesec implements the TripleSec v3 and v4 encryption and authentication scheme.
//
// For details on TripleSec, go to https://keybase.io/triplesec/
package triplesec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/twofish"

	"github.com/keybase/go-crypto/sha3"
)

const SaltLen = 16
const VersionBytesLen = 4
const AESIVLen = 16
const TwofishIVLen = 16
const SalsaIVLen = 24
const MacOutputLen = 64
const MacKeyLen = 48
const CipherKeyLen = 32

type Version uint32

var LatestVersion Version = 4

type VersionParams struct {
	MacKeyLen         int
	TotalIVLen        int
	TotalMacLen       int
	TotalMacKeyLen    int
	DkLen             int
	UseTwofish        bool
	UseKeccakOverSHA3 bool
	Version           Version
}

var versionParamsLookup = map[Version]VersionParams{
	3: VersionParams{
		TotalIVLen:        AESIVLen + TwofishIVLen + SalsaIVLen,
		TotalMacLen:       2 * MacOutputLen,
		TotalMacKeyLen:    2 * MacKeyLen,
		DkLen:             2*MacKeyLen + 3*CipherKeyLen,
		UseTwofish:        true,
		UseKeccakOverSHA3: true,
		Version:           3,
	},
	4: VersionParams{
		TotalIVLen:        AESIVLen + SalsaIVLen,
		TotalMacLen:       2 * MacOutputLen,
		TotalMacKeyLen:    2 * MacKeyLen,
		DkLen:             2*MacKeyLen + 2*CipherKeyLen,
		UseTwofish:        false,
		UseKeccakOverSHA3: false,
		Version:           4,
	},
}

func (vp *VersionParams) Overhead() int {
	return len(MagicBytes) + VersionBytesLen + SaltLen + vp.TotalMacLen + vp.TotalIVLen
}

type Cipher struct {
	passphrase    []byte
	salt          []byte
	derivedKey    []byte
	versionParams VersionParams
}

func scrub(b []byte) {
	for i, _ := range b {
		b[i] = 0
	}
}

// A Cipher is an instance of TripleSec using a particular key and
// a particular salt
func NewCipher(passphrase []byte, salt []byte, version Version) (*Cipher, error) {
	if salt != nil && len(salt) != SaltLen {
		return nil, fmt.Errorf("Need a salt of size %d", SaltLen)
	}
	var versionParams VersionParams
	var ok bool
	if versionParams, ok = versionParamsLookup[version]; !ok {
		return nil, fmt.Errorf("Not a valid version.")
	}
	return &Cipher{passphrase, salt, nil, versionParams}, nil
}

func (c *Cipher) Scrub() {
	scrub(c.passphrase)
	scrub(c.derivedKey)
}

func (c *Cipher) SetSalt(salt []byte) error {
	if len(salt) < SaltLen {
		return fmt.Errorf("need salt of at least %d bytes", SaltLen)
	}
	c.salt = salt[0:SaltLen]
	return nil
}

func (c *Cipher) GetSalt() ([]byte, error) {
	if c.salt != nil {
		return c.salt, nil
	}
	c.salt = make([]byte, SaltLen)
	_, err := rand.Read(c.salt)
	if err != nil {
		return nil, err
	}
	return c.salt, nil
}

func (c *Cipher) DeriveKey(extra int) ([]byte, []byte, error) {

	dkLen := c.versionParams.DkLen + extra

	if c.derivedKey == nil || len(c.derivedKey) < dkLen {
		dk, err := scrypt.Key(c.passphrase, c.salt, 32768, 8, 1, dkLen)
		if err != nil {
			return nil, nil, err
		}
		c.derivedKey = dk
	}
	return c.derivedKey[0:c.versionParams.DkLen], c.derivedKey[c.versionParams.DkLen:], nil
}

// The MagicBytes are the four bytes prefixed to every TripleSec
// ciphertext, 1c 94 d7 de.
var MagicBytes = [4]byte{0x1c, 0x94, 0xd7, 0xde}

// Encrypt encrypts and signs a plaintext message with TripleSec using a random
// salt and the Cipher passphrase. The dst buffer size must be at least len(src)
// + Overhead. dst and src can not overlap. src is left untouched.
//
// Encrypt returns a error on memory or RNG failures.
func (c *Cipher) Encrypt(src []byte) (dst []byte, err error) {
	if len(src) < 1 {
		return nil, fmt.Errorf("the plaintext cannot be empty")
	}

	dst = make([]byte, len(src)+c.versionParams.Overhead())
	buf := bytes.NewBuffer(dst[:0])

	_, err = buf.Write(MagicBytes[0:])
	if err != nil {
		return
	}

	// Write version
	err = binary.Write(buf, binary.BigEndian, c.versionParams.Version)
	if err != nil {
		return
	}

	salt, err := c.GetSalt()
	if err != nil {
		return
	}

	_, err = buf.Write(salt)
	if err != nil {
		return
	}

	dk, _, err := c.DeriveKey(0)
	if err != nil {
		return
	}
	macKeys := dk[:c.versionParams.TotalMacKeyLen]
	cipherKeys := dk[c.versionParams.TotalMacKeyLen:]

	// The allocation over here can be made better
	encryptedData, err := encrypt_data(src, cipherKeys, c.versionParams)
	if err != nil {
		return
	}

	authenticatedData := make([]byte, 0, buf.Len()+len(encryptedData))
	authenticatedData = append(authenticatedData, buf.Bytes()...)
	authenticatedData = append(authenticatedData, encryptedData...)
	macsOutput := generate_macs(authenticatedData, macKeys, c.versionParams)

	_, err = buf.Write(macsOutput)
	if err != nil {
		return
	}
	_, err = buf.Write(encryptedData)
	if err != nil {
		return
	}

	if buf.Len() != len(src)+c.versionParams.Overhead() {
		err = fmt.Errorf("something went terribly wrong: output size wrong")
		return
	}

	return buf.Bytes(), nil
}

func encrypt_data(plain, keys []byte, versionParams VersionParams) ([]byte, error) {
	var iv, key []byte
	var block cipher.Block
	var stream cipher.Stream

	iv_offset := versionParams.TotalIVLen
	res := make([]byte, len(plain)+iv_offset)

	// Generate IVs
	iv = res[:iv_offset]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	offset := 0
	aesIV := iv[offset : offset+AESIVLen]
	offset += AESIVLen
	var twofishIV []byte
	if versionParams.UseTwofish {
		twofishIV = iv[offset : offset+TwofishIVLen]
		offset += TwofishIVLen
	}
	salsaIV := iv[offset : offset+SalsaIVLen]
	offset += SalsaIVLen

	cipherOffset := 0

	// Salsa20
	// For some reason salsa20 API is different
	key_array := new([32]byte)
	copy(key_array[:], keys[len(keys)-cipherOffset-CipherKeyLen:])
	cipherOffset += CipherKeyLen
	salsa20.XORKeyStream(res[iv_offset:], plain, salsaIV, key_array)
	iv_offset -= len(salsaIV)

	// Twofish
	if versionParams.UseTwofish {
		key = keys[len(keys)-cipherOffset-CipherKeyLen : len(keys)-cipherOffset]
		cipherOffset += CipherKeyLen
		block, err = twofish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		stream = cipher.NewCTR(block, twofishIV)
		stream.XORKeyStream(res[iv_offset:], res[iv_offset:])
		iv_offset -= len(twofishIV)
	}

	// AES
	key = keys[len(keys)-cipherOffset-CipherKeyLen : len(keys)-cipherOffset]
	cipherOffset += CipherKeyLen
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream = cipher.NewCTR(block, aesIV)
	stream.XORKeyStream(res[iv_offset:], res[iv_offset:])
	iv_offset -= len(aesIV)

	if iv_offset != 0 {
		return nil, CorruptionError{"something went terribly wrong during encryption: iv_offset final value non-zero"}
	}

	return res, nil
}

func generate_macs(data, keys []byte, versionParams VersionParams) []byte {
	res := make([]byte, 0, 64*2)

	key := keys[:MacKeyLen]
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	res = mac.Sum(res)

	key = keys[MacKeyLen:]
	var digestmod_fn func() hash.Hash
	if versionParams.UseKeccakOverSHA3 {
		digestmod_fn = sha3.NewLegacyKeccak512
	} else {
		digestmod_fn = sha3.New512
	}
	mac = hmac.New(digestmod_fn, key)
	mac.Write(data)
	res = mac.Sum(res)

	return res
}

// Decrypt decrypts a TripleSec ciphertext using the Cipher passphrase.
// The dst buffer size must be at least len(src) - Overhead.
// dst and src can not overlap. src is left untouched.
//
// Encrypt returns a error if the ciphertext is not recognized, if
// authentication fails or on memory failures.
func (c *Cipher) Decrypt(src []byte) (res []byte, err error) {
	if len(src) < len(MagicBytes)+VersionBytesLen {
		err = CorruptionError{"decryption underrun"}
		return
	}

	if !bytes.Equal(src[:len(MagicBytes)], MagicBytes[0:]) {
		err = CorruptionError{"wrong magic bytes"}
		return
	}

	v_b := bytes.NewBuffer(src[len(MagicBytes) : len(MagicBytes)+VersionBytesLen])
	var version Version
	err = binary.Read(v_b, binary.BigEndian, &version)
	if err != nil {
		err = CorruptionError{err.Error()}
		return
	}

	versionParams, ok := versionParamsLookup[version]
	if !ok {
		return nil, VersionError{version}
	}

	err = c.SetSalt(src[8:24])
	if err != nil {
		return
	}

	dk, _, err := c.DeriveKey(0)
	if err != nil {
		return
	}
	macKeys := dk[:c.versionParams.TotalMacKeyLen]
	cipherKeys := dk[c.versionParams.TotalMacKeyLen:]

	macs := src[24 : 24+64*2]
	encryptedData := src[24+64*2:]

	authenticatedData := make([]byte, 0, 24+len(encryptedData))
	authenticatedData = append(authenticatedData, src[:24]...)
	authenticatedData = append(authenticatedData, encryptedData...)

	if !hmac.Equal(macs, generate_macs(authenticatedData, macKeys, versionParams)) {
		err = BadPassphraseError{}
		return
	}

	dst := make([]byte, len(src)-versionParams.Overhead())

	err = decrypt_data(dst, encryptedData, cipherKeys, versionParams)
	if err != nil {
		return
	}

	return dst, nil
}

func decrypt_data(dst, data, keys []byte, versionParams VersionParams) error {
	var iv, key []byte
	var block cipher.Block
	var stream cipher.Stream
	var err error

	buffer := append([]byte{}, data...)

	iv_offset := 0
	cipherOffset := 0

	iv_offset += AESIVLen
	iv = buffer[:iv_offset]
	key = keys[cipherOffset : cipherOffset+CipherKeyLen]
	cipherOffset += CipherKeyLen
	block, err = aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(buffer[iv_offset:], buffer[iv_offset:])

	if versionParams.UseTwofish {
		iv_offset += TwofishIVLen
		iv = buffer[iv_offset-TwofishIVLen : iv_offset]
		key = keys[cipherOffset : cipherOffset+CipherKeyLen]
		cipherOffset += CipherKeyLen
		block, err = twofish.NewCipher(key)
		if err != nil {
			return err
		}
		stream = cipher.NewCTR(block, iv)
		stream.XORKeyStream(buffer[iv_offset:], buffer[iv_offset:])
	}

	iv_offset += SalsaIVLen
	iv = buffer[iv_offset-SalsaIVLen : iv_offset]
	key_array := new([32]byte)
	copy(key_array[:], keys[cipherOffset:cipherOffset+CipherKeyLen])
	salsa20.XORKeyStream(dst, buffer[iv_offset:], iv, key_array)

	if len(buffer[iv_offset:]) != len(data)-versionParams.TotalIVLen {
		return CorruptionError{"something went terribly wrong during decryption: buffer size is wrong"}
	}

	return nil
}
