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
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/twofish" //nolint
)

type RandomnessGenerator interface {
	Read(b []byte) (n int, err error)
}

type CryptoRandGenerator struct{}

func (crg CryptoRandGenerator) Read(b []byte) (n int, err error) {
	return rand.Read(b)
}

func NewCryptoRandGenerator() CryptoRandGenerator {
	return CryptoRandGenerator{}
}

var _ RandomnessGenerator = (*CryptoRandGenerator)(nil)

type RandomTapeGenerator struct {
	randomTape *bytes.Reader
}

func NewRandomTapeGenerator(randomTape []byte) RandomTapeGenerator {
	return RandomTapeGenerator{bytes.NewReader(randomTape)}
}

func (rtg RandomTapeGenerator) Read(b []byte) (n int, err error) {
	return rtg.randomTape.Read(b)
}

var _ RandomnessGenerator = (*RandomTapeGenerator)(nil)

const (
	SaltLen         = 16
	VersionBytesLen = 4
	AESIVLen        = 16
	TwofishIVLen    = 16
	SalsaIVLen      = 24
	MacOutputLen    = 64
	MacKeyLen       = 48
	CipherKeyLen    = 32

	// MaxDeriveKeyExtra is the maximum number of additional bytes callers may
	// request from DeriveKey. Known production callers require at most 128
	// bytes; the larger limit leaves room for future uses while bounding memory.
	MaxDeriveKeyExtra = 1024

	// The only supported cross-version difference is the additional Twofish
	// key present in v3. Keep this internal bound separate from the exported
	// DeriveKey API, which may be used as a general KDF by callers.
	maxCrossVersionKeyExtra = CipherKeyLen
)

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
	3: {
		TotalIVLen:        AESIVLen + TwofishIVLen + SalsaIVLen,
		TotalMacLen:       2 * MacOutputLen,
		TotalMacKeyLen:    2 * MacKeyLen,
		DkLen:             2*MacKeyLen + 3*CipherKeyLen,
		UseTwofish:        true,
		UseKeccakOverSHA3: true,
		Version:           3,
	},
	4: {
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
	rng           RandomnessGenerator
}

func scrub(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewCipher makes an instance of TripleSec using a particular key and
// a particular salt. It copies the passphrase and salt.
func NewCipher(passphrase []byte, salt []byte, version Version) (*Cipher, error) {
	return NewCipherWithRng(passphrase, salt, version, NewCryptoRandGenerator())
}

// NewCipherWithRng makes an instance of TripleSec using a particular key and
// a particular salt and uses a given randomness stream.
//
// WARNING: The rng parameter must be a cryptographically secure random number
// generator (CSPRNG). Using a deterministic or low-entropy generator will
// destroy confidentiality due to IV reuse across the stream cipher layers.
// This parameter exists for deterministic test vectors only. Production code
// should use NewCipher, which correctly uses crypto/rand.
func NewCipherWithRng(passphrase []byte, salt []byte, version Version, rng RandomnessGenerator) (*Cipher, error) {
	if salt != nil && len(salt) != SaltLen {
		return nil, fmt.Errorf("Need a salt of size %d", SaltLen)
	}
	var versionParams VersionParams
	var ok bool
	if versionParams, ok = versionParamsLookup[version]; !ok {
		return nil, fmt.Errorf("Not a valid version")
	}
	// Cipher owns its sensitive inputs so that callers can safely reuse or
	// scrub their buffers without changing cached key-derivation state.
	return &Cipher{bytes.Clone(passphrase), bytes.Clone(salt), nil, versionParams, rng}, nil
}

// Scrub zeros out sensitive key material in the Cipher.
//
// Callers should defer this after creating a Cipher to ensure key material
// is cleared from memory:
//
//	c, _ := NewCipher(passphrase, nil, version)
//	defer c.Scrub()
//
// Note: Due to Go's garbage collector and stack copying, this is best-effort
// and cannot guarantee that all copies of key material are removed from memory.
func (c *Cipher) Scrub() {
	scrub(c.passphrase)
	scrub(c.derivedKey)
}

// SetSalt replaces the Cipher's salt with a copy of the first SaltLen bytes.
func (c *Cipher) SetSalt(salt []byte) error {
	if len(salt) < SaltLen {
		return fmt.Errorf("need salt of at least %d bytes", SaltLen)
	}
	newSalt := salt[0:SaltLen]
	// Invalidate cached derived key if salt changes to prevent using stale keys
	if bytes.Equal(c.salt, newSalt) {
		return nil
	}
	c.derivedKey = nil
	// Keep an owned copy: Decrypt passes a view into the caller's ciphertext,
	// and retaining that view would let later caller mutations bypass cache
	// invalidation.
	c.salt = bytes.Clone(newSalt)
	return nil
}

// GetSalt returns a copy of the Cipher's salt. If the Cipher has no salt, it
// generates and stores one before returning the copy.
func (c *Cipher) GetSalt() ([]byte, error) {
	if c.salt != nil {
		return bytes.Clone(c.salt), nil
	}
	c.salt = make([]byte, SaltLen)
	_, err := c.rng.Read(c.salt)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(c.salt), nil
}

func (c *Cipher) DeriveKey(extra int) ([]byte, []byte, error) {
	if extra < 0 {
		return nil, nil, fmt.Errorf("extra must be non-negative, got %d", extra)
	}
	if extra > MaxDeriveKeyExtra {
		return nil, nil, fmt.Errorf("extra must not exceed %d bytes, got %d", MaxDeriveKeyExtra, extra)
	}

	dkLen := c.versionParams.DkLen + extra

	// SetSalt invalidates cache when salt changes, so we only need
	// to check if cache is nil or insufficient length
	if c.derivedKey == nil || len(c.derivedKey) < dkLen {
		dk, err := scrypt.Key(c.passphrase, c.salt, 32768, 8, 1, dkLen)
		if err != nil {
			return nil, nil, err
		}
		c.derivedKey = dk
	}

	// Return exactly the requested amount of extra bytes, not all cached bytes
	extraEnd := c.versionParams.DkLen + extra
	return c.derivedKey[0:c.versionParams.DkLen], c.derivedKey[c.versionParams.DkLen:extraEnd], nil
}

// MagicBytes are the four bytes prefixed to every TripleSec
// ciphertext, 1c 94 d7 de.
var MagicBytes = [4]byte{0x1c, 0x94, 0xd7, 0xde}

// Encrypt encrypts and signs a plaintext message with TripleSec using the
// Cipher's salt and passphrase. If the Cipher was created without a salt, one
// is generated on its first use and retained for later calls. The dst buffer
// size must be at least len(src) + Overhead. dst and src can not overlap. src
// is left untouched.
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
	encryptedData, err := encryptData(src, cipherKeys, c.rng, c.versionParams)
	if err != nil {
		return
	}

	authenticatedData := make([]byte, 0, buf.Len()+len(encryptedData))
	authenticatedData = append(authenticatedData, buf.Bytes()...)
	authenticatedData = append(authenticatedData, encryptedData...)
	macsOutput := generateMACs(authenticatedData, macKeys, c.versionParams)

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

func encryptData(plain, keys []byte, rng RandomnessGenerator, versionParams VersionParams) ([]byte, error) {
	var iv, key []byte
	var block cipher.Block
	var stream cipher.Stream

	ivOffset := versionParams.TotalIVLen
	res := make([]byte, len(plain)+ivOffset)

	// Generate IVs
	iv = res[:ivOffset]
	_, err := rng.Read(iv)
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

	cipherOffset := 0

	// Salsa20
	// For some reason salsa20 API is different
	keyArray := new([32]byte)
	defer scrub(keyArray[:]) // Zero out key material after use
	copy(keyArray[:], keys[len(keys)-cipherOffset-CipherKeyLen:])
	cipherOffset += CipherKeyLen
	salsa20.XORKeyStream(res[ivOffset:], plain, salsaIV, keyArray)
	ivOffset -= len(salsaIV)

	// Twofish
	if versionParams.UseTwofish {
		key = keys[len(keys)-cipherOffset-CipherKeyLen : len(keys)-cipherOffset]
		cipherOffset += CipherKeyLen
		block, err = twofish.NewCipher(key)
		if err != nil {
			return nil, err
		}
		stream = cipher.NewCTR(block, twofishIV)
		stream.XORKeyStream(res[ivOffset:], res[ivOffset:])
		ivOffset -= len(twofishIV)
	}

	// AES
	key = keys[len(keys)-cipherOffset-CipherKeyLen : len(keys)-cipherOffset]
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream = cipher.NewCTR(block, aesIV)
	stream.XORKeyStream(res[ivOffset:], res[ivOffset:])
	ivOffset -= len(aesIV)

	if ivOffset != 0 {
		return nil, CorruptionError{msg: "something went terribly wrong during encryption: ivOffset final value non-zero"}
	}

	return res, nil
}

func generateMACs(data, keys []byte, versionParams VersionParams) []byte {
	res := make([]byte, 0, 64*2)

	key := keys[:MacKeyLen]
	mac := hmac.New(sha512.New, key)
	_, _ = mac.Write(data)
	res = mac.Sum(res)

	key = keys[MacKeyLen:]
	var digestmodFn func() hash.Hash
	if versionParams.UseKeccakOverSHA3 {
		digestmodFn = sha3.NewLegacyKeccak512
	} else {
		digestmodFn = sha3.New512
	}
	mac = hmac.New(digestmodFn, key)
	_, _ = mac.Write(data)
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
		err = CorruptionError{msg: "decryption underrun"}
		return
	}

	if !bytes.Equal(src[:len(MagicBytes)], MagicBytes[0:]) {
		err = CorruptionError{msg: "wrong magic bytes"}
		return
	}

	vB := bytes.NewBuffer(src[len(MagicBytes) : len(MagicBytes)+VersionBytesLen])
	var version Version
	err = binary.Read(vB, binary.BigEndian, &version)
	if err != nil {
		err = CorruptionError{msg: err.Error(), err: err}
		return
	}

	versionParams, ok := versionParamsLookup[version]
	if !ok {
		return nil, VersionError{v: version}
	}

	// Validate full minimum length before any indexing to prevent panic on malformed input
	if len(src) < versionParams.Overhead() {
		err = CorruptionError{msg: fmt.Sprintf("ciphertext too short: got %d bytes, need at least %d", len(src), versionParams.Overhead())}
		return
	}

	err = c.SetSalt(src[8:24])
	if err != nil {
		return
	}

	// Use ciphertext's versionParams consistently for cross-version decryption
	// Calculate extra bytes needed if ciphertext version differs from constructor version
	extraBytes := 0
	if versionParams.DkLen > c.versionParams.DkLen {
		extraBytes = versionParams.DkLen - c.versionParams.DkLen
	}
	if extraBytes > maxCrossVersionKeyExtra {
		return nil, fmt.Errorf("unsupported cross-version key length difference: %d", extraBytes)
	}

	_, _, err = c.DeriveKey(extraBytes)
	if err != nil {
		return
	}

	// DeriveKey guarantees that the cache contains the constructor version's
	// key plus extraBytes, which is exactly the ciphertext version's key size.
	fullKey := c.derivedKey[:versionParams.DkLen]

	macKeys := fullKey[:versionParams.TotalMacKeyLen]
	cipherKeys := fullKey[versionParams.TotalMacKeyLen:]

	// Calculate header length once (magic + version + salt)
	headerLen := len(MagicBytes) + VersionBytesLen + SaltLen
	macEnd := headerLen + versionParams.TotalMacLen
	if len(src) < macEnd {
		err = CorruptionError{msg: "decryption underrun"}
		return
	}
	macs := src[headerLen:macEnd]
	encryptedData := src[macEnd:]

	// Authenticated data includes: magic + version + salt + encrypted data (but NOT the MACs)
	authenticatedData := make([]byte, 0, headerLen+len(encryptedData))
	authenticatedData = append(authenticatedData, src[:headerLen]...)
	authenticatedData = append(authenticatedData, encryptedData...)

	if !hmac.Equal(macs, generateMACs(authenticatedData, macKeys, versionParams)) {
		err = BadPassphraseError{}
		return
	}

	dst := make([]byte, len(src)-versionParams.Overhead())

	err = decryptData(dst, encryptedData, cipherKeys, versionParams)
	if err != nil {
		return
	}

	return dst, nil
}

func decryptData(dst, data, keys []byte, versionParams VersionParams) error {
	var iv, key []byte
	var block cipher.Block
	var stream cipher.Stream
	var err error

	buffer := append([]byte{}, data...)

	ivOffset := 0
	cipherOffset := 0

	ivOffset += AESIVLen
	iv = buffer[:ivOffset]
	key = keys[cipherOffset : cipherOffset+CipherKeyLen]
	cipherOffset += CipherKeyLen
	block, err = aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(buffer[ivOffset:], buffer[ivOffset:])

	if versionParams.UseTwofish {
		ivOffset += TwofishIVLen
		iv = buffer[ivOffset-TwofishIVLen : ivOffset]
		key = keys[cipherOffset : cipherOffset+CipherKeyLen]
		cipherOffset += CipherKeyLen
		block, err = twofish.NewCipher(key)
		if err != nil {
			return err
		}
		stream = cipher.NewCTR(block, iv)
		stream.XORKeyStream(buffer[ivOffset:], buffer[ivOffset:])
	}

	ivOffset += SalsaIVLen
	iv = buffer[ivOffset-SalsaIVLen : ivOffset]
	keyArray := new([32]byte)
	defer scrub(keyArray[:]) // Zero out key material after use
	copy(keyArray[:], keys[cipherOffset:cipherOffset+CipherKeyLen])
	salsa20.XORKeyStream(dst, buffer[ivOffset:], iv, keyArray)

	if len(buffer[ivOffset:]) != len(data)-versionParams.TotalIVLen {
		return CorruptionError{msg: "something went terribly wrong during decryption: buffer size is wrong"}
	}

	return nil
}
