// Tests for code review fixes
package triplesec

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDeriveKeyReturnsExactExtraBytes verifies that DeriveKey returns
// exactly the requested number of extra bytes, not all cached bytes
func TestDeriveKeyReturnsExactExtraBytes(t *testing.T) {
	password := []byte("test")
	salt := bytes.Repeat([]byte{0xAA}, SaltLen)

	c, err := NewCipher(password, salt, 4)
	require.NoError(t, err)

	// First call: request 32 extra bytes
	dk1, extra1, err := c.DeriveKey(32)
	require.NoError(t, err)
	require.Len(t, dk1, c.versionParams.DkLen)
	require.Len(t, extra1, 32)

	// Second call (cached): request only 10 extra bytes
	dk2, extra2, err := c.DeriveKey(10)
	require.NoError(t, err)
	require.Len(t, dk2, c.versionParams.DkLen)
	// This is the key test: should return exactly 10 bytes, not all 32 cached bytes
	require.Len(t, extra2, 10)

	// Verify dk slices are the same (from cache)
	require.Same(t, &dk1[0], &dk2[0])

	// Third call: request more than cached (should re-derive)
	_, extra3, err := c.DeriveKey(50)
	require.NoError(t, err)
	require.Len(t, extra3, 50)
}

// TestCacheInvalidationWithoutDerivdKeySalt verifies that cache
// invalidation works correctly without the derivedKeySalt field
func TestCacheInvalidationWithoutDerivedKeySalt(t *testing.T) {
	password := []byte("password")
	salt1 := bytes.Repeat([]byte{0x01}, SaltLen)
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)

	c, err := NewCipher(password, salt1, 4)
	require.NoError(t, err)

	// Derive key with salt1
	dk1, _, err := c.DeriveKey(0)
	require.NoError(t, err)
	dk1Copy := append([]byte{}, dk1...)

	// Cache should be populated
	require.NotNil(t, c.derivedKey)

	// Change salt to salt2 (should invalidate cache)
	err = c.SetSalt(salt2)
	require.NoError(t, err)

	// Cache should be cleared
	require.Nil(t, c.derivedKey)

	// Derive key with salt2 (should be different)
	dk2, _, err := c.DeriveKey(0)
	require.NoError(t, err)

	// Keys should be different (derived from different salts)
	require.NotEqual(t, dk1Copy, dk2)

	// Set salt back to salt1
	err = c.SetSalt(salt1)
	require.NoError(t, err)

	// Derive again - should get same key as original
	dk3, _, err := c.DeriveKey(0)
	require.NoError(t, err)
	require.Equal(t, dk1Copy, dk3)
}

func TestCipherOwnsSensitiveInputs(t *testing.T) {
	password := []byte("password")
	originalPassword := bytes.Clone(password)
	salt := bytes.Repeat([]byte{0x01}, SaltLen)
	originalSalt := bytes.Clone(salt)

	c, err := NewCipher(password, salt, 4)
	require.NoError(t, err)

	// Mutating constructor inputs must not alter Cipher state.
	scrub(password)
	scrub(salt)
	ciphertext, err := c.Encrypt([]byte("message"))
	require.NoError(t, err)
	require.Equal(t, originalSalt, ciphertext[8:24])

	fresh, err := NewCipher(originalPassword, nil, 4)
	require.NoError(t, err)
	_, err = fresh.Decrypt(ciphertext)
	require.NoError(t, err)

	// GetSalt must not expose the internal salt backing array.
	exposedSalt, err := c.GetSalt()
	require.NoError(t, err)
	scrub(exposedSalt)
	ciphertext, err = c.Encrypt([]byte("another message"))
	require.NoError(t, err)
	require.Equal(t, originalSalt, ciphertext[8:24])

	// Scrub must clear only the Cipher's owned copy of the passphrase.
	callerPassword := []byte("another password")
	scrubCipher, err := NewCipher(callerPassword, nil, 4)
	require.NoError(t, err)
	scrubCipher.Scrub()
	require.Equal(t, []byte("another password"), callerPassword)
}

func TestDecryptDoesNotRetainCiphertextSalt(t *testing.T) {
	password := []byte("password")
	producer, err := NewCipher(password, bytes.Repeat([]byte{0x03}, SaltLen), 4)
	require.NoError(t, err)
	ciphertext, err := producer.Encrypt([]byte("first message"))
	require.NoError(t, err)

	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)
	_, err = c.Decrypt(ciphertext)
	require.NoError(t, err)

	// Callers own src and may reuse it after Decrypt returns.
	scrub(ciphertext[8:24])
	nextCiphertext, err := c.Encrypt([]byte("second message"))
	require.NoError(t, err)
	fresh, err := NewCipher(password, nil, 4)
	require.NoError(t, err)
	_, err = fresh.Decrypt(nextCiphertext)
	require.NoError(t, err)
}

// TestHeaderLenNotDuplicated verifies there's no duplicate calculation
// by ensuring Decrypt works correctly (integration test)
func TestHeaderLenNotDuplicated(t *testing.T) {
	password := []byte("test")
	plaintext := []byte("test message")

	for _, version := range []Version{3, 4} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			c, err := NewCipher(password, nil, version)
			require.NoError(t, err)

			ciphertext, err := c.Encrypt(plaintext)
			require.NoError(t, err)

			result, err := c.Decrypt(ciphertext)
			require.NoError(t, err)
			require.Equal(t, plaintext, result)
		})
	}
}
