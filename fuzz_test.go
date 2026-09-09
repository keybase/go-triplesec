// Fuzz and robustness tests for malformed and boundary inputs.
package triplesec

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzDecrypt fuzzes the Decrypt function with random malformed inputs
// to ensure no panics occur (addresses truncation DoS vulnerability)
func FuzzDecrypt(f *testing.F) {
	// Seed corpus with valid ciphertexts
	password := []byte("test")
	plaintext := []byte("test message")

	// Add v3 and v4 ciphertexts as seeds
	for _, version := range []Version{3, 4} {
		c, err := NewCipher(password, nil, version)
		require.NoError(f, err)
		ciphertext, err := c.Encrypt(plaintext)
		require.NoError(f, err)
		f.Add(ciphertext)
	}

	// Add malformed seeds
	f.Add([]byte{})                                                  // Empty
	f.Add(MagicBytes[:])                                             // Just magic
	f.Add(append(MagicBytes[:], 0, 0, 0, 4))                         // Magic + version
	f.Add(append(MagicBytes[:], 0, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8)) // Magic + version + partial salt

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := NewCipher(password, nil, 4)
		require.NoError(t, err)

		// Should never panic, only return errors
		_, _ = c.Decrypt(data)
	})
}

// TestDecryptAllInvalidLengths tests every invalid length from 0 to Overhead
// with valid magic bytes and version to ensure proper error handling
func TestDecryptAllInvalidLengths(t *testing.T) {
	password := []byte("test")

	for _, version := range []Version{3, 4} {
		versionParams := versionParamsLookup[version]
		minValid := versionParams.Overhead()

		c, err := NewCipher(password, nil, version)
		require.NoError(t, err)

		// Test every invalid length with valid magic + version
		for length := range minValid {
			data := make([]byte, length)
			if length >= 4 {
				copy(data, MagicBytes[:])
			}
			if length >= 8 {
				// Set version bytes in big endian
				binary.BigEndian.PutUint32(data[4:8], uint32(version))
			}

			_, err := c.Decrypt(data)
			require.Error(t, err, "version %d, length %d", version, length)
		}
	}
}

// TestCacheInvalidationEdgeCases tests edge cases in cache invalidation logic
func TestCacheInvalidationEdgeCases(t *testing.T) {
	password := []byte("password")
	salt1 := bytes.Repeat([]byte{0x01}, SaltLen)
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)

	// Test 1: SetSalt with same salt should not invalidate
	c, err := NewCipher(password, salt1, 4)
	require.NoError(t, err)

	_, _, err = c.DeriveKey(0)
	require.NoError(t, err)

	cachedKey := c.derivedKey

	// Set same salt again
	err = c.SetSalt(salt1)
	require.NoError(t, err)

	// Cache should still be valid
	require.NotNil(t, c.derivedKey)
	// Compare slice pointers to verify it's the same underlying array
	require.NotEmpty(t, cachedKey)
	require.NotEmpty(t, c.derivedKey)
	require.Same(t, &cachedKey[0], &c.derivedKey[0])

	// Test 2: SetSalt with different salt should invalidate
	err = c.SetSalt(salt2)
	require.NoError(t, err)
	require.Nil(t, c.derivedKey)

	// Test 3: Multiple salt changes
	for i := range 10 {
		salt := bytes.Repeat([]byte{byte(i)}, SaltLen)
		err = c.SetSalt(salt)
		require.NoError(t, err, "iteration %d", i)

		_, _, err = c.DeriveKey(0)
		require.NoError(t, err, "iteration %d", i)
		require.NotNil(t, c.derivedKey, "iteration %d", i)
	}
}

// TestDeriveKeyExtraBytesEdgeCases tests edge cases for extra bytes parameter
func TestDeriveKeyExtraBytesEdgeCases(t *testing.T) {
	password := []byte("test")
	salt := bytes.Repeat([]byte{0xAA}, SaltLen)
	c, err := NewCipher(password, salt, 4)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		extra     int
		shouldErr bool
	}{
		{"zero extra", 0, false},
		{"small extra", 10, false},
		{"medium extra", 1000, false},
		{"maximum extra", MaxDeriveKeyExtra, false},
		{"over maximum", MaxDeriveKeyExtra + 1, true},
		{"negative", -1, true},
		{"negative large", -1000, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset cache for each test
			c.derivedKey = nil

			_, extra, err := c.DeriveKey(tc.extra)
			if tc.shouldErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, extra, tc.extra)
		})
	}
}

// TestDeriveKeyCacheReuseScenarios tests various cache reuse scenarios
func TestDeriveKeyCacheReuseScenarios(t *testing.T) {
	password := []byte("test")
	salt := bytes.Repeat([]byte{0xBB}, SaltLen)
	c, err := NewCipher(password, salt, 4)
	require.NoError(t, err)

	// Scenario 1: Request increasing amounts
	for extra := 0; extra <= 100; extra += 10 {
		dk, extraBytes, err := c.DeriveKey(extra)
		require.NoError(t, err, "extra %d", extra)
		require.Len(t, dk, c.versionParams.DkLen, "extra %d", extra)
		require.Len(t, extraBytes, extra, "extra %d", extra)
	}

	// Scenario 2: Request decreasing amounts (should use cache)
	for extra := 100; extra >= 0; extra -= 10 {
		_, extraBytes, err := c.DeriveKey(extra)
		require.NoError(t, err, "extra %d", extra)
		require.Len(t, extraBytes, extra, "extra %d", extra)
	}

	// Scenario 3: Random access pattern
	randomExtras := []int{50, 10, 75, 25, 100, 0, 60}
	for _, extra := range randomExtras {
		_, extraBytes, err := c.DeriveKey(extra)
		require.NoError(t, err, "extra %d", extra)
		require.Len(t, extraBytes, extra, "extra %d", extra)
	}
}

// TestCrossVersionDecryptionWithDifferentSalts ensures cross-version
// decryption works correctly when salts differ
func TestCrossVersionDecryptionWithDifferentSalts(t *testing.T) {
	password := []byte("test")
	plaintexts := [][]byte{
		[]byte("short"),
		[]byte("medium length message"),
		[]byte("a much longer message that spans multiple blocks and tests the full cipher cascade"),
	}

	for _, plaintext := range plaintexts {
		// Create v3 ciphertext
		c3, err := NewCipher(password, nil, 3)
		require.NoError(t, err)
		ct3, err := c3.Encrypt(plaintext)
		require.NoError(t, err)

		// Create v4 ciphertext
		c4, err := NewCipher(password, nil, 4)
		require.NoError(t, err)
		ct4, err := c4.Encrypt(plaintext)
		require.NoError(t, err)

		// Decrypt v3 with v4 cipher
		result, err := c4.Decrypt(ct3)
		require.NoError(t, err)
		require.Equal(t, plaintext, result)

		// Decrypt v4 with v3 cipher
		result, err = c3.Decrypt(ct4)
		require.NoError(t, err)
		require.Equal(t, plaintext, result)

		// Decrypt multiple times (cache should work correctly)
		for i := range 3 {
			result, err = c4.Decrypt(ct3)
			require.NoError(t, err, "round %d", i)
			require.Equal(t, plaintext, result, "round %d", i)
		}
	}
}

// TestScrubVerification verifies that Scrub actually zeros out key material
func TestScrubVerification(t *testing.T) {
	password := []byte("sensitive password")
	plaintext := []byte("sensitive data")

	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	// Encrypt to populate cache
	_, err = c.Encrypt(plaintext)
	require.NoError(t, err)

	// Verify cache is populated
	require.NotNil(t, c.derivedKey)

	// Call Scrub
	c.Scrub()

	// Verify passphrase is zeroed
	require.Equal(t, make([]byte, len(c.passphrase)), c.passphrase)

	// Verify derivedKey is zeroed
	require.NotNil(t, c.derivedKey)
	require.Equal(t, make([]byte, len(c.derivedKey)), c.derivedKey)
}
