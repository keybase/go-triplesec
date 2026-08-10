// Validation tests for malformed inputs and API boundaries.
package triplesec

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIssue1_TruncatedCiphertext tests that truncated ciphertexts
// return an error instead of panicking (Issue #1 - High severity)
func TestIssue1_TruncatedCiphertext(t *testing.T) {
	c, err := NewCipher([]byte("password"), nil, 4)
	require.NoError(t, err)

	validHeader, err := hex.DecodeString("1c94d7de00000004")
	require.NoError(t, err)

	// Test various truncated lengths from 8 bytes up to just before minimum valid length
	versionParams := versionParamsLookup[4]
	minLen := versionParams.Overhead()

	for length := len(validHeader); length < minLen; length++ {
		testData := make([]byte, length)
		copy(testData, validHeader)

		// Should return error, not panic
		_, err := c.Decrypt(testData)
		require.Error(t, err, "length %d", length)
		var corruptionError CorruptionError
		require.ErrorAs(t, err, &corruptionError, "length %d", length)
	}
}

// TestIssue2_SaltCacheInvalidation tests that the cached derived key
// is invalidated when the salt changes (Issue #2 - Medium severity)
func TestIssue2_SaltCacheInvalidation(t *testing.T) {
	password := []byte("password123")
	plaintext := []byte("Hello, World!")
	salt1 := bytes.Repeat([]byte{0x01}, SaltLen)
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)

	producer1, err := NewCipher(password, salt1, 4)
	require.NoError(t, err)
	ciphertext1, err := producer1.Encrypt(plaintext)
	require.NoError(t, err)

	producer2, err := NewCipher(password, salt2, 4)
	require.NoError(t, err)
	ciphertext2, err := producer2.Encrypt(plaintext)
	require.NoError(t, err)

	// Reuse one consumer across deterministic salt changes. This must exercise
	// cache invalidation rather than depending on random salt behavior.
	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)
	result1, err := c.Decrypt(ciphertext1)
	require.NoError(t, err)
	require.Equal(t, plaintext, result1)

	result2, err := c.Decrypt(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, plaintext, result2)
}

// TestIssue3_VersionMismatch tests that a cipher can decrypt ciphertexts
// with different versions correctly (Issue #3 - Medium severity)
func TestIssue3_VersionMismatch(t *testing.T) {
	password := []byte("testpass")
	plaintext := []byte("test message")

	// Create v4 cipher
	c4, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	// Encrypt with v4
	ciphertext4, err := c4.Encrypt(plaintext)
	require.NoError(t, err)

	// Decrypt with v4 cipher - should work
	result4, err := c4.Decrypt(ciphertext4)
	require.NoError(t, err)
	require.Equal(t, plaintext, result4)

	// Create v3 cipher
	c3, err := NewCipher(password, nil, 3)
	require.NoError(t, err)

	// Encrypt with v3
	ciphertext3, err := c3.Encrypt(plaintext)
	require.NoError(t, err)

	// Decrypt with v3 cipher - should work
	result3, err := c3.Decrypt(ciphertext3)
	require.NoError(t, err)
	require.Equal(t, plaintext, result3)

	// Cross-version decryption: v4 cipher should be able to decrypt v3 ciphertext
	result3_4, err := c4.Decrypt(ciphertext3)
	require.NoError(t, err)
	require.Equal(t, plaintext, result3_4)

	// Cross-version decryption: v3 cipher should be able to decrypt v4 ciphertext
	result4_3, err := c3.Decrypt(ciphertext4)
	require.NoError(t, err)
	require.Equal(t, plaintext, result4_3)
}

// TestIssue5_DeriveKeyValidation tests that DeriveKey rejects
// invalid extra parameters (Issue #5 - Low severity)
func TestIssue5_DeriveKeyValidation(t *testing.T) {
	c, err := NewCipher([]byte("password"), nil, 4)
	require.NoError(t, err)

	// Generate a salt first
	_, err = c.GetSalt()
	require.NoError(t, err)

	// Test negative extra
	_, _, err = c.DeriveKey(-1)
	require.Error(t, err)

	// The documented maximum remains valid.
	_, extra, err := c.DeriveKey(MaxDeriveKeyExtra)
	require.NoError(t, err)
	require.Len(t, extra, MaxDeriveKeyExtra)

	// Values above the documented maximum fail before allocation.
	_, _, err = c.DeriveKey(MaxDeriveKeyExtra + 1)
	require.Error(t, err)

	// Test valid extra values
	_, _, err = c.DeriveKey(0)
	require.NoError(t, err)

	_, _, err = c.DeriveKey(100)
	require.NoError(t, err)
}

// TestMinimalValidCiphertext tests that the minimum valid ciphertext
// length is correctly handled
func TestMinimalValidCiphertext(t *testing.T) {
	password := []byte("test")
	plaintext := []byte("x") // Minimal plaintext

	for _, version := range []Version{3, 4} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			c, err := NewCipher(password, nil, version)
			require.NoError(t, err)

			ciphertext, err := c.Encrypt(plaintext)
			require.NoError(t, err)

			result, err := c.Decrypt(ciphertext)
			require.NoError(t, err)
			require.Equal(t, plaintext, result)

			require.Greater(t, len(ciphertext), 1)
			_, err = c.Decrypt(ciphertext[:len(ciphertext)-1])
			require.Error(t, err)
		})
	}
}
