// Edge-case tests for cipher state, compatibility, and input validation.
package triplesec

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIssue1_AllInvalidLengths tests every possible invalid length
// to ensure no panic paths remain
func TestIssue1_AllInvalidLengths(t *testing.T) {
	c, err := NewCipher([]byte("password"), nil, 4)
	require.NoError(t, err)

	versionParams := versionParamsLookup[4]
	minValid := versionParams.Overhead()

	// Test empty input
	_, err = c.Decrypt([]byte{})
	require.Error(t, err)

	// Test every length from 0 to Overhead-1
	for length := range minValid {
		testData := make([]byte, length)
		// Set valid magic bytes if there's room
		if length >= 4 {
			copy(testData, MagicBytes[:])
		}
		// Set valid version if there's room
		if length >= 8 {
			testData[4] = 0x00
			testData[5] = 0x00
			testData[6] = 0x00
			testData[7] = 0x04
		}

		_, err := c.Decrypt(testData)
		require.Error(t, err, "length %d", length)
	}
}

// TestIssue1_BoundaryCase tests exactly at the minimum valid length
func TestIssue1_BoundaryCase(t *testing.T) {
	password := []byte("test")
	plaintext := []byte("x")

	for _, version := range []Version{3, 4} {
		c, err := NewCipher(password, nil, version)
		require.NoError(t, err)

		ciphertext, err := c.Encrypt(plaintext)
		require.NoError(t, err)

		versionParams := versionParamsLookup[version]
		expectedMinLen := versionParams.Overhead() + len(plaintext)

		require.Len(t, ciphertext, expectedMinLen, "version %d", version)

		// Should decrypt successfully
		result, err := c.Decrypt(ciphertext)
		require.NoError(t, err, "version %d", version)
		require.Equal(t, plaintext, result, "version %d", version)

		// One byte less should fail
		_, err = c.Decrypt(ciphertext[:len(ciphertext)-1])
		require.Error(t, err, "version %d", version)
	}
}

// TestIssue1_CorruptedVersionWithValidMagic tests that corrupted version
// bytes with valid magic don't cause panics
func TestIssue1_CorruptedVersionWithValidMagic(t *testing.T) {
	c, err := NewCipher([]byte("password"), nil, 4)
	require.NoError(t, err)

	// Valid magic + invalid version + short data
	testCases := []string{
		"1c94d7de00000005",         // Invalid version 5
		"1c94d7de00000000",         // Invalid version 0
		"1c94d7deffffffff",         // Invalid version (max uint32)
		"1c94d7de00000004deadbeef", // Valid version but truncated after
	}

	for _, tc := range testCases {
		data, err := hex.DecodeString(tc)
		require.NoError(t, err)
		_, err = c.Decrypt(data)
		require.Error(t, err, "input %s", tc)
		// Should get either VersionError or CorruptionError, not panic
	}
}

// TestIssue2_ExplicitSaltChange tests salt cache invalidation with
// explicit (non-random) salt changes to ensure deterministic behavior
func TestIssue2_ExplicitSaltChange(t *testing.T) {
	password := []byte("password123")
	plaintext := []byte("test data")

	// Create two different explicit salts
	salt1 := bytes.Repeat([]byte{0x01}, SaltLen)
	salt2 := bytes.Repeat([]byte{0x02}, SaltLen)

	// Create cipher with salt1
	c1, err := NewCipher(password, salt1, 4)
	require.NoError(t, err)

	// Encrypt with salt1
	ciphertext1, err := c1.Encrypt(plaintext)
	require.NoError(t, err)

	// Create cipher with salt2
	c2, err := NewCipher(password, salt2, 4)
	require.NoError(t, err)

	// Encrypt with salt2
	ciphertext2, err := c2.Encrypt(plaintext)
	require.NoError(t, err)

	// Ciphertexts should be different (different salts)
	require.NotEqual(t, ciphertext1, ciphertext2)

	// Reuse c1 to decrypt ciphertext2 (different salt)
	result, err := c1.Decrypt(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)

	// Reuse c1 to decrypt ciphertext1 again (original salt)
	result, err = c1.Decrypt(ciphertext1)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

// TestIssue2_CacheReuse verifies that the cache is actually being used
// when the salt doesn't change
func TestIssue2_CacheReuse(t *testing.T) {
	password := []byte("test")
	salt := bytes.Repeat([]byte{0xAA}, SaltLen)
	c, err := NewCipher(password, salt, 4)
	require.NoError(t, err)

	// First key derivation
	dk1, extra1, err := c.DeriveKey(0)
	require.NoError(t, err)

	// Cache should be populated
	require.NotNil(t, c.derivedKey)

	// Second derivation with same salt - should use cache
	dk2, extra2, err := c.DeriveKey(0)
	require.NoError(t, err)

	// Results should be identical (same underlying slice)
	require.Same(t, &dk1[0], &dk2[0])
	require.Empty(t, extra1)
	require.Empty(t, extra2)
}

// TestIssue2_MultipleCycles tests multiple encrypt/decrypt cycles
// to ensure cache invalidation works correctly across many operations
func TestIssue2_MultipleCycles(t *testing.T) {
	password := []byte("password")
	plaintexts := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}

	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	var ciphertexts [][]byte

	// Encrypt multiple messages with deterministic distinct salts.
	for i, pt := range plaintexts {
		producer, err := NewCipher(password, bytes.Repeat([]byte{byte(i + 1)}, SaltLen), 4)
		require.NoError(t, err, "producer %d", i)
		ct, err := producer.Encrypt(pt)
		require.NoError(t, err, "encrypt %d", i)
		ciphertexts = append(ciphertexts, ct)
	}

	// Decrypt all messages in reverse order (different salt order)
	for i, ciphertext := range slices.Backward(ciphertexts) {
		result, err := c.Decrypt(ciphertext)
		require.NoError(t, err, "decrypt %d", i)
		require.Equal(t, plaintexts[i], result, "decrypt %d", i)
	}

	// Decrypt all messages in forward order
	for i, ct := range ciphertexts {
		result, err := c.Decrypt(ct)
		require.NoError(t, err, "second decrypt %d", i)
		require.Equal(t, plaintexts[i], result, "second decrypt %d", i)
	}
}

// TestIssue3_VersionParamConsistency verifies that all operations in
// Decrypt use the ciphertext version consistently
func TestIssue3_VersionParamConsistency(t *testing.T) {
	password := []byte("test")
	plaintext := []byte("version test message")

	// Encrypt with v3
	c3, err := NewCipher(password, nil, 3)
	require.NoError(t, err)
	ciphertext3, err := c3.Encrypt(plaintext)
	require.NoError(t, err)

	// Encrypt with v4
	c4, err := NewCipher(password, nil, 4)
	require.NoError(t, err)
	ciphertext4, err := c4.Encrypt(plaintext)
	require.NoError(t, err)

	// Verify v3 has Twofish (longer IV)
	v3Params := versionParamsLookup[3]
	v4Params := versionParamsLookup[4]

	require.True(t, v3Params.UseTwofish)
	require.False(t, v4Params.UseTwofish)

	// Verify different ciphertext lengths due to different IV lengths
	require.Greater(t, len(ciphertext3), len(ciphertext4))

	// Create fresh ciphers and decrypt cross-version
	c3Fresh, err := NewCipher(password, nil, 3)
	require.NoError(t, err)
	c4Fresh, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	// v3 cipher decrypts v4 ciphertext
	result, err := c3Fresh.Decrypt(ciphertext4)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)

	// v4 cipher decrypts v3 ciphertext
	result, err = c4Fresh.Decrypt(ciphertext3)
	require.NoError(t, err)
	require.Equal(t, plaintext, result)
}

// TestIssue5_BoundaryValues tests DeriveKey validation at boundary values
func TestIssue5_BoundaryValues(t *testing.T) {
	c, err := NewCipher([]byte("password"), nil, 4)
	require.NoError(t, err)

	_, err = c.GetSalt()
	require.NoError(t, err)

	testCases := []struct {
		extra     int
		shouldErr bool
		desc      string
	}{
		{-1, true, "negative"},
		{-100, true, "large negative"},
		{0, false, "zero"},
		{1, false, "one"},
		{1000, false, "normal value"},
		{MaxDeriveKeyExtra, false, "maximum"},
		{MaxDeriveKeyExtra + 1, true, "over maximum"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, _, err := c.DeriveKey(tc.extra)
			if tc.shouldErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestIssue4_ScrubInvocation verifies that scrubbing happens on
// multiple encrypt/decrypt cycles
func TestIssue4_ScrubInvocation(t *testing.T) {
	password := []byte("password")
	plaintext := []byte("sensitive data")

	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	// Multiple encrypt/decrypt cycles to ensure defer scrub works each time
	for i := range 5 {
		ciphertext, err := c.Encrypt(plaintext)
		require.NoError(t, err, "encrypt cycle %d", i)

		result, err := c.Decrypt(ciphertext)
		require.NoError(t, err, "decrypt cycle %d", i)
		require.Equal(t, plaintext, result, "cycle %d", i)
	}

	// Test that Cipher.Scrub() can be called safely
	c.Scrub()

	// After scrub, passphrase and derived key should be zeroed
	require.Equal(t, make([]byte, len(c.passphrase)), c.passphrase)

	require.NotNil(t, c.derivedKey)
	require.Equal(t, make([]byte, len(c.derivedKey)), c.derivedKey)
}

// TestSeparateCipherInstances verifies that separate Cipher instances
// can be used concurrently safely (each goroutine has its own instance).
// Note: A single Cipher instance is NOT safe for concurrent use.
func TestSeparateCipherInstances(t *testing.T) {
	password := []byte("password")
	plaintext := []byte("concurrent test")

	// Create one cipher to generate test ciphertexts
	c, err := NewCipher(password, nil, 4)
	require.NoError(t, err)

	// Create multiple ciphertexts
	var ciphertexts [][]byte
	for range 10 {
		ct, err := c.Encrypt(plaintext)
		require.NoError(t, err)
		ciphertexts = append(ciphertexts, ct)
	}

	// Decrypt concurrently using SEPARATE cipher instances per goroutine
	type result struct {
		plaintext []byte
		err       error
	}
	results := make(chan result, len(ciphertexts))

	for _, ct := range ciphertexts {
		// Construct each Cipher in the test goroutine so setup failures use the
		// same require-based assertion style as the rest of the added tests.
		cipher, err := NewCipher(password, nil, 4)
		require.NoError(t, err)
		go func(cipher *Cipher, ct []byte) {
			pt, err := cipher.Decrypt(ct)
			results <- result{plaintext: pt, err: err}
		}(cipher, ct)
	}

	// Wait for all goroutines and check results
	for i := 0; i < len(ciphertexts); i++ {
		r := <-results
		require.NoError(t, r.err, "concurrent decrypt %d", i)
		require.Equal(t, plaintext, r.plaintext, "concurrent decrypt %d", i)
	}
}

// TestCipherNotThreadSafe documents that a single Cipher instance
// is not safe for concurrent use (this is expected behavior)
func TestCipherNotThreadSafe(t *testing.T) {
	t.Skip("This test documents that Cipher is not thread-safe by design")
	// If you uncomment this test and run with -race, it will fail.
	// This is expected: users should create separate Cipher instances
	// for concurrent operations, not share a single instance.
}
