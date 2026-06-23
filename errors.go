package triplesec

import (
	"fmt"
)

type CorruptionError struct {
	msg string
	err error
}

func (e CorruptionError) Error() string {
	return "Triplesec corruption: " + e.msg
}

func (e CorruptionError) Unwrap() error {
	return e.err
}

type VersionError struct {
	v Version
}

func (e VersionError) Error() string {
	return fmt.Sprintf("Unknown version: %v", e.v)
}

type BadPassphraseError struct{}

func (e BadPassphraseError) Error() string {
	return "Bad passphrase (or inflight message tampering)"
}
