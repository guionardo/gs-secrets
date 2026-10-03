package store

import (
	"errors"
	"fmt"
)

// On-disk vault format:
//
//	[5]byte magic "GSSEC"
//	[1]byte format version (vaultVersion)
//	[1]byte cipher suite id (vaultCipher)
//	[...] nonce || ciphertext (AES-256-GCM)
//
// The header lets readers reject garbage and foreign formats loudly instead
// of misinterpreting them, and gives future format migrations a place to
// hang a version number.
const (
	vaultMagic   = "GSSEC"
	vaultVersion = 1
	vaultCipher  = 1 // AES-256-GCM
	headerLen    = len(vaultMagic) + 2
)

// errLegacyVault reports a blob without the format header; it is returned by
// decodeVault so callers can fall back to the pre-header layout.
var errLegacyVault = errors.New("legacy vault format without header")

// encodeVault wraps the GCM-sealed ciphertext in the versioned header.
func encodeVault(key, plaintext []byte) ([]byte, error) {
	sealed, err := encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, headerLen+len(sealed))
	blob = append(blob, vaultMagic...)
	blob = append(blob, vaultVersion, vaultCipher)
	return append(blob, sealed...), nil
}

// decodeVault validates the header and unwraps the sealed payload. A blob
// without the magic header yields errLegacyVault so callers can attempt the
// pre-header layout; anything with a header of an unknown version or cipher
// suite is rejected.
func decodeVault(key, blob []byte) ([]byte, error) {
	if len(blob) < headerLen || string(blob[:len(vaultMagic)]) != vaultMagic {
		return nil, errLegacyVault
	}
	if blob[len(vaultMagic)] != vaultVersion {
		return nil, fmt.Errorf("unsupported vault format version %d", blob[len(vaultMagic)])
	}
	if blob[len(vaultMagic)+1] != vaultCipher {
		return nil, fmt.Errorf("unsupported vault cipher suite %d", blob[len(vaultMagic)+1])
	}
	return decrypt(key, blob[headerLen:])
}
