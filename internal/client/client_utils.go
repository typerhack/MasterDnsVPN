// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (client_utils.go) handles common client utility functions.
// ==============================================================================
package client

import (
	"crypto/rand"
)

// randomBytes generates random bytes using a cryptographically secure PRNG.
// This is used for generating sensitive identifiers like session codes and verify tokens.
func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// fragmentPayload splits a payload into chunks of max mtu size.
func fragmentPayload(payload []byte, mtu int) [][]byte {
	if len(payload) <= mtu {
		return [][]byte{payload}
	}
	var fragments [][]byte
	for i := 0; i < len(payload); i += mtu {
		end := i + mtu
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}
	return fragments
}
