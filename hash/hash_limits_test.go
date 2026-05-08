// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hash_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/hash"
)

// TestCompareRejectsExtremeHashParameters reproduces the bug-bounty-reported
// DoS class: an attacker-controlled hash with extreme cost parameters causes
// the comparator to allocate gigabytes (or run for hours) and crash or hang
// the Kratos process at login time. Each case here would, without the bounds
// in hash_limits.go, drive the underlying primitive into pathological
// behavior. The comparator must error early instead.
func TestCompareRejectsExtremeHashParameters(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cases := []struct {
		name string
		hash string
	}{
		{
			// The originally reported attack: ln=31 → N=2^31 → ~256 GiB at r=8.
			name: "firescrypt ln=31 (reported)",
			hash: "$firescrypt$ln=31,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaA==$Bw==$a2V5a2V5",
		},
		{
			name: "firescrypt ln=18",
			hash: "$firescrypt$ln=18,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaA==$Bw==$a2V5a2V5",
		},
		{
			name: "firescrypt r=1024",
			hash: "$firescrypt$ln=14,r=1024,p=1$c2FsdHNhbHRzYWx0$aGFzaA==$Bw==$a2V5a2V5",
		},
		{
			name: "firescrypt p=1024",
			hash: "$firescrypt$ln=14,r=8,p=1024$c2FsdHNhbHRzYWx0$aGFzaA==$Bw==$a2V5a2V5",
		},
		{
			// Plain scrypt: ln=2097153 (one above 2^21) — far beyond cap.
			name: "scrypt N too large",
			hash: "$scrypt$ln=2097153,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaA==",
		},
		{
			name: "scrypt r=1024",
			hash: "$scrypt$ln=16384,r=1024,p=1$c2FsdHNhbHRzYWx0$aGFzaA==",
		},
		{
			// Argon2: 8 GiB requested.
			name: "argon2id m=8GiB",
			hash: "$argon2id$v=19$m=8388608,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw",
		},
		{
			name: "argon2id t=1000",
			hash: "$argon2id$v=19$m=65536,t=1000,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw",
		},
		{
			name: "argon2i m=8GiB",
			hash: "$argon2i$v=19$m=8388608,t=3,p=4$kk51rW/vxIVCYn+EG4kTSg$NyT88uraJ6im6dyha/M5jhXvpqlEdlS/9fEm7ScMb8c",
		},
		{
			// PBKDF2: 1B iterations.
			name: "pbkdf2 i=1_000_000_000",
			hash: "$pbkdf2-sha256$i=1000000000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI",
		},
		{
			// Bcrypt cost=20 → ~64s per compare. Format-valid but resource
			// exhaustion risk.
			name: "bcrypt cost=20",
			hash: "$2a$20$abcdefghijklmnopqrstuugn/uitWMnDoOdJaSWqW1pjEXZ8eOSCqK",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := hash.Compare(ctx, []byte("any-password"), []byte(tc.hash))
			require.Error(t, err, "expected bounds-exceeded error; without it the process would OOM or hang")
			require.ErrorIs(t, err, hash.ErrHashParametersOutOfBounds)
		})
	}
}

// TestValidateImportedHashRejectsExtremeParameters covers the import-time
// counterpart: malicious hashes must be rejected at the admin import API
// boundary, before they are ever persisted, so that a single poisoned row
// cannot crash-loop the service on every login attempt.
func TestValidateImportedHashRejectsExtremeParameters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hash string
	}{
		{name: "firescrypt ln=31", hash: "$firescrypt$ln=31,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaA==$Bw==$a2V5a2V5"},
		{name: "scrypt N too large", hash: "$scrypt$ln=2097153,r=8,p=1$c2FsdHNhbHRzYWx0$aGFzaA=="},
		{name: "argon2id m=8GiB", hash: "$argon2id$v=19$m=8388608,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw"},
		{name: "argon2i t=1000", hash: "$argon2i$v=19$m=65536,t=1000,p=4$kk51rW/vxIVCYn+EG4kTSg$NyT88uraJ6im6dyha/M5jhXvpqlEdlS/9fEm7ScMb8c"},
		{name: "pbkdf2 i=1B", hash: "$pbkdf2-sha256$i=1000000000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI"},
		{name: "bcrypt cost=20", hash: "$2a$20$abcdefghijklmnopqrstuugn/uitWMnDoOdJaSWqW1pjEXZ8eOSCqK"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := hash.ValidateImportedHash([]byte(tc.hash))
			require.Error(t, err)
			require.ErrorIs(t, err, hash.ErrHashParametersOutOfBounds)
		})
	}
}

// TestValidateImportedHashAcceptsRealisticHashes guards against bounds being
// set so tightly that legitimate, real-world hashes are rejected. The values
// here mirror the existing valid-hash test cases in TestCompare.
func TestValidateImportedHashAcceptsRealisticHashes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hash string
	}{
		{name: "bcrypt cost=12", hash: "$2a$12$o6hx.Wog/wvFSkT/Bp/6DOxCtLRTDj7lm9on9suF/WaCGNVHbkfL6"},
		{name: "bcrypt cost=15", hash: "$2a$15$GRvRO2nrpYTEuPQX6AieaOlZ4.7nMGsXpt.QWMev1zrP86JNspZbO"},
		{name: "argon2id m=32 t=2 p=4", hash: "$argon2id$v=19$m=32,t=2,p=4$cm94YnRVOW5jZzFzcVE4bQ$MNzk5BtR2vUhrp6qQEjRNw"},
		{name: "argon2i m=65536 t=3 p=4", hash: "$argon2i$v=19$m=65536,t=3,p=4$kk51rW/vxIVCYn+EG4kTSg$NyT88uraJ6im6dyha/M5jhXvpqlEdlS/9fEm7ScMb8c"},
		{name: "pbkdf2-sha256 i=100000", hash: "$pbkdf2-sha256$i=100000,l=32$1jP+5Zxpxgtee/iPxGgOz0RfE9/KJuDElP1ley4VxXc$QJxzfvdbHYBpydCbHoFg3GJEqMFULwskiuqiJctoYpI"},
		{name: "pbkdf2-sha512 i=100000", hash: "$pbkdf2-sha512$i=100000,l=32$bdHBpn7OWOivJMVJypy2UqR0UnaD5prQXRZevj/05YU$+wArTfv1a+bNGO1iZrmEdVjhA+lL11wF4/IxpgYfPwc"},
		{name: "scrypt ln=16384 r=8 p=1", hash: "$scrypt$ln=16384,r=8,p=1$2npRo7P03Mt8keSoMbyD/tKFWyUzjiQf2svUaNDSrhA=$MiCzNcIplSMqSBrm4HckjYqYhaVPPjTARTzwB1cVNYE="},
		{name: "firescrypt ln=14", hash: "$firescrypt$ln=14,r=8,p=1$sPtDhWcd1MfdAw==$xbSou7FOl6mChCyzpCPIQ7tku7nsQMTFtyOZSXXd7tjBa4NtimOx7v42Gv2SfzPQu1oxM2/k4SsbOu73wlKe1A==$Bw==$YE0dO4bwD4JnJafh6lZZfkp1MtKzuKAXQcDCJNJNyeCHairWHKENOkbh3dzwaCdizzOspwr/FITUVlnOAwPKyw=="},
		// Hashes without parametrized cost (no allocation/CPU vector) — must
		// pass through without error.
		{name: "md5", hash: "$md5$CY9rzUYh03PK3k6DJie09g=="},
		{name: "sha256-crypt", hash: "$sha256-crypt$rounds=535000$05R.9KB6UC2kLI3w$Q/zslzx./JjkAVPTwp6th7nW5l7JU91Gte/UmIh.U78"},
		{name: "ssha", hash: "{SSHA}JFZFs0oHzxbMwkSJmYVeI8MnTDy/276a"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, hash.ValidateImportedHash([]byte(tc.hash)))
		})
	}
}
