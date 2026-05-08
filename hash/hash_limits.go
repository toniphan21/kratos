// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hash

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// ErrHashParametersOutOfBounds is returned when an imported or stored hash
// declares cost parameters that exceed the bounds enforced by this package.
// The bounds exist to prevent attacker-controlled hash parameters from causing
// memory exhaustion (process OOM) or unbounded CPU consumption when the
// password comparator is invoked.
var ErrHashParametersOutOfBounds = errors.New("hash parameters exceed allowed bounds")

// Bounds for cost parameters embedded in imported password hashes. Each value
// is chosen to comfortably accommodate strong real-world configurations while
// bounding worst-case memory and CPU consumption when the comparator runs at
// login time.
const (
	// maxScryptLogN bounds the firebase-scrypt ln parameter.
	// firebase-scrypt computes N = 1 << ln. Memory is 128 * N * r bytes.
	// Firebase's strongest documented profile is ln=14 (~16 MiB at r=8); 17
	// leaves headroom for legacy configs while bounding allocation at
	// ~128 MiB at r=8.
	maxScryptLogN uint32 = 17

	// maxScryptN bounds plain scrypt's N directly. OWASP's Password Storage
	// Cheat Sheet recommends N=2^17 (131072) as the minimum for password
	// hashing; no widely-deployed password-hash system documents a larger
	// value. Higher N appears only in file-encryption tooling (tarsnap, age)
	// where multi-second cost is acceptable. The Kratos default and RFC 7914's
	// example both use N=16384 (2^14). Combined with the r=8 ceiling, this
	// caps memory at 128 MiB per compare.
	maxScryptN uint32 = 1 << 17

	// maxScryptR bounds scrypt's r (block size). RFC 7914 specifies r=8
	// verbatim; all five OWASP recommended scrypt configurations use r=8.
	// No documented production password hash uses r > 8. With N=2^17 this
	// caps memory at 128 MiB per compare.
	maxScryptR uint32 = 8

	// maxScryptP bounds scrypt's p (parallelization). p=1 is the standard
	// default; OWASP's highest documented config uses p=10. Go's scrypt
	// implementation runs p iterations serially, so p multiplies CPU
	// linearly without any parallelism gain.
	maxScryptP uint32 = 10

	// maxArgon2MemoryKiB bounds argon2 memory at 1 GiB. Kratos default is
	// 128 MiB; OWASP recommends 64 MiB. 1 GiB matches the existing
	// Argon2DefaultDedicatedMemory ceiling in driver/config.
	maxArgon2MemoryKiB uint32 = 1 << 20

	// maxArgon2Iterations bounds argon2 t. RFC 9106 recommends t∈{1,3};
	// OWASP configurations use up to t=5; libsodium SENSITIVE preset uses
	// t=4. Bitwarden's user-configurable hard cap is 10, the highest
	// documented production value.
	maxArgon2Iterations uint32 = 10

	// maxArgon2Parallelism bounds argon2 p. Default is 2*NumCPU; 16 covers
	// up to 8-core hosts.
	maxArgon2Parallelism uint8 = 16

	// maxPbkdf2Iterations bounds PBKDF2 i. OWASP 2023 recommends 600k
	// (SHA-256) / 210k (SHA-512). 10M ≈ 10× the strongest published
	// recommendation and bounds CPU to a few seconds on modern hardware.
	maxPbkdf2Iterations uint32 = 10_000_000

	// maxBcryptCost bounds bcrypt cost. The format spec allows 4–31, but
	// cost grows exponentially: cost 12 (Kratos, PHP, Django default) is
	// ~250 ms; cost 14 (high-security guidance) is ~1 s; cost 15 (practical
	// max for interactive use) is ~2 s; cost 17 is ~8 s. No mainstream
	// platform defaults above cost 12.
	maxBcryptCost = 15
)

func validateFirebaseScryptParams(logN, r, p uint32) error {
	if logN > maxScryptLogN {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "firescrypt ln=%d exceeds max %d", logN, maxScryptLogN)
	}
	if r == 0 || r > maxScryptR {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "firescrypt r=%d not in [1, %d]", r, maxScryptR)
	}
	if p == 0 || p > maxScryptP {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "firescrypt p=%d not in [1, %d]", p, maxScryptP)
	}
	return nil
}

func validateScryptParams(n, r, p uint32) error {
	if n == 0 || n > maxScryptN {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "scrypt N=%d not in [1, %d]", n, maxScryptN)
	}
	if r == 0 || r > maxScryptR {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "scrypt r=%d not in [1, %d]", r, maxScryptR)
	}
	if p == 0 || p > maxScryptP {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "scrypt p=%d not in [1, %d]", p, maxScryptP)
	}
	return nil
}

func validateArgon2Params(memoryKiB uint64, iterations uint32, parallelism uint8) error {
	if memoryKiB == 0 || memoryKiB > uint64(maxArgon2MemoryKiB) {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "argon2 m=%d KiB not in [1, %d]", memoryKiB, maxArgon2MemoryKiB)
	}
	if iterations == 0 || iterations > maxArgon2Iterations {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "argon2 t=%d not in [1, %d]", iterations, maxArgon2Iterations)
	}
	if parallelism == 0 || parallelism > maxArgon2Parallelism {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "argon2 p=%d not in [1, %d]", parallelism, maxArgon2Parallelism)
	}
	return nil
}

func validatePbkdf2Params(iterations uint32) error {
	if iterations == 0 || iterations > maxPbkdf2Iterations {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "pbkdf2 i=%d not in [1, %d]", iterations, maxPbkdf2Iterations)
	}
	return nil
}

func validateBcryptHashCost(hashed []byte) error {
	cost, err := bcrypt.Cost(hashed)
	if err != nil {
		return err
	}
	if cost > maxBcryptCost {
		return errors.Wrapf(ErrHashParametersOutOfBounds, "bcrypt cost=%d exceeds max %d", cost, maxBcryptCost)
	}
	return nil
}

// ValidateImportedHash performs cost-parameter bounds checking on a hash
// before it is persisted via the admin identity import API. It is the
// import-time counterpart to the bounds checks in the compare* paths and
// exists so we fail fast on malicious imports rather than persisting a hash
// that would crash the process at every login attempt.
//
// Hashers without attacker-controlled cost parameters (md5-crypt, sha-crypt,
// the static SHA/MD5/HMAC families, SSHA) pass through unchanged.
func ValidateImportedHash(hashed []byte) error {
	switch {
	case IsBcryptHash(hashed):
		return validateBcryptHashCost(hashed)
	case IsArgon2idHash(hashed), IsArgon2iHash(hashed):
		_, _, _, err := decodeArgon2idHash(string(hashed))
		return err
	case IsPbkdf2Hash(hashed):
		_, _, _, err := decodePbkdf2Hash(string(hashed))
		return err
	case IsScryptHash(hashed):
		_, _, _, err := decodeScryptHash(string(hashed))
		return err
	case IsFirebaseScryptHash(hashed):
		_, _, _, _, _, err := decodeFirebaseScryptHash(string(hashed))
		return err
	}
	return nil
}
