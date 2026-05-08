// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package deviceauthn_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/selfservice/strategy/deviceauthn"
)

func TestAndroidKeyDescriptionJSON_dropsChallengeAndUniqueID(t *testing.T) {
	desc := deviceauthn.AndroidKeyDescription{
		AttestationVersion:       3,
		AttestationSecurityLevel: 1, // TEE-backed.
		AttestationChallenge:     []byte("nonce"),
		UniqueID:                 []byte("hardware-id"),
		TeeEnforced: deviceauthn.AndroidAuthorizationList{
			AttestationIDManufacturer: []byte("Google"),
		},
	}

	out, err := json.Marshal(desc)
	require.NoError(t, err)

	res := gjson.ParseBytes(out)
	assert.Equal(t, int64(3), res.Get("attestation_version").Int())
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("Google")), res.Get("tee_enforced.attestation_id_manufacturer").String())
	assert.False(t, res.Get("attestation_challenge").Exists(), "challenge is verified at enrollment, not serialized")
	assert.False(t, res.Get("unique_id").Exists(), "unique id is privacy-sensitive, not serialized")
}

func TestKeyAttestationOmitemptyWhenNil(t *testing.T) {
	k := deviceauthn.Key{ClientKeyID: "abc"}
	out, err := json.Marshal(k)
	require.NoError(t, err)
	assert.False(t, gjson.ParseBytes(out).Get("attestation").Exists())
}
