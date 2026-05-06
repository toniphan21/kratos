// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package email_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/courier/template/email"
	"github.com/ory/kratos/pkg"
)

func TestVerifiableAddressChanged(t *testing.T) {
	ctx := context.Background()
	_, reg := pkg.NewFastRegistryWithMocks(t)

	tpl := email.NewVerifiableAddressChanged(reg, &email.VerifiableAddressChangedModel{
		To:        "old@example.com",
		ChangedAt: "2026-04-21T12:00:00Z",
		Identity:  map[string]any{"ID": "00000000-0000-0000-0000-000000000001", "Traits": map[string]any{"email": "new@example.com"}},
	})

	recipient, err := tpl.EmailRecipient()
	require.NoError(t, err)
	assert.Equal(t, "old@example.com", recipient)

	subject, err := tpl.EmailSubject(ctx)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(subject), "address")

	body, err := tpl.EmailBody(ctx)
	require.NoError(t, err)
	assert.Contains(t, body, "00000000-0000-0000-0000-000000000001")

	plain, err := tpl.EmailBodyPlaintext(ctx)
	require.NoError(t, err)
	assert.Contains(t, plain, "00000000-0000-0000-0000-000000000001")
	assert.Contains(t, plain, "2026-04-21T12:00:00Z")
}
