// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/session"
)

func TestNotifyPreviousAddresses_PostPersist(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name              string
		mode              string
		previousAddresses []identity.VerifiableAddress
		updatedAddresses  []identity.VerifiableAddress
		wantRecipients    []string
	}{
		{
			name: "removed-only notifies the dropped address",
			mode: hook.RecipientsRemoved,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "old@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "keep@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "keep@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "new@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: []string{"old@example.com"},
		},
		{
			name: "all-verified notifies every previously verified address",
			mode: hook.RecipientsAllVerified,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "v1@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "v2@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "unverified@example.com", Via: identity.AddressTypeEmail, Verified: false, Status: identity.VerifiableAddressStatusPending},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "new@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: []string{"v1@example.com", "v2@example.com"},
		},
		{
			name: "all notifies every prior address regardless of verification",
			mode: hook.RecipientsAll,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "verified@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "unverified@example.com", Via: identity.AddressTypeEmail, Verified: false, Status: identity.VerifiableAddressStatusPending},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "new@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: []string{"verified@example.com", "unverified@example.com"},
		},
		{
			name: "unsupported via is filtered out",
			mode: hook.RecipientsAll,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "ok@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
				{Value: "pager://123", Via: "pager", Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "new@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: []string{"ok@example.com"},
		},
		{
			name: "no diff queues no notifications",
			mode: hook.RecipientsRemoved,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: nil,
		},
		{
			name: "all-verified does not notify when only non-address traits changed",
			mode: hook.RecipientsAllVerified,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: nil,
		},
		{
			name: "all does not notify when only non-address traits changed",
			mode: hook.RecipientsAll,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: nil,
		},
		{
			name: "verification status flip alone does not notify",
			mode: hook.RecipientsAllVerified,
			previousAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: false, Status: identity.VerifiableAddressStatusPending},
			},
			updatedAddresses: []identity.VerifiableAddress{
				{Value: "stable@example.com", Via: identity.AddressTypeEmail, Verified: true, Status: identity.VerifiableAddressStatusCompleted},
			},
			wantRecipients: nil,
		},
	} {
		tc := tc
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			conf, reg := pkg.NewFastRegistryWithMocks(t)
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/verify_single_email.schema.json")
			conf.MustSet(ctx, config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")

			previous := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
			previous.Traits = identity.Traits(`{"email":"new@example.com"}`)
			previous.VerifiableAddresses = tc.previousAddresses

			updated := *previous
			updated.VerifiableAddresses = tc.updatedAddresses

			h := hook.NewNotifyPreviousAddresses(reg, &hook.NotifyPreviousAddressesConfig{Recipients: tc.mode})

			r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			require.NoError(t, h.ExecuteSettingsPostPersistHook(w, r, settings.PostHookPostPersistExecutorParams{
				Flow:     &settings.Flow{InternalContext: []byte("{}")},
				Previous: previous,
				Updated:  &updated,
				Session:  &session.Session{Identity: &updated},
			}))

			messages, err := reg.CourierPersister().NextMessages(ctx, 12)
			if len(tc.wantRecipients) == 0 {
				require.ErrorIs(t, err, courier.ErrQueueEmpty)
				return
			}
			require.NoError(t, err)
			require.Len(t, messages, len(tc.wantRecipients))
			gotRecipients := make([]string, len(messages))
			for k, m := range messages {
				gotRecipients[k] = m.Recipient
				assert.Equal(t, courier.MessageTypeEmail, m.Type)
			}
			assert.ElementsMatch(t, tc.wantRecipients, gotRecipients)
		})
	}
}

func TestNotifyPreviousAddresses_PostPersist_NilPrevious(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conf, reg := pkg.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/verify_single_email.schema.json")
	conf.MustSet(ctx, config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")

	updated := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)

	h := hook.NewNotifyPreviousAddresses(reg, &hook.NotifyPreviousAddressesConfig{Recipients: hook.RecipientsRemoved})

	r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	require.NoError(t, h.ExecuteSettingsPostPersistHook(w, r, settings.PostHookPostPersistExecutorParams{
		Flow:     &settings.Flow{InternalContext: []byte("{}")},
		Previous: nil,
		Updated:  updated,
		Session:  &session.Session{Identity: updated},
	}))

	_, err := reg.CourierPersister().NextMessages(ctx, 10)
	require.ErrorIs(t, err, courier.ErrQueueEmpty)
}
