// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/x"
)

// TestNotifyPreviousAddresses_Integration exercises the post-persist hook
// against a real registry and courier persister without going through the
// HTTP layer. This catches wiring regressions between the hook, the identity
// manager, the courier, and the template loader that a pure-unit test for
// the hook cannot detect.
func TestNotifyPreviousAddresses_Integration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf, reg := pkg.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/identity.schema.json")
	conf.MustSet(ctx, config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")

	t.Run("case=direct persist queues notification to removed address", func(t *testing.T) {
		original := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		original.Traits = identity.Traits(`{"email":"old@example.com"}`)
		original.VerifiableAddresses = []identity.VerifiableAddress{
			{Value: "old@example.com", Via: identity.AddressTypeEmail, Verified: true},
		}
		require.NoError(t, reg.IdentityManager().Create(ctx, original))

		proposed := *original
		proposed.Traits = identity.Traits(`{"email":"new@example.com"}`)
		proposed.VerifiableAddresses = []identity.VerifiableAddress{
			{Value: "new@example.com", Via: identity.AddressTypeEmail, Verified: false},
		}

		f := &settings.Flow{
			ID:              x.NewUUID(),
			ExpiresAt:       time.Now().Add(time.Hour),
			IssuedAt:        time.Now(),
			RequestURL:      "http://foo.com/settings",
			IdentityID:      proposed.ID,
			Identity:        &proposed,
			Type:            flow.TypeBrowser,
			UI:              &container.Container{Method: "POST"},
			InternalContext: []byte("{}"),
		}
		sess := &session.Session{Identity: original}

		h := hook.NewNotifyPreviousAddresses(reg, &hook.NotifyPreviousAddressesConfig{
			Recipients: hook.RecipientsRemoved,
		})

		r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		require.NoError(t, h.ExecuteSettingsPostPersistHook(w, r, settings.PostHookPostPersistExecutorParams{
			Flow:     f,
			Previous: original,
			Updated:  &proposed,
			Session:  sess,
		}))

		messages, err := reg.CourierPersister().NextMessages(ctx, 10)
		require.NoError(t, err)
		require.Len(t, messages, 1)
		assert.Equal(t, "old@example.com", messages[0].Recipient)
		assert.Equal(t, courier.MessageTypeEmail, messages[0].Type)
		assert.Contains(t, messages[0].Subject, "address")
	})

	t.Run("case=registry wires hook when configured via SelfServiceHook", func(t *testing.T) {
		executor := reg.HookNotifyPreviousAddresses(&hook.NotifyPreviousAddressesConfig{
			Recipients: hook.RecipientsAllVerified,
		})
		require.NotNil(t, executor)

		var _ settings.PostHookPostPersistExecutor = executor
	})
}
