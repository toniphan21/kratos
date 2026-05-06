// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"context"
	"net/http"
	"slices"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
)

const (
	RecipientsRemoved     = "removed"
	RecipientsAllVerified = "all_verified"
	RecipientsAll         = "all"
)

type (
	NotifyPreviousAddressesConfig struct {
		Recipients string `json:"recipients"`
	}

	notifyPreviousAddressesDependencies interface {
		identity.ManagementProvider
		config.Provider
		logrusx.Provider
		otelx.Provider
	}

	NotifyPreviousAddresses struct {
		r notifyPreviousAddressesDependencies
		c *NotifyPreviousAddressesConfig
	}
)

var _ settings.PostHookPostPersistExecutor = new(NotifyPreviousAddresses)

func NewNotifyPreviousAddresses(r notifyPreviousAddressesDependencies, c *NotifyPreviousAddressesConfig) *NotifyPreviousAddresses {
	if c == nil {
		c = &NotifyPreviousAddressesConfig{}
	}
	if c.Recipients == "" {
		c.Recipients = RecipientsRemoved
	}
	return &NotifyPreviousAddresses{r: r, c: c}
}

func (e *NotifyPreviousAddresses) ExecuteSettingsPostPersistHook(
	_ http.ResponseWriter, r *http.Request,
	params settings.PostHookPostPersistExecutorParams,
) error {
	return otelx.WithSpan(r.Context(), "selfservice.hook.NotifyPreviousAddresses.ExecuteSettingsPostPersistHook", func(ctx context.Context) error {
		if params.Previous == nil || params.Updated == nil {
			return nil
		}
		targets := computeNotifyTargets(e.c.Recipients, params.Previous, params.Updated)
		targets = slices.DeleteFunc(targets, func(a identity.AddressRef) bool {
			return a.Via != identity.AddressTypeEmail && a.Via != identity.AddressTypeSMS
		})
		if len(targets) == 0 {
			return nil
		}
		if err := e.r.IdentityManager().SendVerifiableAddressChangedNotifications(ctx, targets, params.Updated); err != nil {
			e.r.Logger().WithError(err).
				WithField("count", len(targets)).
				Warn("Failed to queue one or more verifiable-address-change notifications.")
			// Persist already succeeded — never fail the flow on courier errors.
		}
		return nil
	})
}

func computeNotifyTargets(mode string, original, proposed *identity.Identity) []identity.AddressRef {
	if !addressesChanged(original.VerifiableAddresses, proposed.VerifiableAddresses) {
		return nil
	}
	switch mode {
	case RecipientsAllVerified:
		out := make([]identity.AddressRef, 0, len(original.VerifiableAddresses))
		for _, a := range original.VerifiableAddresses {
			if a.Verified {
				out = append(out, identity.AddressRef{Value: a.Value, Via: a.Via})
			}
		}
		return out
	case RecipientsAll:
		out := make([]identity.AddressRef, 0, len(original.VerifiableAddresses))
		for _, a := range original.VerifiableAddresses {
			out = append(out, identity.AddressRef{Value: a.Value, Via: a.Via})
		}
		return out
	default: // RecipientsRemoved
		keep := map[string]struct{}{}
		for _, a := range proposed.VerifiableAddresses {
			keep[a.Via+"|"+a.Value] = struct{}{}
		}
		out := make([]identity.AddressRef, 0)
		for _, a := range original.VerifiableAddresses {
			if _, still := keep[a.Via+"|"+a.Value]; still {
				continue
			}
			out = append(out, identity.AddressRef{Value: a.Value, Via: a.Via})
		}
		return out
	}
}

type set struct {
	m map[string]struct{}
}

func newSet() *set {
	return &set{m: make(map[string]struct{})}
}

func (s *set) add(via, value string) {
	s.m[via+"|"+value] = struct{}{}
}

func (s *set) contains(via, value string) bool {
	_, ok := s.m[via+"|"+value]
	return ok
}

// addressesChanged reports whether two verifiable-address slices represent
// different (via,value) sets. Status or verification-flag flips alone are not
// "address changes" and must not trigger notifications.
func addressesChanged(a, b []identity.VerifiableAddress) bool {
	if len(a) != len(b) {
		return true
	}
	seen := newSet()
	for _, x := range a {
		seen.add(x.Via, x.Value)
	}
	for _, x := range b {
		if !seen.contains(x.Via, x.Value) {
			return true
		}
	}
	return false
}
