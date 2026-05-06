// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/ory/kratos/courier/template"
)

type (
	VerifiableAddressChanged struct {
		d template.Dependencies
		m *VerifiableAddressChangedModel
	}
	VerifiableAddressChangedModel struct {
		To               string         `json:"to"`
		Identity         map[string]any `json:"identity"`
		ChangedAt        string         `json:"changed_at"`
		TransientPayload map[string]any `json:"transient_payload"`
	}
)

func NewVerifiableAddressChanged(d template.Dependencies, m *VerifiableAddressChangedModel) *VerifiableAddressChanged {
	return &VerifiableAddressChanged{d: d, m: m}
}

func (t *VerifiableAddressChanged) EmailRecipient() (string, error) {
	return t.m.To, nil
}

func (t *VerifiableAddressChanged) EmailSubject(ctx context.Context) (string, error) {
	subject, err := template.LoadText(ctx, t.d, os.DirFS(t.d.CourierConfig().CourierTemplatesRoot(ctx)), "verifiable_address_changed/email.subject.gotmpl", "verifiable_address_changed/email.subject*", t.m, t.d.CourierConfig().CourierTemplatesVerifiableAddressChanged(ctx).Subject)
	return strings.TrimSpace(subject), err
}

func (t *VerifiableAddressChanged) EmailBody(ctx context.Context) (string, error) {
	return template.LoadHTML(ctx, t.d, os.DirFS(t.d.CourierConfig().CourierTemplatesRoot(ctx)), "verifiable_address_changed/email.body.gotmpl", "verifiable_address_changed/email.body*", t.m, t.d.CourierConfig().CourierTemplatesVerifiableAddressChanged(ctx).Body.HTML)
}

func (t *VerifiableAddressChanged) EmailBodyPlaintext(ctx context.Context) (string, error) {
	return template.LoadText(ctx, t.d, os.DirFS(t.d.CourierConfig().CourierTemplatesRoot(ctx)), "verifiable_address_changed/email.body.plaintext.gotmpl", "verifiable_address_changed/email.body.plaintext*", t.m, t.d.CourierConfig().CourierTemplatesVerifiableAddressChanged(ctx).Body.PlainText)
}

func (t *VerifiableAddressChanged) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.m)
}

func (t *VerifiableAddressChanged) TemplateType() template.TemplateType {
	return template.TypeVerifiableAddressChanged
}
