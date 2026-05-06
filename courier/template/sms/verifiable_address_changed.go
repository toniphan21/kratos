// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sms

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/ory/kratos/courier/template"
)

type (
	VerifiableAddressChanged struct {
		deps  template.Dependencies
		model *VerifiableAddressChangedModel
	}
	VerifiableAddressChangedModel struct {
		To                 string         `json:"to"`
		Identity           map[string]any `json:"identity"`
		ChangedAt          string         `json:"changed_at"`
		TransientPayload   map[string]any `json:"transient_payload"`
		UserRequestHeaders http.Header    `json:"-"`
	}
)

func NewVerifiableAddressChanged(d template.Dependencies, m *VerifiableAddressChangedModel) *VerifiableAddressChanged {
	return &VerifiableAddressChanged{deps: d, model: m}
}

func (t *VerifiableAddressChanged) PhoneNumber() (string, error) {
	return t.model.To, nil
}

func (t *VerifiableAddressChanged) SMSBody(ctx context.Context) (string, error) {
	return template.LoadText(
		ctx,
		t.deps,
		os.DirFS(t.deps.CourierConfig().CourierTemplatesRoot(ctx)),
		"verifiable_address_changed/sms.body.gotmpl",
		"verifiable_address_changed/sms.body*",
		t.model,
		t.deps.CourierConfig().CourierSMSTemplatesVerifiableAddressChanged(ctx).Body.PlainText,
	)
}

func (t *VerifiableAddressChanged) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.model)
}

func (t *VerifiableAddressChanged) TemplateType() template.TemplateType {
	return template.TypeVerifiableAddressChanged
}

func (t *VerifiableAddressChanged) RequestHeaders() http.Header {
	return t.model.UserRequestHeaders
}
