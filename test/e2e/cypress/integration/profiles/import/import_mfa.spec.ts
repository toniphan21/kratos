// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

import { TOTP } from "otpauth"

import { gen, KRATOS_ADMIN, website } from "../../../helpers"
import { routes as express } from "../../../helpers/express"

// Regression coverage for https://github.com/ory/kratos/issues/4561.
//
// When TOTP or lookup-secret credentials are imported through the admin
// identity API, the user must be able to use them to complete an AAL2
// login. Previously the import wrote the credential row but not the
// matching identity_credential_identifiers row, so AAL2 login would fail
// with "You have no TOTP device set up." or "You have not configured
// backup codes yet.".
context("Import Identities with MFA credentials", () => {
  before(() => {
    cy.useConfigProfile("mfa")
    cy.proxy("express")
  })

  beforeEach(() => {
    cy.clearAllCookies()
    cy.useConfig((builder) =>
      builder.longPrivilegedSessionTime().disableCodeMfa(),
    )
  })

  // playwright:migrated
  it("should be able to complete AAL2 login using imported TOTP credentials", () => {
    const email = gen.email()
    const password = gen.password()

    // Build the TOTP secret on the test side so we can both ship its
    // otpauth URL into the import payload and generate matching codes
    // later when we authenticate.
    const totp = new TOTP({
      issuer: "Ory",
      label: email,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    })

    cy.request("POST", `${KRATOS_ADMIN}/identities`, {
      schema_id: "default",
      traits: { email, website },
      credentials: {
        password: { config: { password } },
        totp: { config: { totp_url: totp.toString() } },
      },
    })

    // Force AAL2 on sign-in so we exercise the TOTP step-up path.
    cy.requireStrictAal()
    cy.visit(express.login)

    cy.get('input[name="identifier"]').type(email)
    cy.get('input[name="password"]').type(password)
    cy.submitPasswordForm()

    cy.shouldShow2FAScreen()

    cy.get('input[name="totp_code"]').type(totp.generate())
    cy.get('*[name="method"][value="totp"]').click()

    cy.location("pathname").should("not.contain", "/login")
    cy.getSession({
      expectAal: "aal2",
      expectMethods: ["password", "totp"],
    })
  })

  // playwright:migrated
  it("should be able to complete AAL2 login using imported lookup-secret credentials", () => {
    const email = gen.email()
    const password = gen.password()

    // Generate a few human-readable codes so failures in the test log
    // are easy to read; in production these would be opaque strings.
    const codes = [
      "imported-recovery-1",
      "imported-recovery-2",
      "imported-recovery-3",
      "imported-recovery-4",
    ]

    cy.request("POST", `${KRATOS_ADMIN}/identities`, {
      schema_id: "default",
      traits: { email, website },
      credentials: {
        password: { config: { password } },
        lookup_secret: {
          config: {
            codes: codes.map((code) => ({ code })),
          },
        },
      },
    })

    cy.requireStrictAal()
    cy.visit(express.login)

    cy.get('input[name="identifier"]').type(email)
    cy.get('input[name="password"]').type(password)
    cy.submitPasswordForm()

    cy.shouldShow2FAScreen()

    // Reject an invalid code first to make sure we are exercising the
    // lookup-secret branch and not silently bypassing it.
    cy.get('input[name="lookup_secret"]').type("not-a-real-code")
    cy.get('*[name="method"][value="lookup_secret"]').click()
    cy.get('[data-testid="ui/message/4000016"]').should(
      "contain.text",
      "The backup recovery code is not valid.",
    )

    // The form clears between attempts; type one of the imported codes.
    cy.get('input[name="lookup_secret"]').should("have.value", "")
    cy.get('input[name="lookup_secret"]').type(codes[0])
    cy.get('*[name="method"][value="lookup_secret"]').click()

    cy.location("pathname").should("not.contain", "/login")
    cy.getSession({
      expectAal: "aal2",
      expectMethods: ["password", "lookup_secret"],
    })
  })
})
