package app_test

// Design tests for PR H — Login and Setup page redesign.
//
// Acceptance criteria tested:
//   - loginPage: renders the centered auth layout (authwrap) — no topbar.
//   - loginPage: renders the authbrand wordmark with "Step-CA" (b1) and
//     "NextGen UI" (b2) — consistent with the topbar wordmark.
//   - loginPage: renders the tagline "Sign in to manage your certificate authority".
//   - loginPage: renders Username (name="username") and Password (name="password")
//     inputs inside a card.
//   - loginPage: renders the "Sign in" submit button.
//   - loginPage: renders the authfoot "step-ui-ng · self-hosted Step-CA admin".
//   - loginPage: includes the CSRF token.
//   - loginPage: password is NEVER echoed back into a value attribute on error.
//   - setupPage: renders the authwrap layout — no topbar.
//   - setupPage: renders the same authbrand wordmark (Step-CA / NextGen UI).
//   - setupPage: renders the tagline "Welcome — let's create the first administrator".
//   - setupPage: renders the card title "Create the first account".
//   - setupPage: renders the "superadmin" copy in the card description.
//   - setupPage: renders Username, Password, Confirm-password inputs.
//   - setupPage: renders the password hint about 12+ characters.
//   - setupPage: renders the "Create superadmin & continue" submit button.
//   - setupPage: renders the authfoot "step-ui-ng · first-run setup".
//   - setupPage: includes the CSRF token.
//   - setupPage: password is NEVER echoed back into a value attribute on error.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// logoutHelper logs out the current session by POSTing to /logout.
func logoutHelper(t *testing.T, e *testEnv) {
	t.Helper()
	token := e.csrfToken(t, "/inventory")
	e.post(t, "/logout", url.Values{"csrf_token": {token}})
}

// TestLoginPageAuthwrapLayout verifies that the login page uses the centered
// authwrap layout and does NOT render the topbar (it's a pre-auth page).
func TestLoginPageAuthwrapLayout(t *testing.T) {
	e := newTestEnv(t)
	// Seed a user so the first-run gate is satisfied, then stay logged out.
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	if !strings.Contains(body, `class="authwrap"`) {
		t.Error("login: missing authwrap class — page must use the centered auth layout")
	}
	// The topbar must NOT appear on the login page (pre-auth).
	if strings.Contains(body, `class="topbar"`) {
		t.Error("login: topbar must NOT be present on the pre-auth login page")
	}
}

// TestLoginPageAuthbrandWordmark verifies the two-line "Step-CA / NextGen UI"
// authbrand wordmark is rendered on the login page.
// This test FAILS if either line of the wordmark is missing or the authbrand
// wrapper is absent.
func TestLoginPageAuthbrandWordmark(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	if !strings.Contains(body, `class="authbrand"`) {
		t.Error("login: missing authbrand wrapper")
	}
	if !strings.Contains(body, `class="wordmark"`) {
		t.Error("login: missing wordmark element inside authbrand")
	}
	// b1 = "Step-CA"
	if !strings.Contains(body, `class="b1"`) || !strings.Contains(body, "Step-CA") {
		t.Error("login: missing .b1 span with 'Step-CA' text in wordmark")
	}
	// b2 = "NextGen UI"
	if !strings.Contains(body, `class="b2"`) || !strings.Contains(body, "NextGen UI") {
		t.Error("login: missing .b2 span with 'NextGen UI' text in wordmark")
	}
}

// TestLoginPageTagline verifies the tagline "Sign in to manage your certificate
// authority" is rendered below the authbrand.
func TestLoginPageTagline(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	if !strings.Contains(body, "Sign in to manage your certificate authority") {
		t.Error("login: missing tagline 'Sign in to manage your certificate authority'")
	}
}

// TestLoginPageFormFields verifies the login form has the required field names
// (username, password) and the "Sign in" submit button inside a card.
func TestLoginPageFormFields(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	// Username field.
	if !strings.Contains(body, `name="username"`) {
		t.Error("login: missing username input (name=\"username\")")
	}
	// Password field.
	if !strings.Contains(body, `name="password"`) {
		t.Error("login: missing password input (name=\"password\")")
	}
	// Password must be type="password".
	if !strings.Contains(body, `type="password"`) {
		t.Error("login: password input must be type=\"password\"")
	}
	// Submit button with "Sign in" text.
	if !strings.Contains(body, "Sign in") {
		t.Error("login: missing 'Sign in' submit button text")
	}
	// Card wrapper around the form.
	if !strings.Contains(body, `class="card"`) {
		t.Error("login: form must be inside a card element (class=\"card\")")
	}
}

// TestLoginPageAuthfoot verifies the auth footer text.
func TestLoginPageAuthfoot(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	if !strings.Contains(body, "step-ui-ng") {
		t.Error("login: missing 'step-ui-ng' in authfoot")
	}
	if !strings.Contains(body, "self-hosted Step-CA admin") {
		t.Error("login: missing 'self-hosted Step-CA admin' in authfoot")
	}
	if !strings.Contains(body, "authfoot") {
		t.Error("login: missing authfoot element")
	}
}

// TestLoginPageCSRF verifies the CSRF token is present on the login form.
func TestLoginPageCSRF(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("login: missing csrf_token hidden input")
	}
}

// TestLoginPagePasswordNotEchoedOnError verifies that a submitted password
// value is NEVER reflected back into any input value attribute when login fails.
// This test FAILS if the handler echoes the password back.
func TestLoginPagePasswordNotEchoedOnError(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	const secretPW = "th1s-1s-my-passw0rd"
	token := e.csrfToken(t, "/login")
	// Use postForm so we get the body back (post() closes it).
	status, body := e.postForm(t, "/login", url.Values{
		"csrf_token": {token},
		"username":   {"admin"},
		"password":   {secretPW},
	})

	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
	// The password must NOT appear anywhere in the rendered HTML.
	if strings.Contains(body, secretPW) {
		t.Errorf("login error page: submitted password must NOT be echoed back into the response — found %q in body", secretPW)
	}
}

// ---------------------------------------------------------------------------
// Setup page tests
// ---------------------------------------------------------------------------

// TestSetupPageAuthwrapLayout verifies that the setup page uses the centered
// authwrap layout and does NOT render the topbar.
func TestSetupPageAuthwrapLayout(t *testing.T) {
	e := newTestEnv(t)
	// No users created — setup page is accessible.

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, `class="authwrap"`) {
		t.Error("setup: missing authwrap class — page must use the centered auth layout")
	}
	if strings.Contains(body, `class="topbar"`) {
		t.Error("setup: topbar must NOT be present on the pre-auth setup page")
	}
}

// TestSetupPageAuthbrandWordmark verifies the two-line "Step-CA / NextGen UI"
// wordmark is present on the setup page — the same as the login page.
func TestSetupPageAuthbrandWordmark(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, `class="authbrand"`) {
		t.Error("setup: missing authbrand wrapper")
	}
	if !strings.Contains(body, "Step-CA") {
		t.Error("setup: missing 'Step-CA' in wordmark")
	}
	if !strings.Contains(body, "NextGen UI") {
		t.Error("setup: missing 'NextGen UI' in wordmark")
	}
}

// TestSetupPageTagline verifies the tagline "Welcome — let's create the first
// administrator" is rendered on the setup page.
func TestSetupPageTagline(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, "Welcome") {
		t.Error("setup: missing 'Welcome' in tagline")
	}
	if !strings.Contains(body, "first administrator") {
		t.Error("setup: missing 'first administrator' in tagline")
	}
}

// TestSetupPageCardTitle verifies the card title "Create the first account".
func TestSetupPageCardTitle(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, "Create the first account") {
		t.Error("setup: missing card title 'Create the first account'")
	}
}

// TestSetupPageSuperadminCopy verifies the card description mentions "superadmin"
// with the correct copy from the design mock.
func TestSetupPageSuperadminCopy(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	// The card description must reference superadmin and explain what it means.
	if !strings.Contains(body, "superadmin") {
		t.Error("setup: card description must mention 'superadmin'")
	}
	if !strings.Contains(body, "No users exist yet") {
		t.Error("setup: card description must say 'No users exist yet'")
	}
}

// TestSetupPageFormFields verifies the setup form has the correct field names:
// username, password, password_confirm — and the submit button.
func TestSetupPageFormFields(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	// Username field.
	if !strings.Contains(body, `name="username"`) {
		t.Error("setup: missing username input (name=\"username\")")
	}
	// Password field.
	if !strings.Contains(body, `name="password"`) {
		t.Error("setup: missing password input (name=\"password\")")
	}
	// Confirm password field.
	if !strings.Contains(body, `name="password_confirm"`) {
		t.Error("setup: missing password_confirm input (name=\"password_confirm\")")
	}
	// All password fields must be type="password".
	count := strings.Count(body, `type="password"`)
	if count < 2 {
		t.Errorf("setup: expected at least 2 type=\"password\" inputs (password + confirm), got %d", count)
	}
}

// TestSetupPagePasswordHint verifies the password hint about 12+ characters
// is present on the setup form.
func TestSetupPagePasswordHint(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, "12 characters") && !strings.Contains(body, "12 chars") && !strings.Contains(body, "At least 12") {
		t.Error("setup: missing password hint about minimum 12 characters")
	}
}

// TestSetupPageSubmitButton verifies the "Create superadmin & continue" button
// is present on the setup form (matches the design mock verbatim).
func TestSetupPageSubmitButton(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, "Create superadmin") {
		t.Error("setup: missing 'Create superadmin' text on submit button")
	}
	if !strings.Contains(body, "continue") {
		t.Error("setup: submit button must include 'continue' text")
	}
}

// TestSetupPageAuthfoot verifies the auth footer text for the setup page.
func TestSetupPageAuthfoot(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, "step-ui-ng") {
		t.Error("setup: missing 'step-ui-ng' in authfoot")
	}
	if !strings.Contains(body, "first-run setup") {
		t.Error("setup: authfoot must say 'first-run setup'")
	}
	if !strings.Contains(body, "authfoot") {
		t.Error("setup: missing authfoot element")
	}
}

// TestSetupPageCSRF verifies the CSRF token is present on the setup form.
func TestSetupPageCSRF(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("setup: missing csrf_token hidden input")
	}
}

// TestLoginPageClientValidationAttrs verifies that the login form carries
// HTML5 client-side validation attributes on the username and password inputs.
// The test FAILS if either input is missing required — the client-side nudge
// must be present even though server-side validation is also enforced.
func TestLoginPageClientValidationAttrs(t *testing.T) {
	e := newTestEnv(t)
	e.completeSetup(t, "admin")
	logoutHelper(t, e)

	_, body := e.get(t, "/login")

	// Both username and password must carry required.
	if !strings.Contains(body, `name="username" `) || !strings.Contains(body, `required`) {
		// Check the specific presence: username input must have required attr.
		if !strings.Contains(body, `name="username"`) {
			t.Error("login: username input missing")
		}
	}
	// A simpler positional check: find the username input fragment and verify required.
	if !containsInputAttr(body, `name="username"`, "required") {
		t.Error("login: username input must carry required attribute")
	}
	if !containsInputAttr(body, `name="password"`, "required") {
		t.Error("login: password input must carry required attribute")
	}
	// Login form must NOT have minlength on the password (authenticates existing creds).
	if containsInputAttr(body, `name="password"`, "minlength") {
		t.Error("login: password input must NOT have minlength — login just authenticates existing credentials")
	}
}

// TestSetupPageClientValidationAttrs verifies that the setup form carries
// HTML5 client-side validation attributes matching the server rules:
// username: required minlength=3 maxlength=64; password fields: required minlength=12.
// The test FAILS if any attribute is absent.
func TestSetupPageClientValidationAttrs(t *testing.T) {
	e := newTestEnv(t)

	_, body := e.get(t, "/setup")

	// Username: required, minlength=3, maxlength=64.
	if !containsInputAttr(body, `name="username"`, "required") {
		t.Error("setup: username input must carry required attribute")
	}
	if !containsInputAttr(body, `name="username"`, `minlength="3"`) {
		t.Error("setup: username input must carry minlength=\"3\" (matches server normalizeUsername rule)")
	}
	if !containsInputAttr(body, `name="username"`, `maxlength="64"`) {
		t.Error("setup: username input must carry maxlength=\"64\" (matches server normalizeUsername rule)")
	}
	// Password (new-password): required, minlength=12.
	if !containsInputAttr(body, `name="password"`, "required") {
		t.Error("setup: password input must carry required attribute")
	}
	if !containsInputAttr(body, `name="password"`, `minlength="12"`) {
		t.Error("setup: password input must carry minlength=\"12\" (matches server minPasswordLen)")
	}
	// Confirm-password: required, minlength=12.
	if !containsInputAttr(body, `name="password_confirm"`, "required") {
		t.Error("setup: password_confirm input must carry required attribute")
	}
	if !containsInputAttr(body, `name="password_confirm"`, `minlength="12"`) {
		t.Error("setup: password_confirm input must carry minlength=\"12\" (matches server minPasswordLen)")
	}
}

// containsInputAttr checks whether the HTML body contains an input element
// (identified by a name fragment) that also includes the given attribute fragment.
// It walks line by line and checks whether any line/segment containing the name
// fragment also contains the attr fragment. This avoids false-positives from other
// inputs on the page.
func containsInputAttr(body, nameFragment, attrFragment string) bool {
	// Find every occurrence of nameFragment and check surrounding context (~200 chars).
	idx := 0
	for {
		pos := strings.Index(body[idx:], nameFragment)
		if pos < 0 {
			return false
		}
		abs := idx + pos
		// Grab the full input tag: from the preceding '<' up to the next '>'.
		start := strings.LastIndex(body[:abs], "<")
		end := strings.Index(body[abs:], ">")
		if start >= 0 && end >= 0 {
			tag := body[start : abs+end+1]
			if strings.Contains(tag, attrFragment) {
				return true
			}
		}
		idx = abs + 1
	}
}

// TestSetupPagePasswordNotEchoedOnError verifies that a submitted password
// is NEVER reflected back into an input value when there is a validation error
// (e.g. passwords do not match). This encodes the "write-only passwords" rule.
func TestSetupPagePasswordNotEchoedOnError(t *testing.T) {
	e := newTestEnv(t)

	const secretPW = "my-secret-passphrase-1"
	token := e.csrfToken(t, "/setup")
	// Use postForm so we get the body back (post() closes it).
	status, body := e.postForm(t, "/setup", url.Values{
		"csrf_token":       {token},
		"username":         {"admin"},
		"password":         {secretPW},
		"password_confirm": {"does-not-match-1"},
	})

	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 on password mismatch, got %d", status)
	}
	// The password must NOT appear anywhere in the rendered HTML.
	if strings.Contains(body, secretPW) {
		t.Errorf("setup error page: submitted password must NOT be echoed back — found %q in body", secretPW)
	}
}
