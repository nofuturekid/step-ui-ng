package app

// Client onboarding snippets for ACME clients (spec/0010 FR-4): certbot, acme.sh,
// Caddy and Traefik, parameterized with the directory URL and — when EAB is
// required — the EAB keyID/HMAC. When the actual keyID/HMAC are known (just after
// a create), they are substituted; otherwise clear placeholders are used so the
// operator knows where to paste their own EAB credentials.

import "strings"

// clientSnippet is one copy-paste snippet for a named ACME client.
type clientSnippet struct {
	Client string // e.g. "certbot"
	Code   string // the ready-to-copy command/config
}

// eabKeyIDPlaceholder / eabHMACPlaceholder are shown when the real EAB values are
// not available (e.g. on the list page, where the HMAC is never re-shown).
const (
	eabKeyIDPlaceholder = "<EAB_KEY_ID>"
	eabHMACPlaceholder  = "<EAB_HMAC>"
)

// buildSnippets returns the client snippets for a directory URL. When requireEAB
// is true the snippets include the EAB parameters; keyID/hmac are substituted when
// non-empty (the one-time create display), else placeholders are used.
func buildSnippets(directoryURL string, requireEAB bool, keyID, hmac string) []clientSnippet {
	kid := keyID
	if kid == "" {
		kid = eabKeyIDPlaceholder
	}
	mac := hmac
	if mac == "" {
		mac = eabHMACPlaceholder
	}

	return []clientSnippet{
		{Client: "certbot", Code: certbotSnippet(directoryURL, requireEAB, kid, mac)},
		{Client: "acme.sh", Code: acmeShSnippet(directoryURL, requireEAB, kid, mac)},
		{Client: "Caddy", Code: caddySnippet(directoryURL, requireEAB, kid, mac)},
		{Client: "Traefik", Code: traefikSnippet(directoryURL, requireEAB, kid, mac)},
	}
}

func certbotSnippet(dir string, eab bool, kid, mac string) string {
	var b strings.Builder
	b.WriteString("certbot certonly --standalone \\\n")
	b.WriteString("  --server " + dir + " \\\n")
	if eab {
		b.WriteString("  --eab-kid " + kid + " \\\n")
		b.WriteString("  --eab-hmac-key " + mac + " \\\n")
	}
	b.WriteString("  -d example.com")
	return b.String()
}

func acmeShSnippet(dir string, eab bool, kid, mac string) string {
	var b strings.Builder
	b.WriteString("acme.sh --register-account --server " + dir)
	if eab {
		b.WriteString(" \\\n  --eab-kid " + kid + " --eab-hmac-key " + mac)
	}
	b.WriteString("\n")
	b.WriteString("acme.sh --issue --server " + dir + " -d example.com --standalone")
	return b.String()
}

func caddySnippet(dir string, eab bool, kid, mac string) string {
	var b strings.Builder
	b.WriteString("example.com {\n")
	b.WriteString("  tls {\n")
	b.WriteString("    issuer acme {\n")
	b.WriteString("      dir " + dir + "\n")
	if eab {
		b.WriteString("      eab " + kid + " " + mac + "\n")
	}
	b.WriteString("    }\n")
	b.WriteString("  }\n")
	b.WriteString("}")
	return b.String()
}

func traefikSnippet(dir string, eab bool, kid, mac string) string {
	var b strings.Builder
	b.WriteString("# traefik static config (YAML)\n")
	b.WriteString("certificatesResolvers:\n")
	b.WriteString("  step:\n")
	b.WriteString("    acme:\n")
	b.WriteString("      caServer: " + dir + "\n")
	if eab {
		b.WriteString("      eab:\n")
		b.WriteString("        kid: " + kid + "\n")
		b.WriteString("        hmacEncoded: " + mac + "\n")
	}
	b.WriteString("      tlsChallenge: {}")
	return b.String()
}
