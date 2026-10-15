package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestJWKSToPEMMatchesTheKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding
	jwks := fmt.Sprintf(`{"keys": [{"use": "sig", "kty": "RSA", "kid": "k1", "alg": "RS256", "n": %q, "e": %q}, {"kty": "EC", "crv": "P-256"}]}`,
		b64.EncodeToString(key.PublicKey.N.Bytes()), b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()))

	keys, err := JWKSToPEM(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("want one RSA key, got %d", len(keys))
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	// The msecrets CLI's format: PKIX, 64-column base64, no trailing newline.
	encoded := base64.StdEncoding.EncodeToString(der)
	var lines []string
	for len(encoded) > 64 {
		lines, encoded = append(lines, encoded[:64]), encoded[64:]
	}
	want := "-----BEGIN PUBLIC KEY-----\n" + strings.Join(append(lines, encoded), "\n") + "\n-----END PUBLIC KEY-----"
	if keys[0] != want {
		t.Fatalf("PEM differs from the CLI's:\n%s\nwant\n%s", keys[0], want)
	}
	if block, _ := pem.Decode([]byte(keys[0])); block == nil {
		t.Fatal("not PEM")
	}
}

func TestJWKSWithoutRSAKeysIsRefused(t *testing.T) {
	if _, err := JWKSToPEM(`{"keys": [{"kty": "EC"}]}`); err == nil {
		t.Fatal("want an error")
	}
}

func TestUnacceptedSkipsInfoAndAcceptedFindings(t *testing.T) {
	findings := []Finding{{Code: "MS-W035", Level: "info"}, {Code: "MS-W034", Level: "warning"}, {Code: "MS-W036", Level: "warning"}}
	got := Unaccepted(findings, map[string]string{"MS-W036": "groups exist"})
	if len(got) != 1 || got[0].Code != "MS-W034" {
		t.Fatalf("got %v", got)
	}
}

func TestAcceptancesListOnlyThePlansFindings(t *testing.T) {
	apply := acceptances([]Finding{{Code: "MS-W036", Level: "warning"}, {Code: "MS-W036", Level: "warning"}},
		map[string]string{"MS-W036": "groups exist", "MS-W034": "not in this plan"})
	if len(apply.Accept) != 1 || apply.Accept[0].Code != "MS-W036" || apply.Accept[0].Reason != "groups exist" {
		t.Fatalf("got %+v", apply.Accept)
	}
}

func TestFindingsErrorSuggestsAcceptFindings(t *testing.T) {
	err := error(&FindingsError{Plan: &Plan{Target: "acme/web/staging"}, Findings: []Finding{{Code: "MS-W036", Level: "warning", Message: "Create the groups."}}})
	var findings *FindingsError
	if !errors.As(err, &findings) || !strings.Contains(err.Error(), `"MS-W036" = "<why this is fine>"`) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiryReadsTheJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp": 2000000000}`))
	if got := expiry("h." + payload + ".s").Unix(); got != 2000000000 {
		t.Fatalf("got %d", got)
	}
}

func TestNewNeedsExactlyOneWayToLogIn(t *testing.T) {
	for _, credentials := range []Credentials{{}, {Token: "t", TokenCommand: "c"}, {ClientID: "id"}} {
		if _, err := New("https://example", credentials, nil); err == nil {
			t.Fatalf("want an error for %+v", credentials)
		}
	}
	if _, err := New("https://example", Credentials{TokenCommand: "msecrets auth token"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestTokenCommandMustPrintOneToken(t *testing.T) {
	if token, err := runTokenCommand(context.Background(), "echo abc.def.ghi"); err != nil || token != "abc.def.ghi" {
		t.Fatalf("got %q, %v", token, err)
	}
	if _, err := runTokenCommand(context.Background(), "printf 'a\nb\n'"); err == nil {
		t.Fatal("want an error for two lines")
	}
	if _, err := runTokenCommand(context.Background(), "exit 3"); err == nil {
		t.Fatal("want an error for a failed command")
	}
}
