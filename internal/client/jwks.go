package client

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWKSToPEM returns a JWKS document's RSA keys as PEM public keys, which a
// pinned cluster's trust takes. Kubernetes publishes its service-account
// signing keys this way: kubectl get --raw /openid/v1/jwks. The PEM is the
// same as the msecrets CLI's (clusters register --jwks): PKIX, 64-column
// base64, no trailing newline.
func JWKSToPEM(document string) ([]string, error) {
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(document), &jwks); err != nil {
		return nil, fmt.Errorf("the JWKS isn't JSON: %w", err)
	}
	var keys []string
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("a key's modulus isn't base64url: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("a key's exponent isn't base64url: %w", err)
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		keys = append(keys, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))))
	}
	if len(keys) == 0 {
		return nil, errors.New("the JWKS has no RSA keys")
	}
	return keys, nil
}
