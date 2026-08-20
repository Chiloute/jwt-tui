package jwt

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	K   string `json:"k"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

func parseJWKS(b []byte) (*jwkSet, error) {
	var set jwkSet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON", ErrKeyUnreadable)
	}
	if len(set.Keys) == 0 {
		var single jwk
		if err := json.Unmarshal(b, &single); err != nil || single.Kty == "" {
			return nil, fmt.Errorf("%w: no keys in the JWK set", ErrKeyUnreadable)
		}
		set.Keys = []jwk{single}
	}
	return &set, nil
}

func (s *jwkSet) selectKey(kid string) (*jwk, error) {
	if kid == "" {
		if len(s.Keys) == 1 {
			return &s.Keys[0], nil
		}
		return nil, fmt.Errorf("%w: the token has no kid and the JWK set holds %d keys",
			ErrKeyUnreadable, len(s.Keys))
	}
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			return &s.Keys[i], nil
		}
	}
	if len(s.Keys) == 1 && s.Keys[0].Kid == "" {
		return &s.Keys[0], nil
	}
	return nil, fmt.Errorf("%w: no JWK with kid %q", ErrKeyUnreadable, kid)
}

func (k *jwk) isAsymmetric() bool { return k.Kty != "oct" }

func (k *jwk) hasPrivate() bool {
	if k.Kty == "oct" {
		return k.K != ""
	}
	return k.D != ""
}

func (k *jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaPublicKey()
	case "EC":
		return k.ecPublicKey()
	case "OKP":
		return k.ed25519PublicKey()
	case "oct":
		return k.decode("k", k.K)
	case "":
		return nil, fmt.Errorf("%w: JWK has no kty", ErrKeyUnreadable)
	}
	return nil, fmt.Errorf("%w: unsupported JWK kty %q", ErrKeyUnreadable, k.Kty)
}

func (k *jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := k.decode("n", k.N)
	if err != nil {
		return nil, err
	}
	e, err := k.decode("e", k.E)
	if err != nil {
		return nil, err
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, fmt.Errorf("%w: RSA JWK needs both n and e", ErrKeyUnreadable)
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: RSA exponent out of range", ErrKeyUnreadable)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}

func (k *jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
	curve, ecdhCurve, err := ecCurve(k.Crv)
	if err != nil {
		return nil, err
	}
	x, err := k.decode("x", k.X)
	if err != nil {
		return nil, err
	}
	y, err := k.decode("y", k.Y)
	if err != nil {
		return nil, err
	}

	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size || len(x) == 0 || len(y) == 0 {
		return nil, fmt.Errorf("%w: EC coordinates do not fit %s", ErrKeyUnreadable, k.Crv)
	}

	point := make([]byte, 1+2*size)
	point[0] = 4
	new(big.Int).SetBytes(x).FillBytes(point[1 : 1+size])
	new(big.Int).SetBytes(y).FillBytes(point[1+size:])
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("%w: EC point is not on curve %s", ErrKeyUnreadable, k.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func (k *jwk) ed25519PublicKey() (ed25519.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: unsupported OKP curve %q", ErrKeyUnreadable, k.Crv)
	}
	x, err := k.decode("x", k.X)
	if err != nil {
		return nil, err
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 x is %d bytes, want %d",
			ErrKeyUnreadable, len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}

func ecCurve(crv string) (elliptic.Curve, ecdh.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), ecdh.P256(), nil
	case "P-384":
		return elliptic.P384(), ecdh.P384(), nil
	case "P-521":
		return elliptic.P521(), ecdh.P521(), nil
	}
	return nil, nil, fmt.Errorf("%w: unsupported EC curve %q", ErrKeyUnreadable, crv)
}

func (k *jwk) decode(name, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(value); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("%w: JWK field %q is not base64url", ErrKeyUnreadable, name)
}
