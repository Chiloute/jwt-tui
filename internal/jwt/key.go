package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type KeyEncoding int

const (
	EncNone KeyEncoding = iota
	EncPlain
	EncPEM
	EncDER
	EncJWKS
)

func (e KeyEncoding) String() string {
	switch e {
	case EncPlain:
		return "plain"
	case EncPEM:
		return "PEM"
	case EncDER:
		return "DER"
	case EncJWKS:
		return "JWKS"
	}
	return "none"
}

type Key struct {
	Bytes    []byte
	Encoding KeyEncoding
	Origin   string
	Base64   bool
	Private  bool
}

func (k Key) Empty() bool { return k.Encoding == EncNone }

func ResolveKey(spec string) (Key, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return Key{}, nil
	}

	var k Key
	material := []byte(spec)

	if rest, ok := strings.CutPrefix(trimmed, "b64:"); ok {
		b, err := decodeBase64(strings.TrimSpace(rest))
		if err != nil {
			return Key{}, err
		}
		material, k.Base64 = b, true
	}

	if rest, ok := strings.CutPrefix(strings.TrimSpace(string(material)), "@"); ok {
		path, err := expandPath(strings.TrimSpace(rest))
		if err != nil {
			return Key{}, err
		}
		b, err := readKeyFile(path)
		if err != nil {
			return Key{}, err
		}
		material, k.Origin = b, path
	}

	k.Bytes = material
	k.Encoding = sniffEncoding(material, k.Origin != "" || k.Base64)
	k.Private = k.looksPrivate()
	return k, nil
}

func sniffEncoding(b []byte, binaryPossible bool) KeyEncoding {
	if bytes.Contains(b, []byte("-----BEGIN")) {
		return EncPEM
	}
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		return EncJWKS
	}
	if binaryPossible && len(b) > 1 && b[0] == 0x30 {
		return EncDER
	}
	return EncPlain
}

func (k Key) looksPrivate() bool {
	switch k.Encoding {
	case EncPlain:
		return true
	case EncPEM, EncDER:
		kp, err := k.keyPair()
		return err == nil && kp.priv != nil
	case EncJWKS:
		set, err := parseJWKS(k.Bytes)
		if err != nil {
			return false
		}
		for i := range set.Keys {
			if set.Keys[i].hasPrivate() {
				return true
			}
		}
	}
	return false
}

func (k Key) isAsymmetric(kid string) bool {
	switch k.Encoding {
	case EncPEM, EncDER:
		return true
	case EncJWKS:
		j, err := k.jwk(kid)
		if err != nil {
			return false
		}
		return j.isAsymmetric()
	}
	return false
}

func (k Key) jwk(kid string) (*jwk, error) {
	set, err := parseJWKS(k.Bytes)
	if err != nil {
		return nil, err
	}
	return set.selectKey(kid)
}

func (k Key) VerificationKey(alg, kid string) (any, error) {
	if AlgoFamily(alg) == "HMAC" {
		return k.hmacSecret(kid)
	}
	return k.publicKey(alg, kid)
}

func (k Key) SigningKey(alg, kid string) (any, error) {
	if AlgoFamily(alg) == "HMAC" {
		return k.hmacSecret(kid)
	}

	if k.Encoding == EncJWKS {
		return nil, fmt.Errorf("%w: signing from a JWK set is not supported, give the private key as PEM or DER",
			ErrKeyUnreadable)
	}

	kp, err := k.keyPair()
	if err != nil {
		return nil, err
	}
	if kp.priv == nil {
		return nil, fmt.Errorf("%w: signing %s needs the private half, this key only carries the public one",
			ErrKeyUnreadable, alg)
	}
	if err := matchesFamily(kp.priv, alg); err != nil {
		return nil, err
	}
	return kp.priv, nil
}

func (k Key) hmacSecret(kid string) ([]byte, error) {
	switch k.Encoding {
	case EncPlain:
		return k.Bytes, nil
	case EncJWKS:
		j, err := k.jwk(kid)
		if err != nil {
			return nil, err
		}
		if j.isAsymmetric() {
			return nil, fmt.Errorf("%w: JWK is %s, not a symmetric secret", ErrKeyUnreadable, j.Kty)
		}
		secret, err := j.publicKey()
		if err != nil {
			return nil, err
		}
		return secret.([]byte), nil
	}
	return nil, fmt.Errorf("%w: %s key material cannot be used as an HMAC secret",
		ErrKeyUnreadable, k.Encoding)
}

func (k Key) publicKey(alg, kid string) (any, error) {
	if k.Encoding == EncJWKS {
		j, err := k.jwk(kid)
		if err != nil {
			return nil, err
		}
		pub, err := j.publicKey()
		if err != nil {
			return nil, err
		}
		if err := matchesFamily(pub, alg); err != nil {
			return nil, err
		}
		return pub, nil
	}

	kp, err := k.keyPair()
	if err != nil {
		return nil, err
	}
	pub := kp.pub
	if pub == nil && kp.priv != nil {
		signer, ok := kp.priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%w: cannot derive a public key from this private key", ErrKeyUnreadable)
		}
		pub = signer.Public()
	}
	if err := matchesFamily(pub, alg); err != nil {
		return nil, err
	}
	return pub, nil
}

type keyPair struct {
	pub  crypto.PublicKey
	priv crypto.PrivateKey
}

func (k Key) keyPair() (keyPair, error) {
	der := k.Bytes
	blockType := ""

	if k.Encoding == EncPEM {
		block, _ := pem.Decode(k.Bytes)
		if block == nil {
			return keyPair{}, fmt.Errorf("%w: no PEM block found", ErrKeyUnreadable)
		}
		der, blockType = block.Bytes, block.Type
	}

	switch blockType {
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(der)
		return keyPair{pub: pub}, wrapKeyErr(err)
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(der)
		return keyPair{pub: pub}, wrapKeyErr(err)
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(der)
		return keyPair{priv: priv}, wrapKeyErr(err)
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(der)
		return keyPair{priv: priv}, wrapKeyErr(err)
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(der)
		return keyPair{priv: priv}, wrapKeyErr(err)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return keyPair{}, wrapKeyErr(err)
		}
		return keyPair{pub: cert.PublicKey}, nil
	case "":
		return parseDER(der)
	}
	return keyPair{}, fmt.Errorf("%w: unsupported PEM block %q", ErrKeyUnreadable, blockType)
}

func parseDER(der []byte) (keyPair, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return keyPair{pub: pub}, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return keyPair{pub: pub}, nil
	}
	if priv, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return keyPair{priv: priv}, nil
	}
	if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return keyPair{priv: priv}, nil
	}
	if priv, err := x509.ParseECPrivateKey(der); err == nil {
		return keyPair{priv: priv}, nil
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		return keyPair{pub: cert.PublicKey}, nil
	}
	return keyPair{}, fmt.Errorf("%w: DER is not a key or certificate we recognise", ErrKeyUnreadable)
}

func matchesFamily(key any, alg string) error {
	family := AlgoFamily(alg)
	var got string

	switch key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		if family == "RSA" || family == "RSAPSS" {
			return nil
		}
		got = "RSA"
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		if family == "ECDSA" {
			return nil
		}
		got = "ECDSA"
	case ed25519.PublicKey, ed25519.PrivateKey:
		if family == "Ed25519" {
			return nil
		}
		got = "Ed25519"
	case []byte:
		if family == "HMAC" {
			return nil
		}
		got = "symmetric"
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrKeyUnreadable, key)
	}

	return fmt.Errorf("%w: %s needs a %s key, this one is %s", ErrKeyUnreadable, alg, family, got)
}

func wrapKeyErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
}

func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: the b64: key is not valid base64", ErrKeyUnreadable)
}

func expandPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: @ with no path", ErrKeyUnreadable)
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("%w: cannot expand ~: %v", ErrKeyUnreadable, err)
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	return p, nil
}

var keyFiles struct {
	mu    sync.Mutex
	path  string
	mtime time.Time
	size  int64
	data  []byte
}

func readKeyFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnreadable, unwrapPathErr(err))
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory", ErrKeyUnreadable, path)
	}

	keyFiles.mu.Lock()
	defer keyFiles.mu.Unlock()

	if keyFiles.path == path && keyFiles.size == st.Size() && keyFiles.mtime.Equal(st.ModTime()) {
		return keyFiles.data, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnreadable, unwrapPathErr(err))
	}
	keyFiles.path, keyFiles.size, keyFiles.mtime, keyFiles.data = path, st.Size(), st.ModTime(), data
	return data, nil
}

func unwrapPathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %v", pe.Path, pe.Err)
	}
	return err
}
