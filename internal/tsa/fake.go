package tsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/digitorus/timestamp"
)

// Fake is an in-process TSA for tests and local trials. It is never used
// unless explicitly constructed.
type Fake struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	Now  func() time.Time
}

// NewFake creates a fake TSA with a self-signed time stamping certificate.
func NewFake() (*Fake, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Fake{Cert: cert, Key: key}, nil
}

// Pool returns a CertPool holding the fake TSA certificate.
func (f *Fake) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(f.Cert)
	return p
}

// Stamp implements Stamper.
func (f *Fake) Stamp(_ context.Context, data []byte, _ string) ([]byte, error) {
	now := time.Now()
	if f.Now != nil {
		now = f.Now()
	}
	ts := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     Digest(data),
		Time:              now,
		Policy:            []int{1, 2, 3, 4, 1},
		AddTSACertificate: true,
		Nonce:             big.NewInt(1),
	}
	return ts.CreateResponse(f.Cert, f.Key)
}
