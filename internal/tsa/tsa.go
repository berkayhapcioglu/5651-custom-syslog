// Package tsa obtains and checks RFC 3161 time stamps.
//
// Two modes are supported:
//
//   - http: a standard RFC 3161 request is POSTed to the configured URL
//     (application/timestamp-query). Works with any RFC 3161 TSA.
//   - exec: an external client is run. KamuSM's TSA needs its own
//     authentication (customer number + password through their client
//     library), so the official client is wrapped this way.
//
// In both modes the response is parsed, its signature is checked against the
// certificate embedded in it, and the message imprint is compared with the
// SHA-256 of the data. When a CA file is configured the signer certificate
// must also chain to it and be valid for time stamping.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
)

// Stamper produces a DER-encoded TimeStampResp for data.
type Stamper interface {
	Stamp(ctx context.Context, data []byte, dataPath string) ([]byte, error)
}

// Result is a checked time stamp.
type Result struct {
	Time    time.Time
	Serial  string
	Subject string
}

// HTTP talks RFC 3161 over HTTP(S).
type HTTP struct {
	URL      string
	Username string
	Password string
	Headers  map[string]string
	Policy   string
	Client   *http.Client
}

// Stamp implements Stamper.
func (h *HTTP) Stamp(ctx context.Context, data []byte, _ string) ([]byte, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	opts := &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true, Nonce: nonce}
	if h.Policy != "" {
		oid, err := parseOID(h.Policy)
		if err != nil {
			return nil, err
		}
		opts.TSAPolicyOID = asn1.ObjectIdentifier(oid)
	}
	req, err := timestamp.CreateRequest(bytes.NewReader(data), opts)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	hreq.Header.Set("Accept", "application/timestamp-reply")
	for k, v := range h.Headers {
		hreq.Header.Set(k, v)
	}
	if h.Username != "" {
		hreq.SetBasicAuth(h.Username, h.Password)
	}
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa: HTTP %d", resp.StatusCode)
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, errors.New("tsa: nonce mismatch")
	}
	return body, nil
}

// Exec runs an external client. Command elements may contain {data} (path of
// the data to stamp) and {out} (where the client must write the DER response).
type Exec struct {
	Command []string
	Timeout time.Duration
}

// Stamp implements Stamper.
func (e *Exec) Stamp(ctx context.Context, _ []byte, dataPath string) ([]byte, error) {
	out := dataPath + ".tsr.tmp"
	defer os.Remove(out)
	args := make([]string, len(e.Command))
	for i, a := range e.Command {
		a = strings.ReplaceAll(a, "{data}", dataPath)
		args[i] = strings.ReplaceAll(a, "{out}", out)
	}
	t := e.Timeout
	if t == 0 {
		t = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	// #nosec G204 -- command comes from the operator's config; no shell is involved
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tsa exec: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	b, err := os.ReadFile(out) // #nosec G304 -- path derived from data path
	if err != nil {
		return nil, fmt.Errorf("tsa exec: no response written: %w", err)
	}
	return b, nil
}

// Check verifies a DER TimeStampResp against data. roots may be nil to skip
// chain verification (the embedded signature is still checked).
func Check(resp, data []byte, roots *x509.CertPool) (*Result, error) {
	ts, err := timestamp.ParseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("time stamp: %w", err)
	}
	if ts.HashAlgorithm != crypto.SHA256 && ts.HashAlgorithm != crypto.SHA384 && ts.HashAlgorithm != crypto.SHA512 {
		return nil, fmt.Errorf("time stamp: weak hash algorithm %v", ts.HashAlgorithm)
	}
	h := ts.HashAlgorithm.New()
	h.Write(data)
	if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
		return nil, errors.New("time stamp: message imprint does not match the data")
	}
	if len(ts.Certificates) == 0 {
		return nil, errors.New("time stamp: response carries no certificate (request certReq)")
	}
	signer := ts.Certificates[0]
	for _, c := range ts.Certificates {
		for _, u := range c.ExtKeyUsage {
			if u == x509.ExtKeyUsageTimeStamping {
				signer = c
			}
		}
	}
	if roots != nil {
		inter := x509.NewCertPool()
		for _, c := range ts.Certificates {
			if c != signer {
				inter.AddCert(c)
			}
		}
		if _, err := signer.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			CurrentTime:   ts.Time,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}); err != nil {
			return nil, fmt.Errorf("time stamp: TSA certificate: %w", err)
		}
	}
	return &Result{Time: ts.Time, Serial: ts.SerialNumber.String(), Subject: signer.Subject.String()}, nil
}

// LoadRoots reads PEM or DER certificates from a file.
func LoadRoots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied CA path
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if bytes.Contains(b, []byte("-----BEGIN")) {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, err
			}
			pool.AddCert(c)
		}
		return pool, nil
	}
	c, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}
	pool.AddCert(c)
	return pool, nil
}

// Digest is the SHA-256 the stamp is expected to cover.
func Digest(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

func parseOID(s string) ([]int, error) {
	var oid []int
	for _, p := range strings.Split(s, ".") {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 {
			return nil, fmt.Errorf("bad policy OID %q", s)
		}
		oid = append(oid, n)
	}
	return oid, nil
}
