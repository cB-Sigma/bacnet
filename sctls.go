package bacnet

// The TLS profile of BACnet/SC connections (Annex AB.7.4): TLS 1.3 only,
// mutual authentication with the operational certificate, and the peer's
// certificate accepted when it is well formed, valid now and directly
// signed by one of the configured issuer certificates. No other check
// (host name, extended key usage, chain building through intermediates)
// is made unless the installation turns it on (VerifyHostname).
//
// tlsx (a fork of crypto/tls) is used rather than crypto/tls because
// AB.7.5.4 asks for TLS key updates to refresh session keys, and
// crypto/tls has no way to send a TLS 1.3 KeyUpdate on demand; tlsx has
// Conn.SendKeyUpdate. TLS_AES_128_GCM_SHA256, ecdsa_secp256r1_sha256 and
// secp256r1 key exchange, which AB.7.4 requires, are all supported.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/cB-Sigma/tlsx"
)

// SCTLS is a BACnet/SC node's operational credentials (AB.7.4.1.1) and
// the checks it makes of its peers. The hooks are optional: an
// application puts its crypto policy, revocation checks and cipher suite
// restrictions there; without them only the checks of AB.7.4 (a) to (d)
// are made and tlsx's TLS 1.3 suites are offered.
type SCTLS struct {
	Certificate tlsx.Certificate    // the operational certificate and its key
	Issuers     []*x509.Certificate // the issuer certificates peers must be signed by
	// VerifyHostname additionally checks the hub's certificate against
	// the host of its URI (an installation option; off by default as
	// AB.7.4 requires).
	VerifyHostname bool
	// Now is the clock for validity checks; nil is time.Now.
	Now func() time.Time
	// CheckCertificate, when set, judges a peer certificate under the
	// application's crypto policy (use is "peer certificate"); an error
	// refuses it.
	CheckCertificate func(use string, c *x509.Certificate) error
	// CheckRevocation, when set, is called for a peer certificate that is
	// directly signed by issuer (AB.7.4 (c): revocation is a local
	// matter). An error refuses the certificate.
	CheckRevocation func(ctx context.Context, leaf, issuer *x509.Certificate) error
	// TLS13CipherSuites, when set and returning a non-empty list,
	// restricts the TLS 1.3 cipher suites; it is asked each time a
	// configuration is made.
	TLS13CipherSuites func() []uint16
}

func (s *SCTLS) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// VerifyPeer is the mutual authentication of AB.7.4 (a) to (d):
// well-formed, active now and not expired, and directly signed by one of
// the issuer certificates (the signature checks with its public key).
// Revocation (a local matter in AB.7.4) is checked with CheckRevocation.
func (s *SCTLS) VerifyPeer(raw [][]byte) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, errors.New("the peer sent no certificate")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, fmt.Errorf("the peer's certificate is malformed: %w", err)
	}
	if s.CheckCertificate != nil {
		if err := s.CheckCertificate("peer certificate", leaf); err != nil {
			return nil, err
		}
	}
	now := s.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the peer's certificate is not valid now (valid %s to %s)", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	for _, iss := range s.Issuers {
		if iss.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
			if s.CheckRevocation != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := s.CheckRevocation(ctx, leaf, iss); err != nil {
					return nil, fmt.Errorf("the peer's certificate failed the revocation check: %w", err)
				}
			}
			return leaf, nil
		}
	}
	return nil, errors.New("the peer's certificate is not directly signed by a configured issuer certificate")
}

// Config is the TLS configuration for one side: client for the hub
// connector (serverName is the URI's host), server for the hub function.
func (s *SCTLS) Config(server bool, serverName string) *tlsx.Config {
	cfg := &tlsx.Config{
		MinVersion:       tlsx.VersionTLS13,
		MaxVersion:       tlsx.VersionTLS13,
		Certificates:     []tlsx.Certificate{s.Certificate},
		CurvePreferences: []tlsx.CurveID{tlsx.CurveP256, tlsx.X25519},
		NextProtos:       []string{"http/1.1"},
		// Chain building is replaced by verifyPeer (direct signing only).
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			leaf, err := s.VerifyPeer(raw)
			if err != nil {
				return err
			}
			if !server && s.VerifyHostname && serverName != "" {
				return leaf.VerifyHostname(serverName)
			}
			return nil
		},
	}
	if server {
		cfg.ClientAuth = tlsx.RequireAnyClientCert
		cfg.InsecureSkipVerify = false
	}
	if s.TLS13CipherSuites != nil {
		if suites := s.TLS13CipherSuites(); len(suites) > 0 {
			cfg.Ext.CipherSuitesTLS13 = suites
		}
	}
	return cfg
}
