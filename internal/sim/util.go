package sim

import (
	"crypto/tls"
	"encoding/json"
	"errors"

	"meshid/internal/identity"
	"meshid/internal/mesh"
)

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

type meshServerConfig struct {
	trust mesh.TrustSource
	creds *identity.Creds
}

func (m *meshServerConfig) config() (*tls.Config, error) {
	if m.creds == nil {
		return nil, errors.New("sim: node has no credentials")
	}
	return mesh.ServerConfig{
		Verifier: mesh.NewVerifier(mesh.VerifierConfig{Trust: m.trust, Expect: mesh.ExpectClient}),
		Certs:    asRotating(m.creds),
	}.TLSConfig(), nil
}

// asRotating adapts identity.Creds — which already implements both
// GetCertificate methods — to mesh's certificate-source interface.
func asRotating(c *identity.Creds) *mesh.RotatingSource { return mesh.NewRotatingSourceFrom(c) }
