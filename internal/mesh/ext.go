package mesh

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"

	"meshid/internal/certutil"
)

var (
	oidMeta  = certutil.OIDMeshMeta
	oidScope = certutil.OIDMeshScope
)

type meta = certutil.Meta

type scope = certutil.Scope

func certExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
