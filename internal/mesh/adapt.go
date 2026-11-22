package mesh

import "crypto/tls"

// CertificateGetter is anything that can supply the current certificate for a
// handshake. identity.Creds implements it, as does RotatingSource.
type CertificateGetter interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// NewRotatingSourceFrom adapts a CertificateGetter to a *RotatingSource-like
// handle used by ServerConfig and DialConfig.
func NewRotatingSourceFrom(g CertificateGetter) *RotatingSource {
	return &RotatingSource{getter: g}
}
