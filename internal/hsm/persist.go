package hsm

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"

	"meshid/internal/certutil"
)

// The simulated module keeps its key material in files under a directory with
// mode 0700. This stands in for the TPM's non-volatile and sealed storage.
// Real TPMs refuse to release private keys at all; here the file permission is
// the only barrier, which is why the simulation treats "root on the machine"
// as equivalent to "controls that machine's identity" — and why the design
// never relies on a node's runtime secrets to protect *other* nodes.

func (m *Module) save(dir, node string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	writeKey := func(name string, k *ecdsa.PrivateKey) error {
		if k == nil {
			return nil
		}
		pemStr, err := certutil.EncodeKeyPEM(k)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), []byte(pemStr), 0o600)
	}
	writeCert := func(name string, c *x509.Certificate) error {
		if c == nil {
			return nil
		}
		return os.WriteFile(filepath.Join(dir, name), []byte(certutil.EncodeCertPEM(c.Raw)), 0o600)
	}
	if err := writeKey("ek.key", m.ekKey); err != nil {
		return err
	}
	if err := writeCert("ek.crt", m.EKCert); err != nil {
		return err
	}
	if err := writeCert("ek-root.crt", m.EKRoot); err != nil {
		return err
	}
	if err := writeKey("ak.key", m.akKey); err != nil {
		return err
	}
	if err := writeCert("ak.crt", m.akCert); err != nil {
		return err
	}
	if err := writeKey("node.key", m.nodeKey); err != nil {
		return err
	}
	if err := writeKey("nodeca.key", m.nodeCAKey); err != nil {
		return err
	}
	if m.akCSR != nil {
		os.WriteFile(filepath.Join(dir, "ak.csr"), []byte(certutil.EncodeCSRPEM(m.akCSR.Raw)), 0o600)
	}
	return nil
}

// OpenOrManufacture loads module state from dir, or creates a module with a
// vendor-certified EK if the directory holds no state.
func OpenOrManufacture(v *Vendor, dir, node string) (*Module, error) {
	if raw, err := os.ReadFile(filepath.Join(dir, "ek.crt")); err == nil {
		m := &Module{sealed: map[string][]byte{}}
		cp, err := certutil.ParseCertPEM(string(raw))
		if err != nil {
			return nil, err
		}
		m.EKCert = cp
		m.EKPub = cp.PublicKey.(*ecdsa.PublicKey)
		if r, err := os.ReadFile(filepath.Join(dir, "ek-root.crt")); err == nil {
			root, err := certutil.ParseCertPEM(string(r))
			if err != nil {
				return nil, err
			}
			m.EKRoot = root
		}
		if k, err := loadKey(filepath.Join(dir, "ek.key")); err == nil {
			m.ekKey = k
		}
		if k, err := loadKey(filepath.Join(dir, "ak.key")); err == nil {
			m.akKey = k
		}
		if c, err := loadCert(filepath.Join(dir, "ak.crt")); err == nil && c != nil {
			m.akCert = c
			if m.EKRoot != nil {
				m.akChain = []*x509.Certificate{c, m.EKCert, m.EKRoot}
			}
		}
		if csrRaw, err := os.ReadFile(filepath.Join(dir, "ak.csr")); err == nil {
			if csr, err := certutil.ParseCSR(string(csrRaw)); err == nil {
				m.akCSR = csr
			}
		}
		if k, err := loadKey(filepath.Join(dir, "node.key")); err == nil {
			m.nodeKey = k
		}
		if k, err := loadKey(filepath.Join(dir, "nodeca.key")); err == nil {
			m.nodeCAKey = k
		}
		return m, nil
	}
	m, err := Manufacture(v, node)
	if err != nil {
		return nil, err
	}
	if err := m.save(dir, node); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Module) Save(dir, node string) error { return m.save(dir, node) }

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return certutil.ParseKeyPEM(string(b))
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return certutil.ParseCertPEM(string(b))
}
