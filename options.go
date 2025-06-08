package unbound

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type OptionFn func(*Options) error

type Options struct {
	ServerCertificates  []*x509.Certificate
	ControlCertificates []*x509.Certificate
	ControlPrivateKey   *rsa.PrivateKey
}

func WithServerCertificates(certs []*x509.Certificate) OptionFn {
	return func(c *Options) error {
		c.ServerCertificates = certs
		return nil
	}
}

func WithControlCertificates(certs []*x509.Certificate) OptionFn {
	return func(c *Options) error {
		c.ControlCertificates = certs
		return nil
	}
}

func WithControlPrivateKey(key *rsa.PrivateKey) OptionFn {
	return func(c *Options) error {
		c.ControlPrivateKey = key
		return nil
	}
}

func WithServerCertificatesFile(file string) OptionFn {
	return func(c *Options) error {
		if file == "" {
			return nil
		}

		certs, err := parseCertificateFile(file)
		if err != nil {
			return err
		}
		c.ServerCertificates = append(c.ServerCertificates, certs...)
		return nil
	}
}

func WithControlCertificatesFile(file string) OptionFn {
	return func(c *Options) error {
		if file == "" {
			return nil
		}

		certs, err := parseCertificateFile(file)
		if err != nil {
			return err
		}
		c.ControlCertificates = append(c.ControlCertificates, certs...)
		return nil
	}
}

func WithControlPrivateKeyFile(file string) OptionFn {
	return func(c *Options) error {
		if file == "" {
			return nil
		}

		key, err := parsePrivateKeyFile(file)
		if err != nil {
			return err
		}

		c.ControlPrivateKey = key
		return nil
	}
}

func parseCertificateFile(file string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read server certificate file: %w", err)
	}

	block, rest := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate file %s", file)
	}

	var certs []*x509.Certificate
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse server certificate: %w", err)
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}

func parsePrivateKeyFile(file string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read control private key file: %w", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("invalid private key file %s", file)
	}

	key1, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	key2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)

	var privateKey *rsa.PrivateKey
	switch {
	case err1 != nil && err2 != nil:
		return nil, fmt.Errorf("could not parse control private key, neither PKCS1 nor PKCS2: %w/%w", err1, err2)
	case err1 == nil:
		privateKey = key1
	default:
		if key, ok := key2.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("could not parse control private key, only RSA private key is supported: %w", err2)
		} else {
			privateKey = key
		}
	}

	return privateKey, nil
}
