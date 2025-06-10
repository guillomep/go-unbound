// Library used to remotely control unbound
package unbound

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Unbound client interface
type Client interface {
	// Retrieve local data from Unbound
	LocalData() []RR
	// Add a record to unbound
	AddLocalData(rr RR) error
	// Remove a record from unbound
	RemoveLocalData(rr RR) error
}

// Resource records
type RR struct {
	Name  string
	Value string
	TTL   int
	Type  string
}

// Unbound client configuration
type UnboundClient struct {
	Client
	scheme string
	host   string

	tlsConfig *tls.Config
}

func NewClient(host string, opts ...OptionFn) (*UnboundClient, error) {
	var options Options
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	parsedURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	clientHost := parsedURL.Host
	if parsedURL.Scheme == "unix" {
		clientHost = parsedURL.Path
	}

	return &UnboundClient{
		scheme:    parsedURL.Scheme,
		host:      clientHost,
		tlsConfig: (*UnboundClient)(nil).buildTLSConfig(options),
	}, nil
}

// Deprecated: Use NewClient instead.
func NewUnboundClient(host string, serverCertFile, controlPrivateKeyFile, controlCertFile string) (*UnboundClient, error) {
	return NewClient(host,
		WithServerCertificatesFile(serverCertFile),
		WithControlCertificatesFile(controlCertFile),
		WithControlPrivateKeyFile(controlPrivateKeyFile),
	)
}

func (_ *UnboundClient) buildTLSConfig(opts Options) *tls.Config {
	if len(opts.ServerCertificates) == 0 && len(opts.ControlCertificates) == 0 {
		return nil
	}

	roots := x509.NewCertPool()
	for _, cert := range opts.ServerCertificates {
		roots.AddCert(cert)
	}

	controlCertificate := tls.Certificate{
		Certificate: func() (certs [][]byte) {
			for _, cert := range opts.ControlCertificates {
				certs = append(certs, cert.Raw)
			}
			return certs
		}(),
		PrivateKey: opts.ControlPrivateKey,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{controlCertificate},
		RootCAs:      roots,
		ServerName:   "unbound",
	}
}

// Return all local records of an unbound server
func (u *UnboundClient) LocalData() []RR {
	dataCh := make(chan string)
	errCh := make(chan error)

	var rrs []RR
	go sendCommand("list_local_data", u, dataCh, errCh)
	select {
	case line := <-dataCh:
		if rr, err := parseLocalData(line); err == nil {
			rrs = append(rrs, rr)
		}
		for line = range dataCh {
			if rr, err := parseLocalData(line); err == nil {
				rrs = append(rrs, rr)
			}
		}
		break
	case <-errCh:
		return nil
	}

	return rrs
}

// Add a record to the unbound server
func (u *UnboundClient) AddLocalData(rr RR) error {
	dataCh := make(chan string)
	errCh := make(chan error)

	var sb strings.Builder

	sb.WriteString("local_data ")
	sb.WriteString(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", rr.Name, rr.TTL, rr.Type, rr.Value))

	go sendCommand(sb.String(), u, dataCh, errCh)

	select {
	case line := <-dataCh:
		if strings.ToLower(line) != "ok" {
			return fmt.Errorf("Failed to add local data: %s", line)
		}
		break
	case err := <-errCh:
		return fmt.Errorf("Failed to add local data: %v", err)
	}

	return nil
}

// Remove a record from the unbound server
func (u *UnboundClient) RemoveLocalData(rr RR) error {
	dataCh := make(chan string)
	errCh := make(chan error)

	var sb strings.Builder

	sb.WriteString("local_data_remove ")
	sb.WriteString(rr.Name)

	go sendCommand(sb.String(), u, dataCh, errCh)

	select {
	case line := <-dataCh:
		if strings.ToLower(line) != "ok" {
			return fmt.Errorf("Failed to delete local data: %s", line)
		}
		break
	case err := <-errCh:
		return fmt.Errorf("Failed to delete local data: %v", err)
	}

	return nil
}

func parseLocalData(data string) (RR, error) {
	rrPattern := regexp.MustCompile(`^([A-Za-z0-9-.]+)\t(\d+)\tIN\t([A-Z]+)\t(.*)$`)
	if matches := rrPattern.FindStringSubmatch(data); matches != nil {
		// Don't care about error since with the regex it is a number
		ttl, _ := strconv.Atoi(matches[2])
		return RR{
			Name:  matches[1],
			TTL:   ttl,
			Type:  matches[3],
			Value: matches[4],
		}, nil
	}
	return RR{}, fmt.Errorf("No match found in data")
}

func scanResult(input io.Reader, dataCh chan<- string, errCh chan<- error) {
	scanner := bufio.NewScanner(input)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}

		dataCh <- scanner.Text()
	}
	close(dataCh)

	errCh <- scanner.Err()
}

func sendCommand(command string, client *UnboundClient, dataCh chan<- string, errCh chan<- error) {
	var (
		conn net.Conn
		err  error
	)

	if client.tlsConfig == nil {
		conn, err = net.Dial(client.scheme, client.host)
	} else {
		conn, err = tls.Dial(client.scheme, client.host, client.tlsConfig)
	}
	if err != nil {
		errCh <- err
		return
	}
	defer conn.Close()
	_, err = conn.Write([]byte("UBCT1 " + command + "\n"))
	if err != nil {
		errCh <- err
		return
	}
	scanResult(conn, dataCh, errCh)
}
