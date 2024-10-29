package unbound

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type RR struct {
	Name  string
	Value string
	TTL   int
	Type  string
}

type UnboundClient struct {
	Client
	scheme    string
	host      string
	tlsConfig *tls.Config
}

type Client interface {
	LocalData() []RR
	AddLocalData(rr RR) error
	RemoveLocalData(rr RR) error
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

func NewUnboundClient(host string, ca string, key string, cert string) (*UnboundClient, error) {
	url, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	clientHost := url.Host
	if url.Scheme == "unix" {
		clientHost = url.Path
	}

	if ca == "" && cert == "" {
		return &UnboundClient{
			scheme: url.Scheme,
			host:   clientHost,
		}, nil
	}

	caData, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("Failed to parse CA")
	}

	certData, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	keyData, err := os.ReadFile(key)
	if err != nil {
		return nil, err
	}
	keyPair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, err
	}

	return &UnboundClient{
		scheme: url.Scheme,
		host:   clientHost,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{keyPair},
			RootCAs:      roots,
			ServerName:   "unbound",
		},
	}, nil
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

func (u *UnboundClient) RemoveLocalData(rr RR) error {
	dataCh := make(chan string)
	errCh := make(chan error)

	var sb strings.Builder

	sb.WriteString("local_data_remove ")
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
