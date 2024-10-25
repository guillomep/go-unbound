package unbound

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func scanResult(input io.Reader, ch chan<- string) error {
	scanner := bufio.NewScanner(input)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}

		ch <- scanner.Text()
	}
	close(ch)

	return scanner.Err()
}

func sendCommand(command string, client *UnboundClient, ch chan<- string) error {
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
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("UBCT1 " + command + "\n"))
	if err != nil {
		return err
	}
	return scanResult(conn, ch)
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

func (u *UnboundClient) LocalData() []RR {
	ch := make(chan string)

	rrPattern := regexp.MustCompile(`^([A-Za-z0-9-.]+)\t(\d+)\tIN\t([A-Z]+)\t(.*)$`)

	var rrs []RR
	go sendCommand("list_local_data", u, ch)
	for line := range ch {
		if matches := rrPattern.FindStringSubmatch(line); matches != nil {
			// Don't care about error since with the regex it is a number
			ttl, _ := strconv.Atoi(matches[2])
			rrs = append(rrs, RR{
				Name:  matches[1],
				TTL:   ttl,
				Type:  matches[3],
				Value: matches[4],
			})
		}
	}

	return rrs
}

func (u *UnboundClient) AddLocalData(rr RR) error {
	ch := make(chan string)

	var sb strings.Builder

	sb.WriteString("local_data ")
	sb.WriteString(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", rr.Name, rr.TTL, rr.Type, rr.Value))

	go sendCommand(sb.String(), u, ch)

	for line := range ch {
		if strings.ToLower(line) != "ok" {
			return errors.New(fmt.Sprintf("Failed to add local data: %s", line))
		}
	}

	return nil
}

func (u *UnboundClient) RemoveLocalData(rr RR) error {
	ch := make(chan string)

	var sb strings.Builder

	sb.WriteString("local_data_remove ")
	sb.WriteString(fmt.Sprintf("%s\t%d\tIN\t%s\t%s", rr.Name, rr.TTL, rr.Type, rr.Value))

	go sendCommand(sb.String(), u, ch)

	for line := range ch {
		if strings.ToLower(line) != "ok" {
			return errors.New(fmt.Sprintf("Failed to remove local data: %s", line))
		}
	}

	return nil
}
