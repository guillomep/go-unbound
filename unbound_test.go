package unbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func echoServer(c net.Conn) {
	buf := make([]byte, 512)
	nr, err := c.Read(buf)
	if err != nil {
		return
	}

	data := buf[0:nr]
	_, err = c.Write(data)
	if err != nil {
		panic(err)
	}
	c.Close()
}

func TestScanResult(t *testing.T) {
	input := `test.lan.	300	IN	AAAA	2a01:cb1c:e08:4920:3205:5ff:fe0e:6f96

test.lan.	300	IN	A	192.168.2.134

localhost.	10800	IN	SOA	localhost. nobody.invalid. 1 3600 1200 604800 10800

localhost.	10800	IN	NS	localhost.`

	reader := strings.NewReader(input)
	dataCh := make(chan string)
	errCh := make(chan error)
	countLine := 0
	wantLine := 4
	go scanResult(reader, dataCh, errCh)
	for l := range dataCh {
		t.Logf("%s", l)
		countLine++
	}

	assert.Equal(t, wantLine, countLine)
}

func TestSendCommand(t *testing.T) {
	tests := []struct {
		typ      string
		listenOn string
		clean    func()
	}{
		{
			typ:      "tcp",
			listenOn: "127.0.0.1:32320",
			clean:    func() {},
		},
		{
			typ:      "unix",
			listenOn: "/tmp/go.sock",
			clean:    func() { os.Remove("/tmp/go.sock") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.typ+"://"+tt.listenOn, func(t *testing.T) {
			defer tt.clean()
			ln, err := net.Listen(tt.typ, tt.listenOn)
			if err != nil {
				panic(err)
			}
			go func(ln net.Listener) {
				fd, err := ln.Accept()
				if err != nil {
					panic(err)
				}

				echoServer(fd)
				ln.Close()
			}(ln)

			dataCh := make(chan string, 1)
			errCh := make(chan error)
			client, err := NewUnboundClient(tt.typ+"://"+tt.listenOn, "", "", "")
			assert.Nil(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			go sendCommand("test_command", client, dataCh, errCh)
			go func() {
				defer cancel()
				for {
					select {
					case result := <-dataCh:
						assert.Equal(t, "UBCT1 test_command", result)
						return
					case err := <-errCh:
						assert.Nil(t, err)
						return
					}
				}
			}()
			<-ctx.Done()
		})
	}
}

func TestSendCommandTLSWithFiles(t *testing.T) {
	caData, _ := os.ReadFile("./testdata/ca.pem")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		t.Fatal("Cannot parse CA")
	}
	certDataServer, _ := os.ReadFile("./testdata/server.pem")
	keyDataServer, _ := os.ReadFile("./testdata/server.key")
	keyPairServer, _ := tls.X509KeyPair(certDataServer, keyDataServer)

	tests := []struct {
		typ      string
		listenOn string
		clean    func()
	}{
		{
			typ:      "tcp",
			listenOn: "127.0.0.1:32321",
			clean:    func() {},
		},
		{
			typ:      "unix",
			listenOn: "/tmp/gotls.sock",
			clean:    func() { os.Remove("/tmp/gotls.sock") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.typ+"://"+tt.listenOn, func(t *testing.T) {
			defer tt.clean()
			ln, err := tls.Listen(tt.typ, tt.listenOn, &tls.Config{
				Certificates: []tls.Certificate{keyPairServer},
				ClientCAs:    roots,
				ServerName:   "unbound",
				ClientAuth:   tls.RequireAndVerifyClientCert,
			},
			)
			if err != nil {
				panic(err)
			}
			go func(ln net.Listener) {
				fd, err := ln.Accept()
				if err != nil {
					panic(err)
				}

				echoServer(fd)
				ln.Close()
			}(ln)

			dataCh := make(chan string, 1)
			errCh := make(chan error)
			client, err := NewUnboundClient(tt.typ+"://"+tt.listenOn, "./testdata/ca.pem", "./testdata/client.key", "./testdata/client.pem")
			assert.Nil(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			go sendCommand("test_command", client, dataCh, errCh)
			go func() {
				defer cancel()
				for {
					select {
					case result := <-dataCh:
						assert.Equal(t, "UBCT1 test_command", result)
						return
					case err := <-errCh:
						assert.Nil(t, err)
						return
					}
				}
			}()
			<-ctx.Done()
		})
	}
}

func TestSendCommandTLSInMemory(t *testing.T) {
	caCerts, err := parseCertificateFile("./testdata/ca.pem")
	require.NoError(t, err)
	roots := x509.NewCertPool()
	for _, cert := range caCerts {
		roots.AddCert(cert)
	}

	serverCert, err := tls.LoadX509KeyPair("./testdata/server.pem", "./testdata/server.key")
	require.NoError(t, err)

	controlCerts, err := parseCertificateFile("./testdata/client.pem")
	require.NoError(t, err)
	controlKey, err := parsePrivateKeyFile("./testdata/client.key")
	require.NoError(t, err)

	tests := []struct {
		typ      string
		listenOn string
		clean    func()
	}{
		{
			typ:      "tcp",
			listenOn: "127.0.0.1:32321",
			clean:    func() {},
		},
		{
			typ:      "unix",
			listenOn: "/tmp/gotls.sock",
			clean:    func() { os.Remove("/tmp/gotls.sock") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.typ+"://"+tt.listenOn, func(t *testing.T) {
			defer tt.clean()
			ln, err := tls.Listen(tt.typ, tt.listenOn, &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientCAs:    roots,
				ServerName:   "unbound",
				ClientAuth:   tls.RequireAndVerifyClientCert,
			},
			)
			if err != nil {
				panic(err)
			}
			go func(ln net.Listener) {
				fd, err := ln.Accept()
				if err != nil {
					panic(err)
				}

				echoServer(fd)
				ln.Close()
			}(ln)

			dataCh := make(chan string, 1)
			errCh := make(chan error)
			client, err := NewClient(tt.typ+"://"+tt.listenOn,
				WithServerCertificates(caCerts),
				WithControlCertificates(controlCerts),
				WithControlPrivateKey(controlKey),
			)
			assert.Nil(t, err)

			ctx, cancel := context.WithCancel(t.Context())
			go sendCommand("test_command", client, dataCh, errCh)
			go func() {
				defer cancel()
				for {
					select {
					case result := <-dataCh:
						assert.Equal(t, "UBCT1 test_command", result)
						return
					case err := <-errCh:
						assert.Nil(t, err)
						return
					}
				}
			}()
			<-ctx.Done()
		})
	}
}

func TestSendCommandBadTLS(t *testing.T) {
	caData, _ := os.ReadFile("./testdata/ca.pem")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		t.Fatal("Cannot parse CA")
	}
	certDataServer, _ := os.ReadFile("./testdata/bad_server.pem")
	keyDataServer, _ := os.ReadFile("./testdata/server.key")
	keyPairServer, _ := tls.X509KeyPair(certDataServer, keyDataServer)

	ln, err := tls.Listen("tcp", "127.0.0.1:32322", &tls.Config{
		Certificates: []tls.Certificate{keyPairServer},
		ClientCAs:    roots,
		ServerName:   "test",
		ClientAuth:   tls.RequireAndVerifyClientCert,
	},
	)
	assert.Nil(t, err)
	go func(ln net.Listener) {
		fd, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		echoServer(fd)
		ln.Close()
	}(ln)

	dataCh := make(chan string, 1)
	errCh := make(chan error)
	client, err := NewUnboundClient("tcp://127.0.0.1:32322", "./testdata/ca.pem", "./testdata/client.key", "./testdata/client.pem")
	assert.Nil(t, err)
	go sendCommand("test_command", client, dataCh, errCh)
	err = <-errCh
	assert.Error(t, err)
}

func TestBadClient(t *testing.T) {
	tests := []struct {
		name string
		host string
		ca   string
		key  string
		cert string
	}{
		{
			name: "bad host",
			host: "ur%65://test",
			ca:   "./testdata/ca.pem",
			key:  "./testdata/client.key",
			cert: "./testdata/client.pem",
		},
		{
			name: "ca not exist",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/notexist.pem",
			key:  "./testdata/client.key",
			cert: "./testdata/client.pem",
		},
		{
			name: "key not exist",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/ca.pem",
			key:  "./testdata/notexist.key",
			cert: "./testdata/client.pem",
		},
		{
			name: "cert not exist",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/ca.pem",
			key:  "./testdata/client.key",
			cert: "./testdata/notexist.pem",
		},
		{
			name: "ca not valid",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/noapem.pem",
			key:  "./testdata/client.key",
			cert: "./testdata/client.pem",
		},
		{
			name: "key not valid",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/ca.pem",
			key:  "./testdata/notapem.key",
			cert: "./testdata/client.pem",
		},
		{
			name: "cert not valid",
			host: "unix:///tmp/gobad.sock",
			ca:   "./testdata/ca.pem",
			key:  "./testdata/client.key",
			cert: "./testdata/notapem.pem",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewUnboundClient(tt.host, tt.ca, tt.key, tt.cert)

			assert.Nil(t, client)
			assert.Error(t, err)
		})
	}
}

func TestLocalData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected []RR
	}{
		{
			name: "good data",
			data: "test.lan.	300	IN	A	192.168.2.134\nlocalhost.	10800	IN	NS	localhost.",
			expected: []RR{
				{Name: "test.lan.", TTL: 300, Type: "A", Value: "192.168.2.134"},
				{Name: "localhost.", TTL: 10800, Type: "NS", Value: "localhost."},
			},
		},
		{
			name: "with bad data",
			data: "test.lan.	300	IN	A	192.168.2.134\nblabla",
			expected: []RR{
				{Name: "test.lan.", TTL: 300, Type: "A", Value: "192.168.2.134"},
			},
		},
		{
			name: "with ttl not number",
			data: "test.lan.	300	IN	A	192.168.2.134\nlocalhost.	notint	IN	NS	localhost.",
			expected: []RR{
				{Name: "test.lan.", TTL: 300, Type: "A", Value: "192.168.2.134"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("unix", "/tmp/local.sock")
			assert.Nil(t, err)
			go func(ln net.Listener) {
				fd, err := ln.Accept()
				if err != nil {
					panic(err)
				}

				buf := make([]byte, 512)
				_, err = fd.Read(buf)
				if err != nil {
					return
				}
				_, err = fd.Write([]byte(tt.data))
				if err != nil {
					panic(err)
				}
				fd.Close()
				ln.Close()
			}(ln)

			client, _ := NewUnboundClient("unix:///tmp/local.sock", "", "", "")
			result := client.LocalData()

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAddLocalData(t *testing.T) {
	ln, err := net.Listen("unix", "/tmp/addlocal.sock")
	assert.Nil(t, err)
	go func(ln net.Listener) {
		fd, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 512)
		nr, err := fd.Read(buf)
		if err != nil {
			return
		}

		if string(buf[0:nr]) == "UBCT1 local_data test.lan\t300\tIN\tA\t127.0.0.1\n" {
			_, err = fd.Write([]byte("ok"))
		} else {
			_, err = fd.Write(buf)
		}
		if err != nil {
			panic(err)
		}
		fd.Close()
		ln.Close()
	}(ln)

	client, _ := NewUnboundClient("unix:///tmp/addlocal.sock", "", "", "")
	result := client.AddLocalData(RR{Name: "test.lan", TTL: 300, Type: "A", Value: "127.0.0.1"})

	assert.Nil(t, result)
}

func TestBadAddLocalData(t *testing.T) {
	ln, err := net.Listen("unix", "/tmp/badlocal.sock")
	assert.Nil(t, err)
	go func(ln net.Listener) {
		fd, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 512)
		_, err = fd.Read(buf)
		if err != nil {
			return
		}

		_, err = fd.Write([]byte("an expected error occured"))
		if err != nil {
			panic(err)
		}
		fd.Close()
		ln.Close()
	}(ln)

	client, _ := NewUnboundClient("unix:///tmp/badlocal.sock", "", "", "")
	result := client.AddLocalData(RR{Name: "test.lan", TTL: 300, Type: "A", Value: "127.0.0.1"})

	assert.NotNil(t, result)
	assert.Error(t, result)
}

func TestRemoveLocalData(t *testing.T) {
	ln, err := net.Listen("unix", "/tmp/removelocal.sock")
	assert.Nil(t, err)
	go func(ln net.Listener) {
		fd, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 512)
		nr, err := fd.Read(buf)
		if err != nil {
			return
		}

		if string(buf[0:nr]) == "UBCT1 local_data_remove test.lan\n" {
			_, err = fd.Write([]byte("ok"))
		} else {
			_, err = fd.Write(buf)
		}
		if err != nil {
			panic(err)
		}
		fd.Close()
		ln.Close()
	}(ln)

	client, _ := NewUnboundClient("unix:///tmp/removelocal.sock", "", "", "")
	result := client.RemoveLocalData(RR{Name: "test.lan", TTL: 300, Type: "A", Value: "127.0.0.1"})

	assert.Nil(t, result)
}

func TestBadRemoveLocalData(t *testing.T) {
	ln, err := net.Listen("unix", "/tmp/badremove.sock")
	assert.Nil(t, err)
	go func(ln net.Listener) {
		fd, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		buf := make([]byte, 512)
		_, err = fd.Read(buf)
		if err != nil {
			return
		}

		_, err = fd.Write([]byte("an expected error occured"))
		if err != nil {
			panic(err)
		}
		fd.Close()
		ln.Close()
	}(ln)

	client, _ := NewUnboundClient("unix:///tmp/badremove.sock", "", "", "")
	result := client.RemoveLocalData(RR{Name: "test.lan", TTL: 300, Type: "A", Value: "127.0.0.1"})

	assert.NotNil(t, result)
	assert.Error(t, result)
}
