package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const idleTimeout = 5 * time.Minute

func serveRaw(c net.Conn, s *Session) {
	c.SetDeadline(time.Now().Add(idleTimeout))
	io.Copy(io.Discard, c)
}

// servePJL answers the PJL queries tools like PRET use to fingerprint and drive a printer;
// everything else (the print job itself) is just recorded.
func servePJL(c net.Conn, s *Session) {
	br := bufio.NewReader(c)
	for {
		c.SetDeadline(time.Now().Add(idleTimeout))
		line, err := br.ReadBytes('\n')
		for _, cmd := range pjlCommands(line) {
			s.note("PJL: %s", cmd)
			if resp := pjlReply(cmd); resp != "" {
				c.Write([]byte(resp))
			}
		}
		if err != nil {
			return
		}
	}
}

// pjlCommands extracts @PJL commands; a line can carry a UEL (ESC%-12345X) prefix.
func pjlCommands(line []byte) []string {
	var cmds []string
	for _, part := range bytes.Split(line, []byte("\x1b%-12345X")) {
		part = bytes.TrimSpace(part)
		if len(part) >= 4 && strings.EqualFold(string(part[:4]), "@PJL") {
			cmds = append(cmds, string(part))
		}
	}
	return cmds
}

func pjlReply(cmd string) string {
	up := strings.ToUpper(cmd)
	switch {
	case strings.HasPrefix(up, "@PJL ECHO"):
		return cmd + "\r\n\f"
	case strings.HasPrefix(up, "@PJL INFO ID"):
		return fmt.Sprintf("@PJL INFO ID\r\n\"%s\"\r\n\f", *model)
	case strings.HasPrefix(up, "@PJL INFO STATUS"):
		return "@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n\f"
	case strings.HasPrefix(up, "@PJL INFO PRODINFO"):
		return fmt.Sprintf("@PJL INFO PRODINFO\r\nMODEL=\"%s\"\r\n\f", *model)
	case strings.HasPrefix(up, "@PJL INFO FILESYS"):
		return "@PJL INFO FILESYS\r\nVOLUME TOTAL SIZE FREE SIZE LOCATION LABEL STATUS\r\n0:     8388608    7340032    <HT> <HT> READY\r\n\f"
	case strings.HasPrefix(up, "@PJL FSDIRLIST"):
		return cmd + "\r\nFILEERROR=3\r\n\f"
	case strings.HasPrefix(up, "@PJL INFO"):
		return strings.TrimSpace(cmd) + "\r\n\f"
	}
	return ""
}

func serveHTTP(c net.Conn, s *Session) {
	br := bufio.NewReader(c)
	for {
		c.SetDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.note("HTTP parse failed: %v", err)
				// Not HTTP: keep recording whatever else they send.
				io.Copy(io.Discard, br)
			}
			return
		}
		s.note("HTTP %s %s %s Host=%q UA=%q", req.Method, req.RequestURI, req.Proto, req.Host, req.UserAgent())
		io.Copy(io.Discard, req.Body)

		status, body := http.StatusOK, fakePage()
		if req.URL.Path != "/" && req.URL.Path != "/index.html" {
			status, body = http.StatusNotFound, "<html><body><h1>404 Not Found</h1></body></html>"
		}
		resp := &http.Response{
			StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Request: req,
			Header: http.Header{
				"Content-Type": {"text/html; charset=utf-8"},
				"Server":       {"HP HTTP Server; " + *model},
				"Date":         {time.Now().UTC().Format(http.TimeFormat)},
			},
			ContentLength: int64(len(body)),
			Body:          io.NopCloser(strings.NewReader(body)),
			Close:         req.Close,
		}
		if err := resp.Write(c); err != nil || req.Close {
			return
		}
	}
}

func fakePage() string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>%[1]s</title></head><body>
<h1>%[1]s</h1><table><tr><td>Status</td><td>Ready</td></tr><tr><td>Toner</td><td>62%%</td></tr></table>
</body></html>`, *model)
}

var tlsConfig *tls.Config

func serveHTTPS(c net.Conn, s *Session) {
	// Record plaintext, not ciphertext: c is the recConn, so detach recording during the
	// handshake and only dump the raw client bytes if the handshake fails (non-TLS probes).
	raw := c.(*recConn).Conn
	tee := &teeConn{Conn: raw}
	cfg := tlsConfig.Clone()
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		s.note("TLS ClientHello SNI=%q ALPN=%v versions=%x ciphers=%d", h.ServerName, h.SupportedProtos, h.SupportedVersions, len(h.CipherSuites))
		return nil, nil
	}
	tc := tls.Server(tee, cfg)
	tc.SetDeadline(time.Now().Add(idleTimeout))
	if err := tc.Handshake(); err != nil {
		s.note("TLS handshake failed: %v", err)
		if tee.buf.Len() > 0 {
			s.add(In, tee.buf.Bytes())
		}
		// Keep recording anything else sent on the plain socket.
		serveRaw(c, s)
		return
	}
	tee.stop = true
	st := tc.ConnectionState()
	s.note("TLS established version=%s cipher=%s", tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	serveHTTP(&recConn{Conn: tc, s: s}, s)
}

// teeConn keeps a copy of what's read until stop is set.
type teeConn struct {
	net.Conn
	buf  bytes.Buffer
	stop bool
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if !t.stop {
		t.buf.Write(p[:n])
	}
	return n, err
}

// loadOrCreateTLS reuses the cert across restarts so the fingerprint stays stable to scanners.
func loadOrCreateTLS(certFile, keyFile string) (*tls.Config, error) {
	if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
		if err := genCert(certFile, keyFile); err != nil {
			return nil, err
		}
		conLog.Printf("generated self-signed cert %s", certFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}, nil
}

func genCert(certFile, keyFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: *model, Organization: []string{"HP"}},
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
}
