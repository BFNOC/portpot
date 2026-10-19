// portpot: listen on arbitrary TCP/UDP ports on 0.0.0.0 and ::, fake a printer's
// services, and log every byte both ways.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// handlers maps a protocol name to its TCP handler. UDP protocols live in udpHandlers.
var handlers = map[string]func(net.Conn, *Session){
	"raw":   serveRaw,
	"pjl":   servePJL,
	"http":  serveHTTP,
	"https": serveHTTPS,
}

var udpHandlers = map[string]func(pkt []byte, s *Session) []byte{
	"udp":  func([]byte, *Session) []byte { return nil },
	"snmp": serveSNMP,
}

var (
	model     = flag.String("model", "HP LaserJet Pro M404dn", "device model shown in PJL/HTTP/SNMP/TLS responses")
	community = flag.String("community", "public", "SNMP community that gets answers; others are only logged")
	logPath   = flag.String("log", "portpot.log", "full log file (hexdump of every byte)")
	webAddr   = flag.String("web", "127.0.0.1:8088", "web viewer address, empty to disable")
	certPath  = flag.String("cert", "portpot.crt", "TLS cert, generated self-signed if missing")
	keyPath   = flag.String("key", "portpot.key", "TLS key, generated if missing")

	fileLog *log.Logger
	conLog  = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
)

type listenFlag []string

func (l *listenFlag) String() string { return strings.Join(*l, ",") }
func (l *listenFlag) Set(v string) error {
	*l = append(*l, strings.Split(v, ",")...)
	return nil
}

func main() {
	var listens listenFlag
	flag.Var(&listens, "l", "port/proto, repeatable or comma separated. proto: raw pjl http https (TCP), udp snmp (UDP). default proto raw")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: portpot [flags]\n  e.g. portpot -l 9100/pjl,443/https,161/snmp -l 8080/raw\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(listens) == 0 {
		listens = listenFlag{"80/http", "443/https", "9100/pjl", "161/snmp"}
	}

	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	fileLog = log.New(f, "", log.LstdFlags|log.Lmicroseconds)

	bound := 0
	for _, spec := range listens {
		port, proto, err := parseSpec(spec)
		if err != nil {
			log.Fatal(err)
		}
		if proto == "https" && tlsConfig == nil {
			if tlsConfig, err = loadOrCreateTLS(*certPath, *keyPath); err != nil {
				log.Fatalf("tls cert: %v", err)
			}
		}
		// Separate v4 and v6 sockets: Go sets IPV6_V6ONLY on "tcp6"/"udp6", so both bind the same port.
		for _, fam := range []struct{ suffix, host string }{{"4", "0.0.0.0"}, {"6", "::"}} {
			addr := net.JoinHostPort(fam.host, strconv.Itoa(port))
			if err := listen(proto, fam.suffix, addr); err != nil {
				conLog.Printf("FAIL listen %s %s: %v%s", proto, addr, err, bindHint(err))
				continue
			}
			bound++
			conLog.Printf("listening %s %s", proto, addr)
		}
	}
	if bound == 0 {
		log.Fatal("nothing bound, exiting")
	}

	if *webAddr != "" {
		go func() { log.Fatalf("web: %v", serveWeb(*webAddr)) }()
		conLog.Printf("web viewer http://%s/", *webAddr)
	}
	select {}
}

func parseSpec(spec string) (int, string, error) {
	p, proto, _ := strings.Cut(strings.TrimSpace(spec), "/")
	if proto == "" {
		proto = "raw"
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("bad port in %q", spec)
	}
	if handlers[proto] == nil && udpHandlers[proto] == nil {
		return 0, "", fmt.Errorf("unknown proto %q in %q", proto, spec)
	}
	return port, proto, nil
}

func listen(proto, fam, addr string) error {
	if h := udpHandlers[proto]; h != nil {
		pc, err := net.ListenPacket("udp"+fam, addr)
		if err != nil {
			return err
		}
		go servePackets(pc, proto, h)
		return nil
	}
	ln, err := net.Listen("tcp"+fam, addr)
	if err != nil {
		return err
	}
	go acceptLoop(ln, proto, handlers[proto])
	return nil
}

func acceptLoop(ln net.Listener, proto string, h func(net.Conn, *Session)) {
	port := ln.Addr().(*net.TCPAddr).Port
	for {
		c, err := ln.Accept()
		if err != nil {
			conLog.Printf("accept %s/%d: %v", proto, port, err)
			time.Sleep(100 * time.Millisecond) // don't spin on EMFILE
			continue
		}
		go func() {
			s := newSession("tcp", port, proto, c.RemoteAddr().String())
			defer c.Close()
			defer func() {
				if r := recover(); r != nil {
					s.note("handler panic: %v\n%s", r, debug.Stack())
				}
			}()
			h(&recConn{Conn: c, s: s}, s)
			s.close()
		}()
	}
}

// ponytail: one session per UDP packet; group by remote addr with an idle timeout if walks get noisy.
func servePackets(pc net.PacketConn, proto string, h func([]byte, *Session) []byte) {
	port := pc.LocalAddr().(*net.UDPAddr).Port
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			conLog.Printf("read %s/%d: %v", proto, port, err)
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		s := newSession("udp", port, proto, from.String())
		s.add(In, pkt)
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.note("handler panic: %v\n%s", r, debug.Stack())
				}
			}()
			if out := h(pkt, s); out != nil {
				if _, err := pc.WriteTo(out, from); err != nil {
					s.note("reply failed: %v", err)
					return
				}
				s.add(Out, out)
			}
		}()
		s.close()
	}
}

// recConn records everything read/written through it into the session.
type recConn struct {
	net.Conn
	s *Session
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.add(In, p[:n])
	}
	if err != nil && !errors.Is(err, io.EOF) {
		c.s.note("read error: %v", err)
	}
	return n, err
}

func (c *recConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.s.add(Out, p[:n])
	}
	if err != nil {
		c.s.note("write error after %d/%d bytes: %v", n, len(p), err)
	}
	return n, err
}

func bindHint(err error) string {
	// Windows errnos don't match the syscall constants, so also match its messages.
	msg := err.Error()
	switch {
	case errors.Is(err, syscall.EACCES), strings.Contains(msg, "forbidden by its access permissions"):
		return " (low port needs root/admin: sudo, or setcap cap_net_bind_service=+ep on Linux; on Windows also check `netsh int ipv4 show excludedportrange tcp`)"
	case errors.Is(err, syscall.EADDRINUSE), strings.Contains(msg, "Only one usage of each socket address"):
		return " (port taken by another process: on Windows check IIS/http.sys for 80/443, SNMP service for 161)"
	case strings.Contains(err.Error(), "address family"), strings.Contains(err.Error(), "cannot assign"):
		return " (IPv6 disabled on this host?)"
	}
	return ""
}
