package main

import (
	"io"
	"log"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func init() { fileLog, conLog = log.New(io.Discard, "", 0), log.New(io.Discard, "", 0) }

func snmpRoundTrip(t *testing.T, ver gosnmp.SnmpVersion, comm string, typ gosnmp.PDUType, oids ...string) *gosnmp.SnmpPacket {
	t.Helper()
	vars := make([]gosnmp.SnmpPDU, len(oids))
	for i, o := range oids {
		vars[i] = gosnmp.SnmpPDU{Name: o, Type: gosnmp.Null}
	}
	req := &gosnmp.SnmpPacket{Version: ver, Community: comm, PDUType: typ, RequestID: 42, MaxRepetitions: 20, Variables: vars}
	pkt, err := req.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	out := serveSNMP(pkt, newSession("udp", 161, "snmp", "test"))
	if out == nil {
		return nil
	}
	resp, err := (&gosnmp.GoSNMP{}).SnmpDecodePacket(out)
	if err != nil {
		t.Fatalf("reply not decodable: %v", err)
	}
	if resp.RequestID != 42 || resp.PDUType != gosnmp.GetResponse {
		t.Fatalf("bad reply header: %+v", resp)
	}
	return resp
}

func TestSNMP(t *testing.T) {
	r := snmpRoundTrip(t, gosnmp.Version2c, "public", gosnmp.GetRequest, ".1.3.6.1.2.1.1.1.0")
	if got := string(r.Variables[0].Value.([]byte)); got != *model {
		t.Fatalf("sysDescr = %q", got)
	}

	if snmpRoundTrip(t, gosnmp.Version2c, "private", gosnmp.GetRequest, ".1.3.6.1.2.1.1.1.0") != nil {
		t.Fatal("wrong community must not get a reply")
	}

	// Walk the whole MIB with GetNext, as snmpwalk -v1 would.
	oid, n := ".1.3", 0
	for {
		r := snmpRoundTrip(t, gosnmp.Version2c, "public", gosnmp.GetNextRequest, oid)
		v := r.Variables[0]
		if v.Type == gosnmp.EndOfMibView {
			break
		}
		if compareOID(v.Name, oid) <= 0 {
			t.Fatalf("walk went backwards: %s after %s", v.Name, oid)
		}
		oid, n = v.Name, n+1
	}
	if n != len(mib) {
		t.Fatalf("walk returned %d of %d entries", n, len(mib))
	}

	r = snmpRoundTrip(t, gosnmp.Version2c, "public", gosnmp.GetBulkRequest, ".1.3.6.1.2.1.1")
	if len(r.Variables) != len(mib)+1 || r.Variables[len(mib)].Type != gosnmp.EndOfMibView {
		t.Fatalf("bulk returned %d vars", len(r.Variables))
	}

	r = snmpRoundTrip(t, gosnmp.Version1, "public", gosnmp.GetRequest, ".1.3.6.1.9.9")
	if r.Error != gosnmp.NoSuchName {
		t.Fatalf("v1 missing oid error = %v", r.Error)
	}
}

func TestPJL(t *testing.T) {
	cmds := pjlCommands([]byte("\x1b%-12345X@PJL INFO ID\r\n"))
	if len(cmds) != 1 || cmds[0] != "@PJL INFO ID" {
		t.Fatalf("cmds = %q", cmds)
	}
	if r := pjlReply("@PJL ECHO DELIMITER123"); r != "@PJL ECHO DELIMITER123\r\n\f" {
		t.Fatalf("echo = %q", r)
	}
	if r := pjlReply("@PJL JOB"); r != "" {
		t.Fatalf("job should not reply, got %q", r)
	}
}

func TestParseSpec(t *testing.T) {
	for spec, ok := range map[string]bool{"9100": true, "443/https": true, "161/snmp": true, "0/raw": false, "70000": false, "80/ftp": false} {
		if _, _, err := parseSpec(spec); (err == nil) != ok {
			t.Errorf("parseSpec(%q) err = %v", spec, err)
		}
	}
}
