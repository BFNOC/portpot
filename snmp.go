package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var startTime = time.Now()

type mibEntry struct {
	oid string
	typ gosnmp.Asn1BER
	val func() any
}

func str(s *string) func() any { return func() any { return *s } }

// Fixed so the fingerprint stays the same across restarts.
var (
	hostName = "NPI3A1F2C"
	serial   = "VNB3K12345"
	empty    = ""
)

// mib is sorted by OID; GetNext walks it in order.
var mib = sortMIB([]mibEntry{
	{".1.3.6.1.2.1.1.1.0", gosnmp.OctetString, func() any { return *model }},                             // sysDescr
	{".1.3.6.1.2.1.1.2.0", gosnmp.ObjectIdentifier, func() any { return ".1.3.6.1.4.1.11.2.3.9.1" }},     // sysObjectID (HP)
	{".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, func() any { return uint32(time.Since(startTime) / 10e6) }}, // sysUpTime
	{".1.3.6.1.2.1.1.4.0", gosnmp.OctetString, str(&empty)},                                              // sysContact
	{".1.3.6.1.2.1.1.5.0", gosnmp.OctetString, str(&hostName)},                                           // sysName
	{".1.3.6.1.2.1.1.6.0", gosnmp.OctetString, str(&empty)},                                              // sysLocation
	{".1.3.6.1.2.1.25.3.2.1.3.1", gosnmp.OctetString, func() any { return *model }},                      // hrDeviceDescr
	{".1.3.6.1.2.1.25.3.5.1.1.1", gosnmp.Integer, func() any { return 3 }},                               // hrPrinterStatus idle
	{".1.3.6.1.2.1.43.5.1.1.17.1", gosnmp.OctetString, str(&serial)},                                     // prtGeneralSerialNumber
})

func sortMIB(m []mibEntry) []mibEntry {
	slices.SortFunc(m, func(a, b mibEntry) int { return compareOID(a.oid, b.oid) })
	return m
}

func compareOID(a, b string) int {
	pa, pb := strings.Split(strings.Trim(a, "."), "."), strings.Split(strings.Trim(b, "."), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x - y
		}
	}
	return len(pa) - len(pb)
}

func normOID(o string) string { return "." + strings.Trim(o, ".") }

func serveSNMP(pkt []byte, s *Session) []byte {
	req, err := (&gosnmp.GoSNMP{}).SnmpDecodePacket(pkt)
	if err != nil {
		s.note("SNMP decode failed: %v", err)
		return nil
	}
	oids := make([]string, len(req.Variables))
	for i, v := range req.Variables {
		oids[i] = v.Name
	}
	s.note("SNMP %s community=%q %s reqid=%d oids=%v", req.Version, req.Community, req.PDUType, req.RequestID, oids)
	if req.PDUType == gosnmp.SetRequest {
		for _, v := range req.Variables {
			s.note("SNMP Set %s = %v (%s)", v.Name, v.Value, v.Type)
		}
	}
	if req.Version == gosnmp.Version3 || req.Community != *community {
		s.note("SNMP no reply: v3 or wrong community, like a real agent")
		return nil
	}

	var vars []gosnmp.SnmpPDU
	switch req.PDUType {
	case gosnmp.GetRequest:
		for _, v := range req.Variables {
			vars = append(vars, snmpGet(v.Name))
		}
	case gosnmp.GetNextRequest:
		for _, v := range req.Variables {
			vars = append(vars, snmpNext(v.Name))
		}
	case gosnmp.GetBulkRequest:
		// ponytail: non-repeaters treated as repeaters; enough for snmpwalk/snmpbulkwalk.
		reps := min(int(req.MaxRepetitions), len(mib)+1)
		for _, v := range req.Variables {
			name := v.Name
			for range reps {
				pdu := snmpNext(name)
				vars = append(vars, pdu)
				if pdu.Type == gosnmp.EndOfMibView {
					break
				}
				name = pdu.Name
			}
		}
	default:
		return nil
	}
	if req.Version == gosnmp.Version1 {
		// v1 has no exception values: answer noSuchName instead.
		for i, v := range vars {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.EndOfMibView {
				return snmpMarshal(s, req, req.Variables, gosnmp.NoSuchName, uint8(i+1))
			}
		}
	}
	return snmpMarshal(s, req, vars, gosnmp.NoError, 0)
}

func snmpGet(oid string) gosnmp.SnmpPDU {
	oid = normOID(oid)
	for _, e := range mib {
		if e.oid == oid {
			return gosnmp.SnmpPDU{Name: oid, Type: e.typ, Value: e.val()}
		}
	}
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.NoSuchObject}
}

func snmpNext(oid string) gosnmp.SnmpPDU {
	oid = normOID(oid)
	for _, e := range mib {
		if compareOID(e.oid, oid) > 0 {
			return gosnmp.SnmpPDU{Name: e.oid, Type: e.typ, Value: e.val()}
		}
	}
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView}
}

func snmpMarshal(s *Session, req *gosnmp.SnmpPacket, vars []gosnmp.SnmpPDU, status gosnmp.SNMPError, index uint8) []byte {
	resp := &gosnmp.SnmpPacket{
		Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse,
		RequestID: req.RequestID, Error: status, ErrorIndex: index, Variables: vars,
	}
	out, err := resp.MarshalMsg()
	if err != nil {
		s.note("SNMP marshal failed: %v", err)
		return nil
	}
	parts := make([]string, len(vars))
	for i, v := range vars {
		parts[i] = fmt.Sprintf("%s=%v", v.Name, v.Value)
	}
	s.note("SNMP reply status=%d %v", status, parts)
	return out
}
