package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Dir string

const (
	In   Dir = "in"
	Out  Dir = "out"
	Note Dir = "note"
)

type Event struct {
	Time time.Time `json:"time"`
	Dir  Dir       `json:"dir"`
	Data []byte    `json:"data,omitempty"` // base64 in JSON
	Text string    `json:"text,omitempty"` // notes: parsed protocol info, errors
}

type Session struct {
	ID       int
	Net      string
	Port     int
	Proto    string
	Remote   string
	Start    time.Time
	End      time.Time
	BytesIn  int
	BytesOut int

	mu     sync.Mutex
	events []Event
}

// ponytail: everything stays in memory for the web viewer; cap or spill to disk if runs last days.
var store struct {
	sync.Mutex
	list []*Session
}

func newSession(netw string, port int, proto, remote string) *Session {
	s := &Session{Net: netw, Port: port, Proto: proto, Remote: remote, Start: time.Now()}
	store.Lock()
	s.ID = len(store.list) + 1
	store.list = append(store.list, s)
	store.Unlock()
	s.logf("OPEN")
	return s
}

func (s *Session) tag() string {
	return fmt.Sprintf("#%d %s/%d(%s) %s", s.ID, s.Net, s.Port, s.Proto, s.Remote)
}

func (s *Session) logf(format string, a ...any) {
	line := s.tag() + " " + fmt.Sprintf(format, a...)
	conLog.Print(line)
	fileLog.Print(line)
}

func (s *Session) add(d Dir, data []byte) {
	data = append([]byte(nil), data...)
	s.mu.Lock()
	s.events = append(s.events, Event{Time: time.Now(), Dir: d, Data: data})
	if d == In {
		s.BytesIn += len(data)
	} else {
		s.BytesOut += len(data)
	}
	s.mu.Unlock()
	line := fmt.Sprintf("%s %s %dB", s.tag(), strings.ToUpper(string(d)), len(data))
	conLog.Print(line)
	fileLog.Print(line + "\n" + hex.Dump(data))
}

func (s *Session) note(format string, a ...any) {
	text := fmt.Sprintf(format, a...)
	s.mu.Lock()
	s.events = append(s.events, Event{Time: time.Now(), Dir: Note, Text: text})
	s.mu.Unlock()
	s.logf("NOTE %s", text)
}

func (s *Session) close() {
	s.mu.Lock()
	s.End = time.Now()
	in, out := s.BytesIn, s.BytesOut
	s.mu.Unlock()
	s.logf("CLOSE in=%dB out=%dB", in, out)
}

// snapshot returns a copy safe to marshal while handlers keep writing.
func (s *Session) snapshot(withEvents bool) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]any{
		"id": s.ID, "net": s.Net, "port": s.Port, "proto": s.Proto, "remote": s.Remote,
		"start": s.Start, "bytesIn": s.BytesIn, "bytesOut": s.BytesOut,
	}
	if !s.End.IsZero() {
		m["end"] = s.End
	}
	if withEvents {
		m["events"] = append([]Event(nil), s.events...)
	}
	return m
}
