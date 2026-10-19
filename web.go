package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
)

//go:embed web
var webFS embed.FS

func serveWeb(addr string) error {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(static))

	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		store.Lock()
		list := append([]*Session(nil), store.list...)
		store.Unlock()
		out := make([]map[string]any, len(list))
		for i, s := range list {
			out[i] = s.snapshot(false)
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s := lookup(w, r); s != nil {
			writeJSON(w, s.snapshot(true))
		}
	})

	mux.HandleFunc("GET /api/sessions/{id}/raw", func(w http.ResponseWriter, r *http.Request) {
		s := lookup(w, r)
		if s == nil {
			return
		}
		dir := Dir(r.URL.Query().Get("dir"))
		if dir != In && dir != Out {
			http.Error(w, "dir must be in or out", http.StatusBadRequest)
			return
		}
		var buf bytes.Buffer
		for _, e := range s.snapshot(true)["events"].([]Event) {
			if e.Dir == dir {
				buf.Write(e.Data)
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="session-%d-%s-%d-%s.bin"`, s.ID, s.Proto, s.Port, dir))
		w.Write(buf.Bytes())
	})

	return http.ListenAndServe(addr, mux)
}

func lookup(w http.ResponseWriter, r *http.Request) *Session {
	id, _ := strconv.Atoi(r.PathValue("id"))
	store.Lock()
	defer store.Unlock()
	if id < 1 || id > len(store.list) {
		http.Error(w, "no such session", http.StatusNotFound)
		return nil
	}
	return store.list[id-1]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
