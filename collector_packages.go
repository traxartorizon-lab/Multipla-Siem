package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"net/http"
	"path"
)

func (a *App) registerCollectorPackageRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices/collector-package", a.auth(func(w http.ResponseWriter, r *http.Request) {
		entries, err := assets.ReadDir("release/collectors")
		if err != nil {
			http.Error(w, "Pacote assinado indisponível", 503)
			return
		}
		var buffer bytes.Buffer
		zipper := zip.NewWriter(&buffer)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			raw, err := assets.ReadFile(path.Join("release/collectors", entry.Name()))
			if err != nil {
				http.Error(w, "Falha ao ler pacote", 503)
				return
			}
			file, err := zipper.Create(entry.Name())
			if err != nil {
				http.Error(w, "Falha ao criar pacote", 503)
				return
			}
			if _, err = file.Write(raw); err != nil {
				http.Error(w, "Falha ao criar pacote", 503)
				return
			}
		}
		if zipper.Close() != nil {
			http.Error(w, "Falha ao criar pacote", 503)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="Multipla-SIEM-Coletores-Assinados.zip"`)
		w.Write(buffer.Bytes())
	}))
}
