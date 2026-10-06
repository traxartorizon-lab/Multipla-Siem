package main

import (
	"encoding/base64"
	"net/http"
)

func registerAlertSoundAssets(mux *http.ServeMux) {
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		encoded, err := assets.ReadFile("web/favicon.ico.b64")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			http.Error(w, "ícone indisponível", 500)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(raw)
	})

	for _, name := range []string{"beep", "siren"} {
		name := name
		mux.HandleFunc("GET /audio/alert-"+name+".ogg", func(w http.ResponseWriter, r *http.Request) {
			encoded, err := assets.ReadFile("web/alert-" + name + ".ogg.b64")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(string(encoded))
			if err != nil {
				http.Error(w, "áudio indisponível", 500)
				return
			}
			w.Header().Set("Content-Type", "audio/ogg")
			w.Header().Set("Cache-Control", "private, max-age=86400")
			w.Write(raw)
		})
	}
}
