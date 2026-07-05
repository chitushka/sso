package app

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

const spaDist = "web/admin/dist"

// registerSPA serves the built admin UI. Any path not claimed by the API
// falls back to index.html so Vue Router handles it client-side. If the dist
// directory is absent (API-only build), the server runs without a UI.
func registerSPA(r chi.Router, logger *slog.Logger) {
	if _, err := os.Stat(filepath.Join(spaDist, "index.html")); err != nil {
		logger.Info("admin ui not found, serving API only", "dir", spaDist)
		return
	}
	fs := http.FileServer(http.Dir(spaDist))
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.NotFound(w, req)
			return
		}
		p := filepath.Join(spaDist, filepath.Clean("/"+req.URL.Path))
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, req)
			return
		}
		http.ServeFile(w, req, filepath.Join(spaDist, "index.html"))
	})
	logger.Info("admin ui enabled", "dir", spaDist)
}
