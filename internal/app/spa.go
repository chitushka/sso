package app

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

const spaDist = "web/admin/dist"

// registerSPA раздаёт собранный административный интерфейс. Не занятые API
// маршруты возвращают index.html для обработки во Vue Router. Если каталог
// сборки отсутствует, сервер продолжает работать только с API.
func registerSPA(r chi.Router, logger *slog.Logger) {
	root := http.Dir(spaDist)
	if !isSPAFile(root, "/index.html") {
		logger.Info("admin ui not found, serving API only", "dir", spaDist)
		return
	}
	fs := http.FileServer(root)
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.NotFound(w, req)
			return
		}
		if isSPAFile(root, req.URL.Path) {
			fs.ServeHTTP(w, req)
			return
		}
		index, err := root.Open("/index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		defer func() { _ = index.Close() }()
		info, err := index.Stat()
		if err != nil {
			http.NotFound(w, req)
			return
		}
		http.ServeContent(w, req, "index.html", info.ModTime(), index)
	})
	logger.Info("admin ui enabled", "dir", spaDist)
}

func isSPAFile(root http.Dir, requestPath string) bool {
	file, err := root.Open(requestPath)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	return err == nil && !info.IsDir()
}
