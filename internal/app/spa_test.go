package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRegisterSPAWithoutBuildKeepsAPINotFound(t *testing.T) {
	r := chi.NewRouter()
	registerSPA(r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, ожидался 404", w.Code)
	}
}

func TestSPAFileLookupStaysInsideRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "dist")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := http.Dir(root)
	if !isSPAFile(fs, "/app.js") {
		t.Fatal("файл внутри корня SPA не найден")
	}
	if isSPAFile(fs, "/../secret.txt") {
		t.Fatal("поиск SPA-файла вышел за пределы корня")
	}
}
