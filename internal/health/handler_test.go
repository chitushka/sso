package health

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestLiveAndVersionDoNotDependOnDatabase(t *testing.T) {
	r := chi.NewRouter()
	RegisterRoutes(r, nil, "test-version")
	for _, test := range []struct {
		path string
		want string
	}{{"/health/live", `"status":"ok"`}, {"/health/version", `"version":"test-version"`}} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, test.path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), test.want) {
			t.Fatalf("%s: status=%d body=%q", test.path, w.Code, w.Body.String())
		}
	}
}
