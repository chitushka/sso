package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoStoreSetsRequiredHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	NoStore(w)

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	w.WriteHeader(http.StatusOK)
}

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"name\":\"first\"} {\"name\":\"second\"}"))
	req.Header.Set("Content-Type", "application/json")
	var body struct {
		Name string `json:"name"`
	}
	if err := Decode(req, &body); err == nil {
		t.Fatal("expected trailing JSON document to be rejected")
	}
}

func TestDecodeAcceptsOneJSONDocument(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"name\":\"value\"}\n"))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	var body struct {
		Name string `json:"name"`
	}
	if err := Decode(req, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Name != "value" {
		t.Fatalf("unexpected value %q", body.Name)
	}
}

func TestDecodeRejectsNonJSONContentType(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"value"}`))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := Decode(req, &body); err == nil {
			t.Fatalf("Content-Type %q принят как JSON", contentType)
		}
	}
}
