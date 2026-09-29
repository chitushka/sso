package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"name\":\"first\"} {\"name\":\"second\"}"))
	var body struct {
		Name string `json:"name"`
	}
	if err := Decode(req, &body); err == nil {
		t.Fatal("expected trailing JSON document to be rejected")
	}
}

func TestDecodeAcceptsOneJSONDocument(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("{\"name\":\"value\"}\n"))
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
