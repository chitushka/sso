package ldap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chitushka/sso/internal/audit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type handlerRepository struct {
	provider Provider
	updated  Provider
}

func (r *handlerRepository) Create(_ context.Context, p Provider) (Provider, error) {
	p.ID = r.provider.ID
	r.provider = p
	return p, nil
}

func (r *handlerRepository) List(context.Context) ([]Provider, error) {
	return []Provider{r.provider}, nil
}

func (r *handlerRepository) FindByID(context.Context, uuid.UUID) (Provider, error) {
	return r.provider, nil
}

func (r *handlerRepository) FirstEnabled(context.Context) (Provider, error) {
	return r.provider, nil
}

func (r *handlerRepository) Update(_ context.Context, p Provider) (Provider, error) {
	r.updated = p
	r.provider = p
	return p, nil
}

func (r *handlerRepository) Delete(context.Context, uuid.UUID) error { return nil }

func (r *handlerRepository) ListGroupMappings(context.Context, uuid.UUID) ([]GroupMapping, error) {
	return nil, nil
}

func (r *handlerRepository) CreateGroupMapping(_ context.Context, m GroupMapping) (GroupMapping, error) {
	return m, nil
}

func (r *handlerRepository) DeleteGroupMapping(context.Context, uuid.UUID) error { return nil }

type handlerAuditRepository struct{}

func (handlerAuditRepository) Write(context.Context, audit.Event) error { return nil }

func passthrough(next http.Handler) http.Handler { return next }

func TestLDAPProviderResponsesDoNotExposeBindPassword(t *testing.T) {
	providerID := uuid.New()
	const secret = "ldap-bind-secret"

	tests := []struct {
		name       string
		method     string
		path       string
		password   string
		wantStatus int
	}{
		{name: "список", method: http.MethodGet, path: "/api/v1/ldap/providers/", wantStatus: http.StatusOK},
		{name: "создание", method: http.MethodPost, path: "/api/v1/ldap/providers/", password: secret, wantStatus: http.StatusCreated},
		{name: "обновление с сохранением секрета", method: http.MethodPut, path: "/api/v1/ldap/providers/" + providerID.String(), wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &handlerRepository{provider: Provider{
				ID:           providerID,
				Name:         "Корпоративный LDAP",
				Host:         "ldap.example.org",
				Port:         636,
				UseTLS:       true,
				BindDN:       "cn=sso,dc=example,dc=org",
				BindPassword: secret,
				BaseDN:       "dc=example,dc=org",
				Enabled:      true,
			}}
			svc := NewService(repo, nil, handlerAuditRepository{})
			router := chi.NewRouter()
			RegisterRoutes(router, svc, passthrough, func(string, string) func(http.Handler) http.Handler {
				return passthrough
			})

			var body *bytes.Reader
			if tt.method == http.MethodGet {
				body = bytes.NewReader(nil)
			} else {
				encoded, err := json.Marshal(Provider{
					Name:         "Корпоративный LDAP",
					Host:         "ldap.example.org",
					Port:         636,
					UseTLS:       true,
					BindDN:       "cn=sso,dc=example,dc=org",
					BindPassword: tt.password,
					BaseDN:       "dc=example,dc=org",
					Enabled:      true,
				})
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.NewReader(encoded)
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.method != http.MethodGet {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("неожиданный статус: %d, тело: %s", rec.Code, rec.Body.String())
			}
			if bytes.Contains(rec.Body.Bytes(), []byte(secret)) {
				t.Fatalf("ответ содержит LDAP bind password: %s", rec.Body.String())
			}
			var payload any
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("некорректный JSON: %v", err)
			}
			if hasJSONKey(payload, "bind_password") {
				t.Fatalf("ответ содержит поле bind_password: %s", rec.Body.String())
			}
			if tt.method == http.MethodPut && repo.updated.BindPassword != secret {
				t.Fatal("пустой пароль при обновлении не сохранил существующий секрет")
			}
		})
	}
}

func hasJSONKey(value any, key string) bool {
	switch typed := value.(type) {
	case map[string]any:
		if _, ok := typed[key]; ok {
			return true
		}
		for _, nested := range typed {
			if hasJSONKey(nested, key) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if hasJSONKey(nested, key) {
				return true
			}
		}
	}
	return false
}
