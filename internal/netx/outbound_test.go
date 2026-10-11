package netx

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type staticResolver struct {
	addresses []net.IPAddr
	err       error
}

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, r.err
}

type stubConn struct {
	remote net.Addr
}

func (c *stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { return nil }
func (c *stubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stubConn) RemoteAddr() net.Addr             { return c.remote }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestSafeDialRejectsNonPublicIPv4AndIPv6(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:443",
		"192.0.2.1:443",
		"[::1]:443",
		"[fc00::1]:443",
		"[fe80::1]:443",
		"[2001:db8::1]:443",
	} {
		t.Run(address, func(t *testing.T) {
			called := false
			dial := safeDialContext(staticResolver{}, func(context.Context, string, string) (net.Conn, error) {
				called = true
				return nil, nil
			})
			if conn, err := dial(context.Background(), "tcp", address); err == nil || conn != nil {
				t.Fatalf("непубличный адрес принят: conn=%v err=%v", conn, err)
			}
			if called {
				t.Fatal("сетевое соединение начато до отклонения адреса")
			}
		})
	}
}

func TestSafeDialRejectsHostWhenAnyDNSAnswerIsNonPublic(t *testing.T) {
	resolver := staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}}
	called := false
	dial := safeDialContext(resolver, func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	})
	if _, err := dial(context.Background(), "tcp", "idp.example:443"); err == nil {
		t.Fatal("смешанный публичный и локальный DNS-ответ должен быть отклонён")
	}
	if called {
		t.Fatal("соединение не должно начинаться при небезопасном DNS-ответе")
	}
}

func TestSafeDialRejectsChangedActualAddress(t *testing.T) {
	for _, actual := range []string{"127.0.0.1", "1.1.1.1"} {
		t.Run(actual, func(t *testing.T) {
			resolver := staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}
			dial := safeDialContext(resolver, func(context.Context, string, string) (net.Conn, error) {
				return &stubConn{remote: &net.TCPAddr{IP: net.ParseIP(actual), Port: 443}}, nil
			})
			if _, err := dial(context.Background(), "tcp", "idp.example:443"); err == nil {
				t.Fatal("подмена фактического адреса подключения должна быть отклонена")
			}
		})
	}
}

func TestSafeDialAcceptsResolvedPublicAddress(t *testing.T) {
	publicIP := net.ParseIP("8.8.8.8")
	resolver := staticResolver{addresses: []net.IPAddr{{IP: publicIP}}}
	dial := safeDialContext(resolver, func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Fatalf("подключение выполнено не к проверенному IP: %s", address)
		}
		return &stubConn{remote: &net.TCPAddr{IP: publicIP, Port: 443}}, nil
	})
	conn, err := dial(context.Background(), "tcp", "idp.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSafeHTTPClientDisablesProxyAndRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
	client := NewSafeHTTPClient(time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("неожиданный тип HTTP transport")
	}
	if transport.Proxy != nil {
		t.Fatal("защищённый клиент не должен использовать proxy из окружения")
	}

	calls := 0
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		location, _ := url.Parse("https://redirect.example/next")
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {location.String()}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	resp, err := client.Get("https://idp.example/start")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || calls != 1 {
		t.Fatalf("redirect был выполнен: status=%d calls=%d", resp.StatusCode, calls)
	}
}
