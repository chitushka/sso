package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewSafeHTTPClient создаёт клиент для URL, задаваемых администратором.
// Клиент разрешает только публичные адреса, не использует proxy и redirects.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return newSafeHTTPClient(timeout, net.DefaultResolver, dialer.DialContext)
}

func newSafeHTTPClient(timeout time.Duration, resolver ipResolver, dial dialContextFunc) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeDialContext(resolver, dial)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func safeDialContext(resolver ipResolver, dial dialContextFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("неподдерживаемый тип исходящего соединения")
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || port == "" {
			return nil, errors.New("некорректный исходящий адрес")
		}
		if strings.Contains(host, "%") {
			return nil, errors.New("IPv6-адреса с зоной запрещены")
		}

		ips, err := resolvePublicIPs(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		var dialErr error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err != nil {
				dialErr = err
				continue
			}
			if conn == nil {
				dialErr = errors.New("исходящее соединение не создано")
				continue
			}
			actual := connectionIP(conn.RemoteAddr())
			if !IsPublicIP(actual) || !containsIP(ips, actual) {
				_ = conn.Close()
				return nil, errors.New("фактический адрес исходящего соединения не разрешён")
			}
			return conn, nil
		}
		return nil, fmt.Errorf("не удалось подключиться к исходящему узлу: %w", dialErr)
	}
}

func resolvePublicIPs(ctx context.Context, resolver ipResolver, host string) ([]net.IP, error) {
	if literal := net.ParseIP(host); literal != nil {
		if !IsPublicIP(literal) {
			return nil, errors.New("непубличный исходящий IP-адрес запрещён")
		}
		return []net.IP{literal}, nil
	}
	resolved, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(resolved))
	for _, addr := range resolved {
		if !IsPublicIP(addr.IP) {
			return nil, errors.New("исходящий узел разрешился в непубличный адрес")
		}
		if !containsIP(ips, addr.IP) {
			ips = append(ips, addr.IP)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("исходящий узел не имеет IP-адресов")
	}
	return ips, nil
}

func connectionIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func containsIP(ips []net.IP, candidate net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(candidate) {
			return true
		}
	}
	return false
}
