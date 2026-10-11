package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldaplib "github.com/go-ldap/ldap/v3"
)

func listenLDAP(t *testing.T, handler func(net.Conn) error) (Provider, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	errorsCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorsCh <- err
			return
		}
		defer conn.Close()
		errorsCh <- handler(conn)
	}()
	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return Provider{
		Host:              host,
		Port:              port,
		BindDN:            "cn=admin,dc=example,dc=org",
		BindPassword:      "directory-password",
		BaseDN:            "dc=example,dc=org",
		UserFilter:        "(uid={username})",
		UsernameAttribute: "uid",
		EmailAttribute:    "mail",
	}, errorsCh
}

func waitServer(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("тестовый LDAP-сервер не завершился")
	}
}

func hangUntilClosed(conn net.Conn) error {
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	if err == nil {
		return errors.New("LDAP-клиент неожиданно отправил дополнительный запрос")
	}
	return nil
}

func readRequestAndHang(conn net.Conn) error {
	if _, err := ber.ReadPacket(conn); err != nil {
		return fmt.Errorf("прочитать LDAP-запрос: %w", err)
	}
	return hangUntilClosed(conn)
}

func readBytesAndHang(conn net.Conn) error {
	buffer := make([]byte, 4096)
	if _, err := conn.Read(buffer); err != nil {
		return fmt.Errorf("прочитать начало TLS handshake: %w", err)
	}
	return hangUntilClosed(conn)
}

func TestLDAPBindStopsWhenContextCancelled(t *testing.T) {
	accepted := make(chan struct{})
	provider, serverResult := listenLDAP(t, func(conn net.Conn) error {
		close(accepted)
		return readRequestAndHang(conn)
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- NewClient().TestConnection(ctx, provider) }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("LDAP-соединение не установлено")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ожидалась отмена контекста, получено: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LDAP bind не прерван после отмены контекста")
	}
	waitServer(t, serverResult)
}

func TestLDAPBindHonorsOperationDeadline(t *testing.T) {
	provider, serverResult := listenLDAP(t, readRequestAndHang)
	started := time.Now()
	err := NewClient().WithTimeout(80*time.Millisecond).TestConnection(context.Background(), provider)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ожидалось истечение deadline, получено: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("зависший LDAP bind завершился слишком поздно: %s", elapsed)
	}
	waitServer(t, serverResult)
}

func TestLDAPSearchHonorsOperationDeadline(t *testing.T) {
	searchReceived := make(chan struct{})
	provider, serverResult := listenLDAP(t, func(conn net.Conn) error {
		bindRequest, err := ber.ReadPacket(conn)
		if err != nil {
			return fmt.Errorf("прочитать bind: %w", err)
		}
		if len(bindRequest.Children) < 2 || bindRequest.Children[1].Tag != ldaplib.ApplicationBindRequest {
			return errors.New("получен неожиданный LDAP-запрос вместо bind")
		}
		messageID, ok := bindRequest.Children[0].Value.(int64)
		if !ok {
			return errors.New("bind не содержит message ID")
		}
		response := ber.NewSequence("LDAPMessage")
		response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
		bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldaplib.ApplicationBindResponse, nil, "Bind Response")
		bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(ldaplib.LDAPResultSuccess), "resultCode"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
		response.AppendChild(bindResponse)
		if _, err := conn.Write(response.Bytes()); err != nil {
			return fmt.Errorf("отправить bind-ответ: %w", err)
		}

		searchRequest, err := ber.ReadPacket(conn)
		if err != nil {
			return fmt.Errorf("прочитать search: %w", err)
		}
		if len(searchRequest.Children) < 2 || searchRequest.Children[1].Tag != ldaplib.ApplicationSearchRequest {
			return errors.New("получен неожиданный LDAP-запрос вместо search")
		}
		close(searchReceived)
		return hangUntilClosed(conn)
	})
	result := make(chan error, 1)
	go func() {
		_, err := NewClient().WithTimeout(500*time.Millisecond).Authenticate(context.Background(), provider, "alice", "AlicePassword1!")
		result <- err
	}()
	select {
	case <-searchReceived:
	case err := <-result:
		t.Fatalf("LDAP authenticate завершился до search: %v", err)
	case <-time.After(time.Second):
		t.Fatal("LDAP search не был отправлен")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ожидалось истечение deadline поиска, получено: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("зависший LDAP search не прерван по deadline")
	}
	waitServer(t, serverResult)
}

func TestLDAPTLSNegotiationHonorsOperationDeadline(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Provider)
		handler   func(net.Conn) error
	}{
		{name: "LDAPS", configure: func(p *Provider) { p.UseTLS = true }, handler: readBytesAndHang},
		{name: "StartTLS", configure: func(p *Provider) { p.StartTLS = true }, handler: readRequestAndHang},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, serverResult := listenLDAP(t, test.handler)
			test.configure(&provider)
			err := NewClient().WithTimeout(80*time.Millisecond).TestConnection(context.Background(), provider)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("ожидалось истечение deadline TLS, получено: %v", err)
			}
			waitServer(t, serverResult)
		})
	}
}

func TestLDAPDialHonorsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewClient().TestConnection(ctx, Provider{Host: "203.0.113.1", Port: 389, BindDN: "cn=admin", BindPassword: "secret"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась отмена dial, получено: %v", err)
	}
}
