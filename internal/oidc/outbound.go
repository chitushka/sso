package oidc

import (
	"net/http"
	"time"

	"github.com/chitushka/sso/internal/netx"
)

func newBackchannelHTTPClient() *http.Client {
	return netx.NewSafeHTTPClient(10 * time.Second)
}
