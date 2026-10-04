package ldap

import "errors"

var (
	ErrInvalidCredentials  = errors.New("invalid ldap credentials")
	ErrTLSRequired         = errors.New("LDAP TLS is required")
	ErrConflictingTLSModes = errors.New("LDAP use_tls and start_tls cannot both be enabled")
)
