package bootstrap

import "errors"

var (
	ErrAlreadyInitialized = errors.New("system already initialized")
	ErrInvalidInput       = errors.New("username, email and password>=12 are required")
)
