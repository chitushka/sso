package bootstrap

import "github.com/chitushka/sso/internal/users"

type StatusResponse struct {
	Initialized bool `json:"initialized"`
}

type CreateAdminInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateAdminResponse struct {
	Initialized bool       `json:"initialized"`
	User        users.User `json:"user"`
}
