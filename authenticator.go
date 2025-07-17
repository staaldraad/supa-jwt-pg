package main

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v2"
)

type user struct {
	Username       string
	PermittedRoles []string
}

type Users struct {
	Users map[string]User `yaml:"users"`
}

type User struct {
	Roles []string `yaml:"roles"`
}

type authenticator struct {
	// AuthorizedUsers is a list of users that are authorized to authenticate
	// and the roles those users can auth as
	AuthorizedUsers Users

	JWKS keyfunc.Keyfunc
}

func discoverAuthenticator(ctx context.Context, jwksURL, mappingFile string) (*authenticator, error) {

	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL}) // Context is used to end the refresh goroutine.
	if err != nil {
		return nil, fmt.Errorf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
	}

	// get permitted users and groups
	data, err := os.ReadFile(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read mapping file: %v", err)
	}

	var users Users
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		return nil, fmt.Errorf("Failed to read mapping file: %v", err)
	}

	return &authenticator{
		JWKS:            jwks,
		AuthorizedUsers: users,
	}, nil
}

// Authenticate authenticates a user with the provided token.
func (a *authenticator) Authenticate(ctx context.Context, user string, tokenString string) error {

	token, err := jwt.Parse(tokenString, a.JWKS.Keyfunc)
	if err != nil {
		fmt.Printf("Invalid token: %v\n", err)
		return fmt.Errorf("Invalid token: %v", err)
	}

	if !token.Valid {
		fmt.Println("Token is invalid")
		return fmt.Errorf("invalid token")
	}

	fmt.Println("Token is valid!")
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		fmt.Printf("Claims: %v\n", claims)
	}

	fmt.Println(claims)
	return isPermitted(claims["email"].(string), user, a.AuthorizedUsers)
}

func isPermitted(username, role string, permittedUsers Users) error {
	if username == "" {
		return fmt.Errorf("empty username")
	}
	for user, info := range permittedUsers.Users {
		if user == username {
			if slices.Contains(info.Roles, role) {
				return nil
			}
		}
	}
	return fmt.Errorf("not permitted %s:%s", username, role)
}
