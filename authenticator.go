package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
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
	PasswordAuth bool

	AuthorizedUsers Users

	JWKS keyfunc.Keyfunc
}

func discoverAuthenticator(ctx context.Context, jwksURL, mappingFile, token string) (*authenticator, error) {
	if looksLikePAT(token) || looksLikeJWT(token) {
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

	return &authenticator{
		PasswordAuth: true,
	}, nil
}

// Authenticate authenticates a user with the provided token.
func (a *authenticator) Authenticate(ctx context.Context, user string, tokenString string) error {

	if a.PasswordAuth {
		res := authPassword(user, tokenString)
		if res != nil {
			// valid username + password and permitted to login
			if strings.Contains(res.Error(), "database \"authdbsupabase\" does not exist") {
				return nil
			}
			return fmt.Errorf("%v", res)
		} else {
			return nil
		}
	}
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

func looksLikePAT(token string) bool {
	return token[:4] == "sbp_"
}

func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0][:3] == "eyJ" && parts[1][:3] == "eyJ"
}

/* authPassword will attempt to auth  to the local postgres database */
func authPassword(username, password string) error {
	connStr := fmt.Sprintf("user=%s password=%s dbname=authdbsupabase sslmode=disable host=127.0.0.1", username, password)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return err
	}
	return nil
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
