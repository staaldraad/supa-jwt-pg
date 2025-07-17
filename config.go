package main

import (
	"fmt"
	"strings"
)

type config struct {
	// URL where to find .well-known/jwks.json
	JwksURL string

	// File that maps users to permitted roles
	MappingFile string
}

func configFromArgs(args []string) (*config, error) {
	c := &config{}

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed arg: %v", arg)
		}

		switch parts[0] {
		case "jwks":
			c.JwksURL = parts[1]
		case "mappings":
			c.MappingFile = parts[1]
		default:
			return nil, fmt.Errorf("unknown option: %v", parts[0])
		}
	}

	return c, nil
}
