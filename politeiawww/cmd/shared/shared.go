// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

var (
	// Global variables for shared commands
	cfg    *Config
	client *Client

	// ErrUserIdentityNotFound is emitted when a user identity is
	// required but the config object does not contain one.
	ErrUserIdentityNotFound = errors.New("user identity not found; " +
		"you must either create a new user or update the user key to  " +
		"generate a new identity for the logged in user")
)

// PrintJSON prints the passed in JSON using the style specified by the global
// config variable.
func PrintJSON(body interface{}) error {
	switch {
	case cfg.Silent:
		// Keep quiet
	case cfg.Verbose:
		// Verbose printing is handled by the http client
		// since it prints details like the url and response
		// codes.
	case cfg.RawJSON:
		// Print raw JSON with no formatting
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("Marshal: %v", err)
		}
		fmt.Printf("%v\n", string(b))
	default:
		// Pretty print the body
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return fmt.Errorf("MarshalIndent: %v", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", b)
	}

	return nil
}

// DigestSHA3 returns the hex encoded SHA3-256 of a string. SHA3-256 was chosen
// to hash passwords in order to match the politeiagui behavior.
func DigestSHA3(s string) string {
	h := sha3.New256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// SetConfig sets the global config variable.
func SetConfig(config *Config) {
	cfg = config
}

// SetClient sets the global client variable.
func SetClient(c *Client) {
	client = c
}
