// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

const (
	// loggedInUserFilename contains the username of the logged in
	// user data for a specific host.
	loggedInUserFilename = "{host}_logged_in_user.json"
)

type loggedInUser struct {
	Username   string `json:"username"`
	HeaderCSRF string `json:"headercsrf"`
}

func (cfg *Config) loadLoggedInUsername() error {
	f, err := cfg.hostFilePath(userFile)
	if err != nil {
		return fmt.Errorf("hostFilePath: %v", err)
	}

	if !fileExists(f) {
		// Nothing to load
		return nil
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return fmt.Errorf("read file %v: %v", f, err)
	}

	cfg.Username = string(b)

	return nil
}

// SaveLoggedInUsername saved the passed in username to the on-disk user file.
// We persist the logged in username between commands so that we know which
// identity to load.
func (cfg *Config) SaveLoggedInUsername(username string) error {
	f, err := cfg.hostFilePath(userFile)
	if err != nil {
		return fmt.Errorf("hostFilePath: %v", err)
	}

	err = ioutil.WriteFile(f, []byte(username), 0600)
	if err != nil {
		return fmt.Errorf("write file %v: %v", f, err)
	}

	// The config identity is the identity of the logged in
	// user so we need to update the identity when the logged
	// in user changes.
	id, err := cfg.LoadIdentity(username)
	if err != nil {
		return fmt.Errorf("load identity: %v", err)
	}
	cfg.Identity = id

	return nil
}

const (
	// identityFilename contains the file name template for a user's
	// identity file.
	identityFilename = "{host}_{username}_identity.json"
)

// guiIdentity matches the identity file that can be downloaded from the gui.
// Converting the identity to this structure before saving it to disk allows
// the CLI and GUI identities to be interchangable.
type guiIdentity struct {
	PublicKey string `json:"publicKey"` // Ed25519 public key, hex encoded
	SecredKey string `json:"secredKey"` // Ed25519 private key, hex encoded
}

// identityFilePath returns the file path for a user identity that is persisted
// between CLI commands.
func identityFilePath(dataDir, host, username string) (string, error) {
	fn := strings.Replace(identityFilename, "{host}", host)
	fn = strings.Replace(identityFilename, "{username}", username)
	return filepath.Join(dataDir, fn)
}

func (cfg *Config) LoadIdentity(username string) (*identity.FullIdentity, error) {
	err := cfg.loadLoggedInUsername()
	if err != nil {
		return nil, fmt.Errorf("load username: %v", err)
	}

	if username == "" {
		// No logged in user
		return nil, nil
	}

	f, err := cfg.identityFilePath(username)
	if err != nil {
		return nil, fmt.Errorf("identityFilePath: %v", err)
	}

	if !fileExists(f) {
		// User identity doesn't exist
		return nil, nil
	}

	id, err := identity.LoadFullIdentity(f)
	if err != nil {
		return nil, fmt.Errorf("load identity %v: %v", f, err)
	}

	return id, nil
}

// SaveIdentity writes the passed in user identity to disk so that it can be
// persisted between commands.  The prepend the hostname and the username onto
// the idenity filename so that we can keep track of the identities for
// multiple users per host.
func (cfg *Config) SaveIdentity(user string, id *identity.FullIdentity) error {
	f, err := cfg.identityFilePath(user)
	if err != nil {
		return fmt.Errorf("identityFilePath: %v", err)
	}

	err = id.Save(f)
	if err != nil {
		return fmt.Errorf("save idenity to %v: %v", f, err)
	}

	cfg.Identity = id
	return nil
}
