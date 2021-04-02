// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// LoginCmd logs into Politeia using the specified credentials.
type LoginCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email" required:"true"`
		Password string `positional-arg-name:"password" required:"true"`
		Code     string `positional-arg-name:"code"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the login command.
func (cmd *LoginCmd) Execute(args []string) error {

	// Fetch CSRF key
	_, err := client.Version()
	if err != nil {
		return err
	}

	// NOTE: Keep in mind that certain special characters in your
	// password can lead to unexpected behavior when your shell
	// parses them.
	//
	// For example, if your password is "password$123" the actual
	// password that is provided to this command will be "password23"
	// depending on your shell.

	// Setup login request
	l := &v1.Login{
		Email:    cmd.Args.Email,
		Password: DigestSHA3(cmd.Args.Password),
		Code:     cmd.Args.Code,
	}

	// Print request details
	err = PrintJSON(l)
	if err != nil {
		return err
	}

	// Send request
	lr, err := client.Login(l)
	if err != nil {
		return err
	}

	// Update the logged in username that we store on disk
	err = cfg.SaveLoggedInUsername(lr.Username)
	if err != nil {
		return fmt.Errorf("SaveLoggedInUsername: %v", err)
	}

	// Print response details
	return PrintJSON(lr)
}

// LoginHelpMsg is the output for the help command when 'login' is specified.
const LoginHelpMsg = `login "email" "password"

Login as a user or admin.

Arguments:
1. email      (string, required)   Email
2. password   (string, required)   Password
3. code       (string)             TOTP Code

Result:
{
  "isadmin":              (bool)    Is the user an admin
  "userid":               (string)  User ID
  "email":                (string)  User email
  "username":             (string)  Username
  "publickey":            (string)  Active public key
  "paywalladdress":       (string)  Registration paywall address
  "paywallamount":        (uint64)  Registration paywall amount in atoms
  "paywalltxnotbefore":   (int64)   Minimum timestamp for paywall tx
  "proposalcredits":      (uint64)  Number of available proposal credits 
  "lastlogintime":        (int64)   Unix timestamp of last login date
  "sessionmaxage":        (int64)   Unix timestamp of session max age
}`
