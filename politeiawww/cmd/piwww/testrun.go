// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// testRunCmd performs a test run of all the politeiawww routes.
type testRunCmd struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`
}

// testUser stores user details that are used throughout the test run.
type testUser struct {
	ID        string // UUID
	Email     string // Email
	Username  string // Username
	Password  string // Password (not hashed)
	PublicKey string // Public key of active identity
}

// login logs in the specified user.
func login(u testUser) error {
	lc := shared.LoginCmd{}
	lc.Args.Email = u.Email
	lc.Args.Password = u.Password
	return lc.Execute(nil)
}

// logout logs out current logged in user.
func logout() error {
	// Logout admin
	lc := shared.LogoutCmd{}
	err := lc.Execute(nil)
	if err != nil {
		return err
	}
	return nil
}

// userPaymentVerify ensures current logged in user has paid registration fee
func userPaymentVerify() (v1.UserRegistrationPaymentReply, error) {
	upvr, err := client.UserPaymentVerify()
	if err != nil {
		return v1.UserRegistrationPaymentReply{}, err
	}
	return *upvr, nil
}

// randomString generates a random string
func randomString(length int) (string, error) {
	b, err := util.Random(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// userNew creates new user
func userNew(email, password, username string) error {
	fmt.Printf("Creating user: %v\n", email)

	unc := userNewCmd{
		Verify: true,
	}
	unc.Args.Email = email
	unc.Args.Username = username
	unc.Args.Password = password
	err := unc.Execute(nil)
	if err != nil {
		return err
	}
	return nil
}

// testUser tests piwww user specific routes.
func testUserRoutes(minPasswordLength int) error {
	// sleepInterval is the time to wait in between requests
	// when polling politeiawww for paywall tx confirmations
	// or RFP vote results.
	const sleepInterval = 15 * time.Second

	var (
		// paywallEnabled represents whether the politeiawww paywall
		// has been enabled.  A disabled paywall will have a paywall
		// address of "" and a paywall amount of 0.
		paywallEnabled bool

		// numCredits is the number of proposal credits that will be
		// purchased using the testnet faucet.
		numCredits = v1.ProposalListPageSize * 2

		// Test users
		user testUser
	)
	fmt.Printf("Running testUserRoutes\n")

	// Create user and verify email
	randomStr, err := randomString(minPasswordLength)
	if err != nil {
		return err
	}
	email := randomStr + "@example.com"
	username := randomStr
	password := randomStr
	err = userNew(email, password, username)
	if err != nil {
		return err
	}

	// Login and store user details
	fmt.Printf("Login user\n")
	lr, err := client.Login(&v1.Login{
		Email:    email,
		Password: shared.DigestSHA3(password),
	})
	if err != nil {
		return err
	}

	user = testUser{
		ID:        lr.UserID,
		Email:     email,
		Username:  username,
		Password:  password,
		PublicKey: lr.PublicKey,
	}

	// Check if paywall is enabled.  Paywall address and paywall
	// amount will be zero values if paywall has been disabled.
	if lr.PaywallAddress != "" && lr.PaywallAmount != 0 {
		paywallEnabled = true
	} else {
		fmt.Printf("WARNING: politeiawww paywall is disabled\n")
	}

	// Run user routes. These are the routes
	// that reqiure the user to be logged in.
	fmt.Printf("Running user routes\n")

	// Pay user registration fee
	if paywallEnabled {
		// New proposal should fail - registration fee not paid
		fmt.Printf("  New proposal failure: registration fee not paid\n")
		npc := proposalNewCmd{
			Random: true,
		}
		err = npc.Execute(nil)
		if err == nil {
			return fmt.Errorf("submited proposal without " +
				"paying registration fee")
		}

		// Pay user registration fee
		fmt.Printf("  Paying user registration fee\n")
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, lr.PaywallAddress, lr.PaywallAmount, "")
		if err != nil {
			return err
		}

		dcr := float64(lr.PaywallAmount) / 1e8
		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			dcr, lr.PaywallAddress, txID)
	}

	// Wait for user registration payment confirmations
	// If the paywall has been disable this will be marked
	// as true. If the paywall has been enabled this will
	// be true once the payment tx has the required number
	// of confirmations.
	upvr, err := userPaymentVerify()
	for !upvr.HasPaid {
		upvr, err = userPaymentVerify()
		if err != nil {
			return err
		}

		fmt.Printf("  Verify user payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Purchase proposal credits
	fmt.Printf("  Proposal paywall details\n")
	ppdr, err := client.UserProposalPaywall()
	if err != nil {
		return err
	}

	if paywallEnabled {
		// New proposal failure - no proposal credits
		fmt.Printf("  New proposal failure: no proposal credits\n")
		npc := proposalNewCmd{
			Random: true,
		}
		err = npc.Execute(nil)
		if err == nil {
			return fmt.Errorf("submited proposal without " +
				"purchasing any proposal credits")
		}

		// Purchase proposal credits
		fmt.Printf("  Purchasing %v proposal credits\n", numCredits)

		atoms := ppdr.CreditPrice * uint64(numCredits)
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, ppdr.PaywallAddress, atoms, "")
		if err != nil {
			return err
		}

		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			float64(atoms)/1e8, lr.PaywallAddress, txID)
	}

	// Keep track of when the pending proposal credit payment
	// receives the required number of confirmations.
	for {
		pppr, err := client.ProposalPaywallPayment()
		if err != nil {
			return err
		}

		// TxID will be blank if the paywall has been disabled
		// or if the payment is no longer pending.
		if pppr.TxID == "" {
			// Verify that the correct number of proposal credits
			// have been added to the user's account.
			upcr, err := client.UserProposalCredits()
			if err != nil {
				return err
			}

			if !paywallEnabled || len(upcr.UnspentCredits) == numCredits {
				break
			}
		}

		fmt.Printf("  Proposal paywall payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Me
	fmt.Printf("  Me\n")
	_, err = client.Me()
	if err != nil {
		return err
	}

	// Change password
	fmt.Printf("  Change password\n")
	randomStr, err = randomString(minPasswordLength)
	if err != nil {
		return err
	}
	cpc := shared.UserPasswordChangeCmd{}
	cpc.Args.Password = user.Password
	cpc.Args.NewPassword = randomStr
	err = cpc.Execute(nil)
	if err != nil {
		return err
	}
	user.Password = cpc.Args.NewPassword

	// Change username
	fmt.Printf("  Change username\n")
	cuc := shared.UserUsernameChangeCmd{}
	cuc.Args.Password = user.Password
	cuc.Args.NewUsername = randomStr
	err = cuc.Execute(nil)
	if err != nil {
		return err
	}
	user.Username = cuc.Args.NewUsername

	// Edit user
	fmt.Printf("  Edit user\n")
	var n uint64 = 1 << 0
	_, err = client.EditUser(
		&v1.EditUser{
			EmailNotifications: &n,
		})
	if err != nil {
		return err
	}

	// Update user key
	fmt.Printf("  Update user key\n")
	var uukc shared.UserKeyUpdateCmd
	err = uukc.Execute(nil)
	if err != nil {
		return err
	}

	return nil
}

// Execute executes the test run command.
func (cmd *testRunCmd) Execute(args []string) error {

	const (
		// Comment actions
		commentActionUpvote   = "upvote"
		commentActionDownvote = "downvote"
	)

	// Suppress output from cli commands
	cfg.Silent = true

	fmt.Printf("Running pre-testrun validation\n")

	// Policy
	fmt.Printf("Policy\n")
	policy, err := client.Policy()
	if err != nil {
		return err
	}

	// Version (CSRF tokens)
	fmt.Printf("Version\n")
	version, err := client.Version()
	if err != nil {
		return err
	}

	// We only allow this to be run on testnet for right now.
	// Running it on mainnet would require changing the user
	// email verification flow.
	// We ensure vote duration isn't longer than
	// 3 blocks as we need to approve an RFP and it's
	// submission as part of our tests.
	switch {
	case !version.TestNet:
		return fmt.Errorf("this command must be run on testnet")
	case policy.MinVoteDuration > 3:
		return fmt.Errorf("--votedurationmin flag should be <= 3, as the " +
			"tests include RFP & submssions voting")
	}

	// Ensure admin credentials are valid
	admin := testUser{
		Email:    cmd.Args.AdminEmail,
		Password: cmd.Args.AdminPassword,
	}
	err = login(admin)
	if err != nil {
		return err
	}

	// Ensure admin paid registration free
	upvr, err := userPaymentVerify()
	if err != nil {
		return err
	}
	if !upvr.HasPaid {
		return fmt.Errorf("admin has not paid registration fee")
	}

	// Logout admin
	logout()

	// Test user routes
	err = testUserRoutes(int(policy.MinPasswordLength))
	if err != nil {
		return err
	}

	return nil
}

const testRunHelpMsg = `testrun "adminusername" "adminpassword"

Run a series of tests on the politeiawww routes.  This command can only be run
on testnet.

Paywall: 
If the politeiawww paywall is enabled the test run will use the Decred tesnet
faucet to pay the user registration fee and to purchase proposal credits.  If
the politeiawww paywall has been disabled a warning will be logged and the
payments will be skipped.

Voting:
The test run will attempt to vote on a proposal.  If a dcrwallet instance is
not being run locally or if the wallet does not contain any eligible tickets
a warning will be logged and voting will be skipped.

Arguments:
1. adminusername   (string, required)   Admin username
2. adminpassword   (string, required)   Admin password
`
