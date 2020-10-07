// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
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
func testUserRoutes(minPasswordLength int) (testUser, error) {
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
		return testUser{}, err
	}
	email := randomStr + "@example.com"
	username := randomStr
	password := randomStr
	err = userNew(email, password, username)
	if err != nil {
		return testUser{}, err
	}

	// Login and store user details
	fmt.Printf("Login user\n")
	lr, err := client.Login(&v1.Login{
		Email:    email,
		Password: shared.DigestSHA3(password),
	})
	if err != nil {
		return testUser{}, err
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
			return testUser{}, fmt.Errorf("submited proposal without " +
				"paying registration fee")
		}

		// Pay user registration fee
		fmt.Printf("  Paying user registration fee\n")
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, lr.PaywallAddress, lr.PaywallAmount, "")
		if err != nil {
			return testUser{}, err
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
	if err != nil {
		return testUser{}, err
	}
	for !upvr.HasPaid {
		upvr, err = userPaymentVerify()
		if err != nil {
			return testUser{}, err
		}

		fmt.Printf("  Verify user payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Purchase proposal credits
	fmt.Printf("  Proposal paywall details\n")
	ppdr, err := client.UserProposalPaywall()
	if err != nil {
		return testUser{}, err
	}

	if paywallEnabled {
		// New proposal failure - no proposal credits
		fmt.Printf("  New proposal failure: no proposal credits\n")
		npc := proposalNewCmd{
			Random: true,
		}
		err = npc.Execute(nil)
		if err == nil {
			return testUser{}, fmt.Errorf("submited proposal without " +
				"purchasing any proposal credits")
		}

		// Purchase proposal credits
		fmt.Printf("  Purchasing %v proposal credits\n", numCredits)

		atoms := ppdr.CreditPrice * uint64(numCredits)
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, ppdr.PaywallAddress, atoms, "")
		if err != nil {
			return testUser{}, err
		}

		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			float64(atoms)/1e8, lr.PaywallAddress, txID)
	}

	// Keep track of when the pending proposal credit payment
	// receives the required number of confirmations.
	for {
		pppr, err := client.ProposalPaywallPayment()
		if err != nil {
			return testUser{}, err
		}

		// TxID will be blank if the paywall has been disabled
		// or if the payment is no longer pending.
		if pppr.TxID == "" {
			// Verify that the correct number of proposal credits
			// have been added to the user's account.
			upcr, err := client.UserProposalCredits()
			if err != nil {
				return testUser{}, err
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
		return testUser{}, err
	}

	// Change password
	fmt.Printf("  Change password\n")
	randomStr, err = randomString(minPasswordLength)
	if err != nil {
		return testUser{}, err
	}
	cpc := shared.UserPasswordChangeCmd{}
	cpc.Args.Password = user.Password
	cpc.Args.NewPassword = randomStr
	err = cpc.Execute(nil)
	if err != nil {
		return testUser{}, err
	}
	user.Password = cpc.Args.NewPassword

	// Change username
	fmt.Printf("  Change username\n")
	cuc := shared.UserUsernameChangeCmd{}
	cuc.Args.Password = user.Password
	cuc.Args.NewUsername = randomStr
	err = cuc.Execute(nil)
	if err != nil {
		return testUser{}, err
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
		return testUser{}, err
	}

	// Update user key
	fmt.Printf("  Update user key\n")
	var uukc shared.UserKeyUpdateCmd
	err = uukc.Execute(nil)
	if err != nil {
		return testUser{}, err
	}

	return user, nil
}

// createMDFile returns a File object that was created using a markdown file
// filled with random text.
func createMDFile() (*pi.File, error) {
	var b bytes.Buffer
	b.WriteString("This is the proposal title\n")

	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			return nil, err
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return &pi.File{
		Name:    "index.md",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}

// newNormalProposal is a wrapper func which creates a proposal by calling
// newProposal
func newNormalProposal() (*pi.ProposalNew, error) {
	return newProposal(false, "")
}

// newProposal returns a NewProposal object contains randonly generated
// markdown text and a signature from the logged in user. If given `rfp` bool
// is true it creates an RFP. If given `linkto` it creates a RFP submission.
func newProposal(rfp bool, linkto string) (*pi.ProposalNew, error) {
	md, err := createMDFile()
	if err != nil {
		return nil, fmt.Errorf("create MD file: %v", err)
	}
	files := []pi.File{*md}

	pm := v1.ProposalMetadata{
		Name: "Some proposal name",
	}
	if rfp {
		pm.LinkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	}
	if linkto != "" {
		pm.LinkTo = linkto
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	metadata := []pi.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    pi.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	sig, err := signedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("sign merkle root: %v", err)
	}

	return &pi.ProposalNew{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}, nil
}

// testPropsWithComments tests the propsal & comments routes
func testPropsWithComments(admin, user testUser, pubKey string) error {
	// Submit new proposal
	fmt.Printf("  New proposal\n")
	pn, err := newNormalProposal()
	if err != nil {
		return err
	}
	pnr, err := client.ProposalNew(*pn)
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	pr := pi.ProposalRecord{
		Files:            pn.Files,
		Metadata:         pn.Metadata,
		PublicKey:        pn.PublicKey,
		Signature:        pn.Signature,
		CensorshipRecord: pnr.CensorshipRecord,
	}
	err = verifyProposal(pr, pubKey)
	if err != nil {
		return fmt.Errorf("verify proposal failed: %v", err)
	}

	// This is the proposal that we'll use for most of the tests
	token := pr.CensorshipRecord.Token
	fmt.Printf("  Proposal submitted: %v\n", token)

	// Edit unvetted proposal
	fmt.Printf("  Edit unvetted proposal\n")
	epc := proposalEditCmd{
		Random:   true,
		Unvetted: true,
	}
	epc.Args.Token = token
	err = epc.Execute(nil)
	if err != nil {
		return err
	}

	// Login with admin and make the proposal public
	fmt.Printf("  Login admin\n")
	err = login(admin)
	if err != nil {
		return err
	}

	fmt.Printf("  Set proposal status: public\n")
	const proposalStatusPublic = "public"
	pssc := proposalStatusSetCmd{
		Unvetted: true,
	}
	pssc.Args.Token = token
	pssc.Args.Status = proposalStatusPublic
	err = pssc.Execute(nil)
	if err != nil {
		return err
	}

	// Log back in with user
	fmt.Printf("  Login user\n")
	err = login(user)
	if err != nil {
		return err
	}

	// Edit vetted proposal
	fmt.Printf("  Edit vetted proposal\n")
	epc.Unvetted = false
	err = epc.Execute(nil)
	if err != nil {
		return err
	}

	// New comment - parent
	fmt.Printf("  New comment: parent\n")
	ncc := commentNewCmd{}
	ncc.Args.Token = token
	ncc.Args.Comment = "this is a comment"
	ncc.Args.ParentID = "0"
	err = ncc.Execute(nil)
	if err != nil {
		return err
	}

	// New comment - reply
	fmt.Printf("  New comment: reply\n")
	ncc.Args.Token = token
	ncc.Args.Comment = "this is a comment reply"
	ncc.Args.ParentID = "1"
	err = ncc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate comments
	fmt.Printf("  Proposal details\n")
	propReq := pi.ProposalRequest{
		Token: token,
	}
	pdr, err := client.Proposals(pi.Proposals{
		State:        pi.PropStateVetted,
		Requests:     []pi.ProposalRequest{propReq},
		IncludeFiles: false,
	})
	if err != nil {
		return err
	}

	prop := pdr.Proposals[token]
	err = verifyProposal(prop, pubKey)
	if err != nil {
		return fmt.Errorf("verify proposal failed: %v", err)
	}

	if prop.Comments != 2 {
		return fmt.Errorf("proposal num comments got %v, want 2",
			prop.Comments)
	}

	fmt.Printf("  Proposal comments\n")
	gcr, err := client.Comments(pi.Comments{
		Token: token,
		State: pi.PropStateVetted,
	})
	if err != nil {
		return fmt.Errorf("Comments: %v", err)
	}

	if len(gcr.Comments) != 2 {
		return fmt.Errorf("num comments got %v, want 2",
			len(gcr.Comments))
	}

	for _, v := range gcr.Comments {
		// We check the userID because userIDs are not part of
		// the politeiad comment record. UserIDs are stored in
		// in politeiawww and are added to the comments at the
		// time of the request. This introduces the potential
		// for errors.
		if v.UserID != user.ID {
			return fmt.Errorf("comment userID got %v, want %v",
				v.UserID, user.ID)
		}
	}

	// Comment vote sequence
	const (
		// Comment actions
		commentActionUpvote   = "upvote"
		commentActionDownvote = "downvote"
	)
	cvc := commentVoteCmd{}
	cvc.Args.Token = pr.CensorshipRecord.Token
	cvc.Args.CommentID = "1"
	cvc.Args.Vote = commentActionUpvote

	fmt.Printf("  Comment vote: upvote\n")
	err = cvc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Comment vote: upvote\n")
	err = cvc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Comment vote: upvote\n")
	err = cvc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Comment vote: downvote\n")
	cvc.Args.Vote = commentActionDownvote
	err = cvc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate comment votes
	fmt.Printf("  Proposal comments\n")
	gcr, err = client.Comments(pi.Comments{
		Token: token,
		State: pi.PropStateVetted,
	})
	if err != nil {
		return err
	}

	for _, v := range gcr.Comments {
		if v.CommentID == 1 {
			// XXX validate upvotes and downvotes separately when they're
			// added to the returned struct
			switch {
			//case v.Upvotes != 0:
			//	return fmt.Errorf("comment result up votes got %v, want 0",
			//		v.Upvotes)
			//case v.Downvotes != 1:
			//	return fmt.Errorf("comment result down votes got %v, want 1",
			//		v.Downvotes)
			case v.Score != -1:
				return fmt.Errorf("comment vote score got %v, want -1",
					v.Score)
			}
		}
	}

	fmt.Printf("  User comment votes\n")
	cvr, err := client.CommentVotes(pi.CommentVotes{
		State:  pi.PropStateVetted,
		Token:  token,
		UserID: user.ID,
	})
	if err != nil {
		return err
	}

	switch {
	case len(cvr.Votes) != 1:
		return fmt.Errorf("user comment votes got %v, want 1",
			len(cvr.Votes))

	case cvr.Votes[0].Vote != pi.CommentVoteDownvote:
		return fmt.Errorf("user like comment action got %v, want %v",
			cvr.Votes[0].Vote, pi.CommentVoteDownvote)
	}

	// Authorize vote then revoke
	const (
		voteAuthActionAuthorize = "authorize"
		voteAuthActionRevoke    = "revoke"
	)
	fmt.Printf("  Authorize vote: authorize\n")
	avc := voteAuthorizeCmd{}
	avc.Args.Token = token
	avc.Args.Action = voteAuthActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Authorize vote: revoke\n")
	avc.Args.Action = voteAuthActionRevoke
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate vote status
	fmt.Printf("  Vote status\n")
	vsr, err := client.VoteStatus(token)
	if err != nil {
		return err
	}

	if vsr.Status != v1.PropVoteStatusNotAuthorized {
		return fmt.Errorf("vote status got %v, want %v",
			vsr.Status, v1.PropVoteStatusNotAuthorized)
	}

	// Authorize vote
	fmt.Printf("  Authorize vote: authorize\n")
	avc.Args.Action = decredplugin.AuthVoteActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate vote status
	fmt.Printf("  Vote status\n")
	vsr, err = client.VoteStatus(token)
	if err != nil {
		return err
	}

	if vsr.Status != v1.PropVoteStatusAuthorized {
		return fmt.Errorf("vote status got %v, want %v",
			vsr.Status, v1.PropVoteStatusNotAuthorized)
	}

	// Logout
	fmt.Printf("  Logout\n")
	err = logout()
	if err != nil {
		return err
	}

	return nil
}

// Execute executes the test run command.
func (cmd *testRunCmd) Execute(args []string) error {
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
	err = logout()
	if err != nil {
		return err
	}

	// Test user routes
	u, err := testUserRoutes(int(policy.MinPasswordLength))
	if err != nil {
		return err
	}

	// Test proposal & comments routes
	err = testPropsWithComments(admin, u, version.PubKey)
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
