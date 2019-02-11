// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

// Help message displayed for the command 'politeiawwwcli help authorizevote'
var AuthorizeVoteCmdHelpMsg = `authorizevote "token" "action"

Authorize or revoke proposal vote. Only the proposal author (owner of 
censorship token) can authorize or revoke vote. 

Arguments:
1. token      (string, required)   Proposal censorship token
2. action     (string, optional)   Valid actions are 'authorize' or 'revoke'
                                   (defaults to 'authorize')

Result:
{
  "action":    (string)  Action that was executed
  "receipt":   (string)  Server signature of client signature 
                         (signed token+version+action)
}`

type AuthorizeVoteCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true" description:"Proposal censorship token"`
		Action string `positional-arg-name:"action" description:"Valid actions are 'authorize' or 'revoke'"`
	} `positional-args:"true"`
}

func (cmd *AuthorizeVoteCmd) Execute(args []string) error {
	token := cmd.Args.Token

	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Validate action
	switch cmd.Args.Action {
	case v1.AuthVoteActionAuthorize, v1.AuthVoteActionRevoke:
		// This is correct; continue
	case "":
		// Default to authorize
		cmd.Args.Action = v1.AuthVoteActionAuthorize
	default:
		return fmt.Errorf("Invalid action.  Valid actions are:\n  " +
			"authorize  (default) authorize a vote\n  " +
			"revoke     revoke a vote authorization")
	}

	// Get server public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get proposal version
	pdr, err := c.ProposalDetails(token, nil)
	if err != nil {
		return err
	}

	// Setup authorize vote request
	sig := cfg.Identity.SignMessage([]byte(token + pdr.Proposal.Version +
		cmd.Args.Action))
	av := &v1.AuthorizeVote{
		Action:    cmd.Args.Action,
		Token:     token,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = Print(av, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	avr, err := c.AuthorizeVote(av)
	if err != nil {
		return err
	}

	// Validate authorize vote receipt
	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(avr.Receipt)
	if err != nil {
		return err
	}
	if !serverID.VerifyMessage([]byte(av.Signature), s) {
		return fmt.Errorf("could not verify authorize vote receipt")
	}

	// Print response details
	return Print(avr, cfg.Verbose, cfg.RawJSON)
}
