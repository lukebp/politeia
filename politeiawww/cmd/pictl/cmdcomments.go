// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdComments retreives the comments for the specified proposal.
type cmdComments struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`

	// Unvetted is used to request the comments of an unvetted record.
	// If this flag is not used the command assumes the record is
	// vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdComments command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdComments) Execute(args []string) error {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Setup state
	var state string
	switch {
	case c.Unvetted:
		state = cmv1.RecordStateUnvetted
	default:
		state = cmv1.RecordStateVetted
	}

	// Get comments
	cm := cmv1.Comments{
		State: state,
		Token: c.Args.Token,
	}
	cr, err := pc.Comments(cm)
	if err != nil {
		return err
	}

	// Print comments
	for _, v := range cr.Comments {
		_ = v
	}

	return nil
}

// commentsHelpMsg is printed to stdout by the help command.
const commentsHelpMsg = `comments "token" 

Get the comments for a record.

If the record is unvetted, the --unvetted flag must be used. Retrieving the
comments on an unvetted record requires the user be either an admin or the
record author.

Arguments:
1. token  (string, required)  Proposal censorship token

Flags:
  --unvetted  (bool, optional)  Record is unvetted.
`
