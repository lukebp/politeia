// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdCommentCount retreives the comments for the specified proposal.
type cmdCommentCount struct {
	Args struct {
		Tokens []string `positional-arg-name:"tokens"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdCommentCount command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentCount) Execute(args []string) error {
	_, err := commentCount(c)
	if err != nil {
		return err
	}
	return nil
}

// commentCount returns the number of comments that have been made on the
// provided records. This function has been pulled out of the Execute method so
// that it can be used in test commands.
func commentCount(c *cmdCommentCount) (map[string]uint32, error) {
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
		return nil, err
	}

	// Get comments
	cc := cmv1.Count{
		Tokens: c.Args.Tokens,
	}
	cr, err := pc.CommentCount(cc)
	if err != nil {
		return nil, err
	}

	// Print counts
	for k, v := range cr.Counts {
		printf("%v %v\n", k, v)
	}

	return cr.Counts, nil
}

// commentCountHelpMsg is printed to stdout by the help command.
const commentCountHelpMsg = `commentcount "tokens..." 

Get the number of comments that have been made on each of the provided
records.

Arguments:
1. token  (string, required)  Proposal censorship token

Examples:
$ pictl commentcount f6458c2d8d9ef41c 9f9af91cf609d839 917c6fde9bcc2118
$ pictl commentcount f6458c2 9f9af91 917c6fd`
