// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// proposalDetails retrieves a full proposal record.
type proposalDetailsCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token"`
		Version string `postional-arg-name:"version" optional:"true"`
	} `positional-args:"true"`

	// Unvetted is used to indicate that the state of the requested
	// proposal is unvetted. If this flag is not used it will be
	// assumed that a vetted proposal is being requested.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the proposalDetailsCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *proposalDetailsCmd) Execute(args []string) error {
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
		state = rcv1.RecordStateUnvetted
	default:
		state = rcv1.RecordStateVetted
	}

	// Get proposal details
	d := rcv1.Details{
		State:   state,
		Token:   c.Args.Token,
		Version: c.Args.Version,
	}
	r, err := pc.RecordDetails(d)
	if err != nil {
		return err
	}

	// Print proposal to stdout
	err = printProposal(*r)
	if err != nil {
		return err
	}

	return nil
}
