// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// proposalNewCmd submits a new proposal.
type proposalNewCmd struct {
	Args struct {
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachments"`
	} `positional-args:"true" optional:"true"`

	// Metadata fields that can be set by the user
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy int64  `long:"linkby" optional:"true"`

	// Random generates random proposal data. An IndexFile and
	// Attachments are not required when using this flag.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a timestamp using the --linkby
	// flag.
	RFP bool `long:"rfp" optional:"true"`
}

// Execute executes the proposalNewCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *proposalNewCmd) Execute(args []string) error {
	// Unpack args
	indexFile := c.Args.IndexFile
	attachments := c.Args.Attachments

	// Verify args and flags
	switch {
	case !c.Random && indexFile == "":
		return fmt.Errorf("index file not found; you must either " +
			"provide an index.md file or use --random")

	case c.Random && indexFile != "":
		return fmt.Errorf("you cannot provide file arguments and use " +
			"the --random flag at the same time")

	case !c.Random && c.Name == "":
		return fmt.Errorf("you must either provide a proposal name " +
			"using the --name flag or use the --random flag to generate " +
			"a random name")

	case c.RFP && c.LinkBy != 0:
		return fmt.Errorf("you cannot use both the --rfp and --linkby " +
			"flags at the same time")
	}

	// Check for user identity. A user identity is required to sign
	// the proposal files.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup client
	pc, err := pclient.New(cfg.Host, cfg.HTTPSCert, cfg.Cookies, cfg.CSRF)
	if err != nil {
		return err
	}

	// Get the pi policy. It contains the proposal requirements.
	pr, err := pc.PiPolicy()
	if err != nil {
		return err
	}

	// Setup index file
	var file *rcv1.File
	if c.Random {
		// Generate random text for the index file
		file, err = createMDFile()
		if err != nil {
			return err
		}
	} else {
		// Read index file from disk
		fp := util.CleanAndExpandPath(indexFile)
		var err error
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}
		file = &rcv1.File{
			Name:    piplugin.FileNameIndexFile,
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		}
	}
	files := []rcv1.File{
		*file,
	}

	// Setup attachment files
	for _, fn := range attachments {
		fp := util.CleanAndExpandPath(fn)
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}

		files = append(files, rcv1.File{
			Name:    filepath.Base(fn),
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	// Setup proposal metadata
	if c.Random {
		r, err := util.Random(int(pr.NameLengthMin))
		if err != nil {
			return err
		}
		c.Name = hex.EncodeToString(r)
	}
	pm := piv1.ProposalMetadata{
		Name: c.Name,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return err
	}
	files = append(files, rcv1.File{
		Name:    piv1.FileNameProposalMetadata,
		MIME:    mime.DetectMimeType(pmb),
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	})

	// Setup vote metadata
	if c.RFP {
		// Set linkby to a month from now
		c.LinkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	}
	if c.LinkBy != 0 || c.LinkTo != "" {
		vm := piv1.VoteMetadata{
			LinkTo: c.LinkTo,
			LinkBy: c.LinkBy,
		}
		vmb, err := json.Marshal(vm)
		if err != nil {
			return err
		}
		files = append(files, rcv1.File{
			Name:    piv1.FileNameProposalMetadata,
			MIME:    mime.DetectMimeType(vmb),
			Digest:  hex.EncodeToString(util.Digest(vmb)),
			Payload: base64.StdEncoding.EncodeToString(vmb),
		})
	}

	// Setup request
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return err
	}
	n := rcv1.New{
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}

	// Send request. The request and response details are printed to
	// the console based on the logging flags that were used.
	err = shared.PrintJSON(n)
	if err != nil {
		return err
	}
	nr, err := pc.RecordNew(n)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(nr)
	if err != nil {
		return err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return err
	}
	err = verifyRecord(nr.Record, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify record: %v", err)
	}

	return nil
}

// proposalNewHelpMsg is the output of the help command.
const proposalNewHelpMsg = `proposalnew [flags] "indexfile" "attachments" 

Submit a new proposal to Politeia.

A proposal can be submitted as an RFP (Request for Proposals) by using either
the --rfp flag or by manually specifying a link by deadline using the --linkby
flag. Only one of these flags can be used at a time.

A proposal can be submitted as an RFP submission by using the --linkto flag
to link to and an existing RFP proposal.

Arguments:
1. indexfile     (string, required)   Index file
2. attachments   (string, optional)   Attachment files

Flags:
 --name   (string, optional)  Name of the proposal.
 --linkto (string, optional)  Token of an existing public proposal to link to.
 --linkby (int64, optional)   UNIX timestamp of the RFP deadline. Setting this
                              field will make the proposal an RFP with a
                              submission deadline specified by the linkby.
 --random (bool, optional)    Generate a random proposal. If this flag is used
                              then the markdownfile argument is no longer
                              required and any provided files will be ignored.
 --rfp    (bool, optional)    Make the proposal an RFP by setting the linkby to
                              one month from the current time. This is intended
                              to be used in place of --linkby.
`
