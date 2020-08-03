// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
)

var (
	_ Plugin = (*ticketVotePlugin)(nil)
)

// ticketVotePlugin satsifies the Plugin interface.
type ticketVotePlugin struct {
	id      *identity.FullIdentity
	backend *tlogbe.Tlogbe
}

// authorize is the structure that is saved to disk when a vote is authorized
// or a previous authorizatio is revoked.
type authorize struct {
	Token     string `json:"token"`     // Record token
	Version   uint32 `json:"version"`   // Record version
	Action    string `json:"action"`    // Authorize or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of token+version+action
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// start is the structure that is saved to disk when a vote is started.
type start struct {
	Vote             ticketvote.Vote `json:"vote"`
	PublicKey        string          `json:"publickey"`
	StartBlockHeight uint32          `json:"startblockheight"`
	StartBlockHash   string          `json:"startblockhash"`
	EndBlockHeight   uint32          `json:"endblockheight"`
	EligibleTickets  []string        `json:"eligibletickets"` // Ticket hashes

	// Signature is a signature of the SHA256 digest of the JSON
	// encoded Vote struct.
	Signature string `json:"signature"`
}

func (p *ticketVotePlugin) cmdAuthorize(payload string) (string, error) {
	log.Tracef("ticketvote cmdAuthorize: %v", payload)

	a, err := ticketvote.DecodeAuthorize([]byte(payload))
	if err != nil {
		return "", err
	}
	_ = a

	// Ensure record exists
	// Verify action
	// Verify record state
	// Prepare

	return "", nil
}

func (p *ticketVotePlugin) cmdStart(payload string) (string, error) {
	log.Tracef("ticketvote cmdStart: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdStartRunoff(payload string) (string, error) {
	log.Tracef("ticketvote cmdStartRunoff: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdBallot(payload string) (string, error) {
	log.Tracef("ticketvote cmdBallot: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdDetails(payload string) (string, error) {
	log.Tracef("ticketvote cmdDetails: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdCastVotes(payload string) (string, error) {
	log.Tracef("ticketvote cmdCastVotes: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdSummaries(payload string) (string, error) {
	log.Tracef("ticketvote cmdSummaries: %v", payload)

	return "", nil
}

func (p *ticketVotePlugin) cmdInventory(payload string) (string, error) {
	log.Tracef("ticketvote cmdInventory: %v", payload)

	return "", nil
}

// Cmd executes a plugin command.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("ticketvote Cmd: %v", cmd)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(payload)
	case ticketvote.CmdStart:
		return p.cmdStart(payload)
	case ticketvote.CmdStartRunoff:
		return p.cmdStartRunoff(payload)
	case ticketvote.CmdBallot:
		return p.cmdBallot(payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(payload)
	case ticketvote.CmdCastVotes:
		return p.cmdCastVotes(payload)
	case ticketvote.CmdSummaries:
		return p.cmdSummaries(payload)
	case ticketvote.CmdInventory:
		return p.cmdInventory(payload)
	}

	return "", ErrInvalidPluginCmd
}

// Hook executes a plugin hook.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Hook(h HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v %v", h, payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Fsck() error {
	log.Tracef("ticketvote Fsck")

	return nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("ticketvote Setup")

	// Ensure dcrdata plugin has been registered

	return nil
}

func TicketVotePluginNew(id *identity.FullIdentity, backend *tlogbe.Tlogbe) (*ticketVotePlugin, error) {
	return &ticketVotePlugin{
		id:      id,
		backend: backend,
	}, nil
}