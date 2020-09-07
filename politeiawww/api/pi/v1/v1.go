// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
)

type ErrorStatusT int
type PropStatusT int
type VoteStatusT int
type VoteT int

const (
	APIVersion = 1

	// Proposal routes
	RouteProposalNew       = "/proposal/new"
	RouteProposalEdit      = "/proposal/edit"
	RouteProposalSetStatus = "/proposal/setstatus"
	RouteProposalDetails   = "/proposal/details"
	RouteProposals         = "/proposals"
	RouteProposalInventory = "/proposals/inventory"

	// Comment routes
	RouteCommentNew    = "/comment/new"
	RouteCommentVote   = "/comment/vote"
	RouteCommentCensor = "/comment/censor"
	RouteComments      = "/comments"
	RouteCommentVotes  = "/comments/votes"

	// Vote routes
	RouteVoteAuthorize   = "/vote/authorize"
	RouteVoteStart       = "/vote/start"
	RouteVoteStartRunoff = "/vote/startrunoff"
	RouteVoteBallot      = "/vote/ballot"
	RouteVoteDetails     = "/vote/details"
	RouteVoteResults     = "/vote/results"
	RouteVoteSummaries   = "/votes/summaries"
	RouteVoteInventory   = "/votes/inventory"

	// Proposal status codes
	PropStatusInvalid   PropStatusT = 0 // Invalid status
	PropStatusUnvetted  PropStatusT = 1 // Prop has not been vetted
	PropStatusPublic    PropStatusT = 2 // Prop has been made public
	PropStatusCensored  PropStatusT = 3 // Prop has been censored
	PropStatusAbandoned PropStatusT = 4 // Prop has been abandoned

	// Vote status codes
	VoteStatusInvalid      VoteStatusT = 0 // Invalid status
	VoteStatusUnauthorized VoteStatusT = 1 // Vote cannot be started
	VoteStatusAuthorized   VoteStatusT = 2 // Vote can be started
	VoteStatusStarted      VoteStatusT = 3 // Vote has been started
	VoteStatusFinished     VoteStatusT = 4 // Vote has finished

	// Vote types
	VoteTypeInvalid VoteT = 0

	// VoteTypeStandard is used to indicate a simple approve or reject
	// vote where the winner is the voting option that has met the
	// specified quorum and pass requirements.
	VoteTypeStandard VoteT = 1

	// VoteTypeRunoff specifies a runoff vote that multiple records
	// compete in. All records are voted on like normal, but there can
	// only be one winner in a runoff vote. The winner is the record
	// that meets the quorum requirement, meets the pass requirement,
	// and that has the most net yes votes. The winning record is
	// considered approved and all other records are considered to be
	// rejected. If no records meet the quorum and pass requirements
	// then all records are considered rejected. Note, in a runoff vote
	// it's possible for a proposal to meet both the quorum and pass
	// requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeRunoff VoteT = 2

	// Error status codes
	ErrorStatusInvalid ErrorStatusT = 0
)

var (
	// APIRoute is the prefix to the v2 API routes.
	APIRoute = fmt.Sprintf("/v%v", APIVersion)

	// ErrorStatus contains human readable error messages.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid: "error status invalid",
	}
)

// UserError represents an error that is caused by something that the user
// did (malformed input, bad timing, etc).
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// ErrorReply are replies that the server returns when it encounters an
// unrecoverable problem while executing a command. The HTTP status code will
// be 500 and the ErrorCode field will contain a UNIX timestamp that the user
// can provide to the server admin to track down the error details in the logs.
type ErrorReply struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e ErrorReply) Error() string {
	return fmt.Sprintf("server error: %v", e.ErrorCode)
}

// File describes an individual file that is part of the proposal. The
// directory structure must be flattened.
type File struct {
	Name    string `json:"name"`    // Filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // File content, base64 encoded
}

// Metadata describes user specified proposal metadata.
type Metadata struct {
	Hint    string `json:"hint"`    // Hint that describes the payload
	Digest  string `json:"digest"`  // SHA256 digest of unencoded payload
	Payload string `json:"payload"` // JSON metadata content, base64 encoded
}

const (
	// Metadata hints
	HintProposalMetadata = "proposalmetadata"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission. It is attached to a proposal submission as a Metadata object.
type ProposalMetadata struct {
	Name string `json:"name"` // Proposal name

	// LinkTo specifies a public proposal token to link this proposal
	// to. Ex, an RFP submission must link to the RFP proposal.
	LinkTo string `json:"linkto,omitempty"`

	// LinkBy is a UNIX timestamp that serves as a deadline for other
	// proposals to link to this proposal. Ex, an RFP submission cannot
	// link to an RFP proposal once the RFP's LinkBy deadline is past.
	LinkBy int64 `json:"linkby,omitempty"`
}

// CensorshipRecord contains cryptographic proof that a proposal was accepted
// for review by the server. The proof is verifiable by the client.
type CensorshipRecord struct {
	// Token is a random censorship token that is generated by the
	// server. It serves as a unique identifier for the proposal.
	Token string `json:"token"`

	// Merkle is the ordered merkle root of all files and metadata in
	// in the proposal.
	Merkle string `json:"merkle"`

	// Signature is the server signature of the Merkle+Token.
	Signature string `json:"signature"`
}

// SetStatus represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	Status    PropStatusT `json:"status"`
	Version   string      `json:"version"`
	Message   string      `json:"message,omitempty"`
	PublicKey string      `json:"publickey"`
	Signature string      `json:"signature"`
	Timestamp int64       `json:"timestamp"`
}

// ProposalRecord is an entire proposal and it's contents.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalRecord struct {
	Version   string         `json:"version"`   // Proposal version
	Timestamp int64          `json:"timestamp"` // Submission UNIX timestamp
	Status    PropStatusT    `json:"status"`    // Proposal status
	UserID    string         `json:"userid"`    // Author ID
	Username  string         `json:"username"`  // Author username
	PublicKey string         `json:"publickey"` // Key used in signature
	Signature string         `json:"signature"` // Signature of merkle root
	Statuses  []StatusChange `json:"statuses"`  // Status change history
	Files     []File         `json:"files"`     // Proposal files
	Metadata  []Metadata     `json:"metadata"`  // User defined metadata

	// LinkedFrom contains a list of public proposals that have linked
	// to this proposal. A link is established when a child proposal
	// specifies this proposal using the LinkTo field of the
	// ProposalMetadata.
	LinkedFrom []string `json:"linkedfrom"`

	// CensorshipRecord contains cryptographic proof that the proposal
	// was received by the server.
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalNew submits a new proposal.
//
// Metadata must contain a ProposalMetadata object.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalNew struct {
	Files     []File     `json:"files"`     // Proposal files
	Metadata  []Metadata `json:"metadata"`  // User defined metadata
	PublicKey string     `json:"publickey"` // Key used for signature
	Signature string     `json:"signature"` // Signature of merkle root
}

// ProposalNewReply is the reply to the ProposalNew command.
type ProposalNewReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// ProposalEdit edits an existing proposal.
//
// Metadata must contain a ProposalMetadata object.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalEdit struct {
	Token     string     `json:"token"`     // Censorship token
	Files     []File     `json:"files"`     // Proposal files
	Metadata  []Metadata `json:"metadata"`  // User defined metadata
	PublicKey string     `json:"publickey"` // Key used for signature
	Signature string     `json:"signature"` // Signature of merkle root
}

// ProposalEditReply is the reply to the ProposalEdit command.
type ProposalEditReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// ProposalSetStatus sets the status of a proposal. Some status changes require
// a reason to be included.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type ProposalSetStatus struct {
	Token     string      `json:"token"`            // Censorship token
	Version   string      `json:"version"`          // Proposal version
	Status    PropStatusT `json:"status"`           // New status
	Reason    string      `json:"reason,omitempty"` // Reason for status change
	PublicKey string      `json:"publickey"`        // Key used for signature
	Signature string      `json:"signature"`        // Client signature
}

// ProposalSetStatusReply is the reply to the ProposalSetStatus command.
type ProposalSetStatusReply struct {
	Timestamp int64 `json:"timestamp"`
}

// ProposalDetails retrieves a proposal record. If a version is not specified,
// the latest version will be returned.
type ProposalDetails struct {
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
}

// ProposalDetailsReply is the reply to the ProposalDetails command.
type ProposalDetailsReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// ProposalInventry retrieves the tokens of all proposals in the inventory,
// catagorized by proposal status and ordered by timestamp of the status change
// from newest to oldest.
type ProposalInventory struct{}

// ProposalInventoryReply is the reply to the ProposalInventory command.
type ProposalInventoryReply struct {
	Unvetted  []string `json:"unvetted"`
	Public    []string `json:"public"`
	Censored  []string `json:"censored"`
	Abandoned []string `json:"abandoned"`
}
