// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a politeiad plugin for functionality that is specific to
// decred's proposal system.
package pi

const (
	ID = "pi"

	// Plugin commands
	CmdProposalInv   = "proposalinv" // Get inventory by proposal status
	CmdVoteInventory = "voteinv"     // Get inventory by vote status
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT int

const (
	// User error status codes
	// TODO number error codes and add human readable error messages
	ErrorCodeInvalid          ErrorCodeT = 0
	ErrorCodePageSizeExceeded ErrorCodeT = iota
	ErrorCodePropTokenInvalid
	ErrorCodePropStatusInvalid
	ErrorCodePropVersionInvalid
	ErrorCodePropStatusChangeInvalid
	ErrorCodePropLinkToInvalid
	ErrorCodeVoteStatusInvalid
	ErrorCodeStartDetailsInvalid
	ErrorCodeStartDetailsMissing
	ErrorCodeVoteParentInvalid
)

const (
	// FileNameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameProposalMetadata = "proposalmetadata.json"

	// TODO MDStream IDs need to be plugin specific
	// MDStreamIDGeneralMetadata is the politeiad metadata stream ID
	// for the GeneralMetadata structure.
	MDStreamIDGeneralMetadata = 1

	// MDStreamIDStatusChanges is the politeiad metadata stream ID
	// that the StatusesChange structure is appended onto.
	MDStreamIDStatusChanges = 2
)

// ProposalMetadata contains metadata that is provided by the user as part of
// the proposal submission bundle. The proposal metadata is included in the
// proposal signature since it is user specified data. The ProposalMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
type ProposalMetadata struct {
	Name string `json:"name"`
}

// GeneralMetadata contains general metadata about a politeiad record. It is
// generated by the server and saved to politeiad as a metadata stream.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all politeiad Files.
type GeneralMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// PropStatusT represents a proposal status.
type PropStatusT int

const (
	// PropStatusInvalid is an invalid proposal status.
	PropStatusInvalid PropStatusT = 0

	// PropStatusUnvetted represents a proposal that has not been made
	// public yet.
	PropStatusUnvetted PropStatusT = 1

	// PropStatusPublic represents a proposal that has been made
	// public.
	PropStatusPublic PropStatusT = 2

	// PropStatusCensored represents a proposal that has been censored.
	PropStatusCensored PropStatusT = 3

	// PropStatusAbandoned represents a proposal that has been
	//  abandoned by the author.
	PropStatusAbandoned PropStatusT = 4
)

var (
	// PropStatuses contains the human readable proposal statuses.
	PropStatuses = map[PropStatusT]string{
		PropStatusInvalid:   "invalid",
		PropStatusUnvetted:  "unvetted",
		PropStatusPublic:    "public",
		PropStatusCensored:  "censored",
		PropStatusAbandoned: "abandoned",
	}

	// StatusChanges contains the allowed proposal status change
	// transitions. If StatusChanges[currentStatus][newStatus] exists
	// then the status change is allowed.
	StatusChanges = map[PropStatusT]map[PropStatusT]struct{}{
		PropStatusUnvetted: {
			PropStatusPublic:   {},
			PropStatusCensored: {},
		},
		PropStatusPublic: {
			PropStatusAbandoned: {},
			PropStatusCensored:  {},
		},
		PropStatusCensored:  {},
		PropStatusAbandoned: {},
	}
)

// StatusChange represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	Token     string      `json:"token"`
	Version   string      `json:"version"`
	Status    PropStatusT `json:"status"`
	Reason    string      `json:"message,omitempty"`
	PublicKey string      `json:"publickey"`
	Signature string      `json:"signature"`
	Timestamp int64       `json:"timestamp"`
}

// ProposalInv retrieves the tokens of all proposals in the inventory that
// match the provided filtering criteria. The returned proposals are
// categorized by proposal state and status. If no filtering criteria is
// provided then the full proposal inventory is returned.
type ProposalInv struct {
	UserID string `json:"userid,omitempty"`
}

// ProposalInvReply is the reply to the ProposalInv command. The returned maps
// contains map[status][]token where the status is the human readable proposal
// status and the token is the proposal token.
type ProposalInvReply struct {
	Unvetted map[string][]string `json:"unvetted"`
	Vetted   map[string][]string `json:"vetted"`
}

// VoteInventory requests the tokens of all proposals in the inventory
// categorized by their vote status. This call relies on the ticketvote
// Inventory call, but breaks the Finished vote status out into Approved and
// Rejected categories. This functionality is specific to pi.
type VoteInventory struct{}

// VoteInventoryReply is the reply to the VoteInventory command.
type VoteInventoryReply struct {
	Unauthorized []string `json:"unauthorized"`
	Authorized   []string `json:"authorized"`
	Started      []string `json:"started"`
	Approved     []string `json:"approved"`
	Rejected     []string `json:"rejected"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}
