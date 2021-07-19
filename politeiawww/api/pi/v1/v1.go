// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// RoutePolicy returns the policy for the pi API.
	RoutePolicy = "/policy"
)

// Policy requests the policy settings for the pi API. It includes the policy
// guidlines for the contents of a proposal record.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
type PolicyReply struct {
	TextFileSizeMax    uint32   `json:"textfilesizemax"` // In bytes
	ImageFileCountMax  uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax   uint32   `json:"imagefilesizemax"` // In bytes
	NameLengthMin      uint32   `json:"namelengthmin"`    // In characters
	NameLengthMax      uint32   `json:"namelengthmax"`    // In characters
	NameSupportedChars []string `json:"namesupportedchars"`
}

const (
	// FileNameIndexFile is the file name of the proposal markdown
	// file that contains the main proposal contents. All proposal
	// submissions must contain an index file.
	FileNameIndexFile = "index.md"

	// FileNameProposalMetadata is the file name of the user submitted
	// ProposalMetadata. All proposal submissions must contain a
	// proposal metadata file.
	FileNameProposalMetadata = "proposalmetadata.json"

	// FileNameVoteMetadata is the file name of the user submitted
	// VoteMetadata. This file will only be present when proposals
	// are hosting or participating in certain types of votes.
	FileNameVoteMetadata = "votemetadata.json"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission.
type ProposalMetadata struct {
	Name string `json:"name"` // Proposal name
}

// VoteMetadata is metadata that is specified by the user on proposal
// submission in order to host or participate in a runoff vote.
type VoteMetadata struct {
	// LinkBy is set when the user intends for the proposal to be the
	// parent proposal in a runoff vote. It is a UNIX timestamp that
	// serves as the deadline for other proposals to declare their
	// intent to participate in the runoff vote.
	LinkBy int64 `json:"linkby,omitempty"`

	// LinkTo is the censorship token of a runoff vote parent proposal.
	// It is set when a proposal is being submitted as a vote options
	// in the runoff vote.
	LinkTo string `json:"linkto,omitempty"`
}

// PropStatusT is used to indicate what part of the proposal life cycle a
// proposal is currently in. It combines record statuses, ticketvote statuses,
// as well as adding in statuses that are specific to the Decred proposal
// system in order to create a unified map of the various paths a proposal can
// take throughout the proposal process. This serves as the source of truth for
// clients so that they don't need to try and decipher what various
// combinations of plugin statuses mean for the proposal.
type PropStatusT uint32

const (
	// PropStatusInvalid represents and invalid proposal status.
	PropStatusInvalid PropStatusT = 0

	// PropStatusUnvetted represents a proposal that has been submitted
	// but has not yet been made public by the admins.
	PropStatusUnvetted PropStatusT = 1

	// PropStatusUnvettedAbandoned represents a proposal that has been
	// submitted, but was abandoned by the author prior to being made
	// public by the admins. The proposal can be marked as abandoned by
	// either the proposal author or an admin. Abandoned proposal files
	// are not deleted from the backend, but on additional proposal or
	// plugin data changes can be made.
	PropStatusUnvettedAbandoned PropStatusT = 2

	// PropStatusUnvettedCensored represents a proposal that has been
	// submitted, but was censored by an admin prior to being made
	// public. Censored proposal files are deleted from the backend.
	// Not additional proposal or plugin data changes can be made.
	PropStatusUnvettedCensored PropStatusT = 3

	// PropStatusUnderReview represents a proposal that has been made
	// public and is being reviewed by the Decred stakeholders, but has
	// not had its voting period started yet.
	PropStatusUnderReview PropStatusT = 4

	// PropStatusAbandoned represents a proposal that has been made
	// public, but has been abandoned by the proposal author.
	// Abandoned proposals are locked from any additional changes.
	PropStatusAbandoned PropStatusT = 5

	PropStatusCensored PropStatusT = 6

	PropStatusVoteStarted PropStatusT = 7

	PropStatusNotFunded PropStatusT = 8

	// PropStatusActive represents a proposal that was funded and is
	// actively being billed against.
	PropStatusActive PropStatusT = 9

	// PropStatusCompleted represents a proposal that was funded and
	// has been completed. A completed proposal is no longer being
	// billed against. A proposal is marked as completed by an admin.
	PropStatusCompleted PropStatusT = 10

	// PropStatusClosed represents a proposal that was funded, but
	// was never completed. A proposal is marked as closed by an admin.
	// A closed proposal cannot be billed against any further. The most
	// common reason a proposal would be closed is because the author
	// failed to deliver on the milestones laid out in the proposal.
	PropStatusClosed PropStatusT = 11
)
