// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package comments provides a plugin for adding comment functionality to
// records.
package comments

import (
	"encoding/json"
)

type StateT int
type VoteT int
type ErrorStatusT int

// TODO add a hint to comments that can be used freely by the client. This
// is how we'll distinguish proposal comments from update comments.
const (
	ID      = "comments"
	Version = "1"

	// Plugin commands
	CmdNew        = "new"        // Create a new comment
	CmdEdit       = "edit"       // Edit a comment
	CmdDel        = "del"        // Del a comment
	CmdVote       = "vote"       // Vote on a comment
	CmdGet        = "get"        // Get specified comments
	CmdGetAll     = "getall"     // Get all comments for a record
	CmdGetVersion = "getversion" // Get specified version of a comment
	CmdCount      = "count"      // Get comments count for a record
	CmdVotes      = "votes"      // Get comment votes
	CmdProofs     = "proofs"     // Get inclusion proofs

	// Record states
	StateInvalid  StateT = 0
	StateUnvetted StateT = 1
	StateVetted   StateT = 2

	// Comment vote types
	VoteInvalid  VoteT = 0
	VoteDownvote VoteT = -1
	VoteUpvote   VoteT = 1

	// PolicyCommentLengthMax is the maximum number of characters
	// accepted for comments.
	PolicyCommentLengthMax = 8000

	// PolicayVoteChangesMax is the maximum number times a user can
	// change their vote on a comment. This prevents a malicious user
	// from being able to spam comment votes.
	PolicyVoteChangesMax = 5

	// Error status codes
	ErrorStatusInvalid      ErrorStatusT = 0
	ErrorStatusStateInvalid ErrorStatusT = iota
	ErrorStatusTokenInvalid
	ErrorStatusPublicKeyInvalid
	ErrorStatusSignatureInvalid
	ErrorStatusCommentTextInvalid
	ErrorStatusRecordNotFound
	ErrorStatusCommentNotFound
	ErrorStatusUserUnauthorized
	ErrorStatusParentIDInvalid
	ErrorStatusVoteInvalid
	ErrorStatusVoteChangesMax
)

var (
	// ErrorStatus contains human readable error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:          "invalid error status",
		ErrorStatusTokenInvalid:     "invalid token",
		ErrorStatusPublicKeyInvalid: "invalid public key",
		ErrorStatusSignatureInvalid: "invalid signature",
		ErrorStatusRecordNotFound:   "record not found",
		ErrorStatusCommentNotFound:  "comment not found",
		ErrorStatusParentIDInvalid:  "parent id invalid",
		ErrorStatusVoteInvalid:      "invalid vote",
		ErrorStatusVoteChangesMax:   "vote changes max exceeded",
	}
)

// Comment represent a record comment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type Comment struct {
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID if reply
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Public key used for Signature
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
	CommentID uint32 `json:"commentid"` // Comment ID
	Version   uint32 `json:"version"`   // Comment version
	Timestamp int64  `json:"timestamp"` // UNIX timestamp of last edit
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Deleted   bool   `json:"deleted"`   // Comment has been deleted
	Reason    string `json:"reason"`    // Reason for deletion
}

// CommentAdd is the structure that is saved to disk when a comment is created
// or edited.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type CommentAdd struct {
	// Data generated by client
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Client signature

	// Metadata generated by server
	CommentID uint32 `json:"commentid"` // Comment ID
	Version   uint32 `json:"version"`   // Comment version
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// CommentDel is the structure that is saved to disk when a comment is deleted.
// Some additional fields like ParentID and UserID are required to be saved since
// all the CommentAdd records will be deleted and the client needs these
// additional fields to properly display the deleted comment in the comment
// hierarchy.
//
// Signature is the client signature of the State+Token+CommentID+Reason
type CommentDel struct {
	// Data generated by client
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason for deleting
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Client signature

	// Metadata generated by server
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	UserID    string `json:"userid"`    // Author user ID
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server sig of client sig
}

// CommentVote is the structure that is saved to disk when a comment is voted
// on.
//
// Signature is the client signature of the State+Token+CommentID+Vote.
type CommentVote struct {
	// Data generated by client
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Vote      VoteT  `json:"vote"`      // Upvote or downvote
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Client signature

	// Metadata generated by server
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// New creates a new comment.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type New struct {
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Client signature
}

// EncodeNew encodes a New into a JSON byte slice.
func EncodeNew(n New) ([]byte, error) {
	return json.Marshal(n)
}

// DecodeNew decodes a JSON byte slice into a New.
func DecodeNew(payload []byte) (*New, error) {
	var n New
	err := json.Unmarshal(payload, &n)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// NewReply is the reply to the New command.
type NewReply struct {
	CommentID uint32 `json:"commentid"` // Comment ID
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server sig of client sig
}

// EncodeNew encodes a NewReply into a JSON byte slice.
func EncodeNewReply(nr NewReply) ([]byte, error) {
	return json.Marshal(nr)
}

// DecodeNew decodes a JSON byte slice into a NewReply.
func DecodeNewReply(payload []byte) (*NewReply, error) {
	var nr NewReply
	err := json.Unmarshal(payload, &nr)
	if err != nil {
		return nil, err
	}
	return &nr, nil
}

// Edit edits an existing comment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type Edit struct {
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	CommentID uint32 `json:"commentid"` // Comment ID
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Client signature
}

// EncodeEdit encodes a Edit into a JSON byte slice.
func EncodeEdit(e Edit) ([]byte, error) {
	return json.Marshal(e)
}

// DecodeEdit decodes a JSON byte slice into a Edit.
func DecodeEdit(payload []byte) (*Edit, error) {
	var e Edit
	err := json.Unmarshal(payload, &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// EditReply is the reply to the Edit command.
type EditReply struct {
	Version   uint32 `json:"version"`   // Comment version
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// EncodeEdit encodes a EditReply into a JSON byte slice.
func EncodeEditReply(er EditReply) ([]byte, error) {
	return json.Marshal(er)
}

// DecodeEdit decodes a JSON byte slice into a EditReply.
func DecodeEditReply(payload []byte) (*EditReply, error) {
	var er EditReply
	err := json.Unmarshal(payload, &er)
	if err != nil {
		return nil, err
	}
	return &er, nil
}

// Del permanently deletes all versions of the provided comment.
//
// Signature is the client signature of the State+Token+CommentID+Reason
type Del struct {
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason for deletion
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Client signature
}

// EncodeDel encodes a Del into a JSON byte slice.
func EncodeDel(d Del) ([]byte, error) {
	return json.Marshal(d)
}

// DecodeDel decodes a JSON byte slice into a Del.
func DecodeDel(payload []byte) (*Del, error) {
	var d Del
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// DelReply is the reply to the Del command.
type DelReply struct {
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// EncodeDelReply encodes a DelReply into a JSON byte slice.
func EncodeDelReply(dr DelReply) ([]byte, error) {
	return json.Marshal(dr)
}

// DecodeDelReply decodes a JSON byte slice into a DelReply.
func DecodeDelReply(payload []byte) (*DelReply, error) {
	var dr DelReply
	err := json.Unmarshal(payload, &dr)
	if err != nil {
		return nil, err
	}
	return &dr, nil
}

// Vote casts a comment vote (upvote or downvote).
//
// The effect of a new vote on a comment score depends on the previous vote
// from that user ID. Example, a user upvotes a comment that they have already
// upvoted, the resulting vote score is 0 due to the second upvote removing the
// original upvote. The public key cannot be relied on to remain the same for
// each user so a user ID must be included.
//
// Signature is the client signature of the State+Token+CommentID+Vote.
type Vote struct {
	UserID    string `json:"userid"`    // Unique user ID
	State     StateT `json:"state"`     // Record state
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Vote      VoteT  `json:"vote"`      // Upvote or downvote
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Client signature
}

// EncodeVote encodes a Vote into a JSON byte slice.
func EncodeVote(v Vote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVote decodes a JSON byte slice into a Vote.
func DecodeVote(payload []byte) (*Vote, error) {
	var v Vote
	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// VoteReply is the reply to the Vote command.
type VoteReply struct {
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// EncodeVoteReply encodes a VoteReply into a JSON byte slice.
func EncodeVoteReply(vr VoteReply) ([]byte, error) {
	return json.Marshal(vr)
}

// DecodeVoteReply decodes a JSON byte slice into a VoteReply.
func DecodeVoteReply(payload []byte) (*VoteReply, error) {
	var vr VoteReply
	err := json.Unmarshal(payload, &vr)
	if err != nil {
		return nil, err
	}
	return &vr, nil
}

// Get returns the latest version of the comments for the provided comment IDs.
// An error is not returned if a comment is not found for one or more of the
// comment IDs. Those entries will simply not be included in the reply.
type Get struct {
	State      StateT   `json:"state"`
	Token      string   `json:"token"`
	CommentIDs []uint32 `json:"commentids"`
}

// EncodeGet encodes a Get into a JSON byte slice.
func EncodeGet(g Get) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGet decodes a JSON byte slice into a Get.
func DecodeGet(payload []byte) (*Get, error) {
	var g Get
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetReply is the reply to the Get command. The returned map will not include
// an entry for any comment IDs that did not correspond to an actual comment.
// It is the responsibility of the caller to ensure that a comment was returned
// for all of the provided comment IDs.
type GetReply struct {
	Comments map[uint32]Comment `json:"comments"` // [commentID]Comment
}

// EncodeGetReply encodes a GetReply into a JSON byte slice.
func EncodeGetReply(gr GetReply) ([]byte, error) {
	return json.Marshal(gr)
}

// DecodeGetReply decodes a JSON byte slice into a GetReply.
func DecodeGetReply(payload []byte) (*GetReply, error) {
	var gr GetReply
	err := json.Unmarshal(payload, &gr)
	if err != nil {
		return nil, err
	}
	return &gr, nil
}

// GetAll returns the latest version off all comments for the provided record.
type GetAll struct {
	State StateT `json:"state"`
	Token string `json:"token"`
}

// EncodeGetAll encodes a GetAll into a JSON byte slice.
func EncodeGetAll(ga GetAll) ([]byte, error) {
	return json.Marshal(ga)
}

// DecodeGetAll decodes a JSON byte slice into a GetAll.
func DecodeGetAll(payload []byte) (*GetAll, error) {
	var ga GetAll
	err := json.Unmarshal(payload, &ga)
	if err != nil {
		return nil, err
	}
	return &ga, nil
}

// GetAllReply is the reply to the GetAll command.
type GetAllReply struct {
	Comments []Comment `json:"comments"`
}

// EncodeGetAllReply encodes a GetAllReply into a JSON byte slice.
func EncodeGetAllReply(gar GetAllReply) ([]byte, error) {
	return json.Marshal(gar)
}

// DecodeGetAllReply decodes a JSON byte slice into a GetAllReply.
func DecodeGetAllReply(payload []byte) (*GetAllReply, error) {
	var gar GetAllReply
	err := json.Unmarshal(payload, &gar)
	if err != nil {
		return nil, err
	}
	return &gar, nil
}

// GetVersion returns a specific version of a comment.
type GetVersion struct {
	State     StateT `json:"state"`
	Token     string `json:"token"`
	CommentID uint32 `json:"commentid"`
	Version   uint32 `json:"version"`
}

// EncodeGetVersion encodes a GetVersion into a JSON byte slice.
func EncodeGetVersion(gv GetVersion) ([]byte, error) {
	return json.Marshal(gv)
}

// DecodeGetVersion decodes a JSON byte slice into a GetVersion.
func DecodeGetVersion(payload []byte) (*GetVersion, error) {
	var gv GetVersion
	err := json.Unmarshal(payload, &gv)
	if err != nil {
		return nil, err
	}
	return &gv, nil
}

// GetVersionReply is the reply to the GetVersion command.
type GetVersionReply struct {
	Comment Comment `json:"comment"`
}

// EncodeGetVersionReply encodes a GetVersionReply into a JSON byte slice.
func EncodeGetVersionReply(gvr GetVersionReply) ([]byte, error) {
	return json.Marshal(gvr)
}

// DecodeGetVersionReply decodes a JSON byte slice into a GetVersionReply.
func DecodeGetVersionReply(payload []byte) (*GetVersionReply, error) {
	var gvr GetVersionReply
	err := json.Unmarshal(payload, &gvr)
	if err != nil {
		return nil, err
	}
	return &gvr, nil
}

// Count returns the comments count for the provided record.
type Count struct {
	State StateT `json:"state"`
	Token string `json:"token"`
}

// EncodeCount encodes a Count into a JSON byte slice.
func EncodeCount(c Count) ([]byte, error) {
	return json.Marshal(c)
}

// DecodeCount decodes a JSON byte slice into a Count.
func DecodeCount(payload []byte) (*Count, error) {
	var c Count
	err := json.Unmarshal(payload, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CountReply is the reply to the Count command.
type CountReply struct {
	Count uint64 `json:"count"`
}

// EncodeCountReply encodes a CountReply into a JSON byte slice.
func EncodeCountReply(cr CountReply) ([]byte, error) {
	return json.Marshal(cr)
}

// DecodeCountReply decodes a JSON byte slice into a CountReply.
func DecodeCountReply(payload []byte) (*CountReply, error) {
	var cr CountReply
	err := json.Unmarshal(payload, &cr)
	if err != nil {
		return nil, err
	}
	return &cr, nil
}

// Votes returns the comment votes that meet the provided filtering criteria.
type Votes struct {
	State  StateT `json:"state"`
	Token  string `json:"token"`
	UserID string `json:"userid"`
}

// EncodeVotes encodes a Votes into a JSON byte slice.
func EncodeVotes(v Votes) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotes decodes a JSON byte slice into a Votes.
func DecodeVotes(payload []byte) (*Votes, error) {
	var v Votes
	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// VotesReply is the reply to the Votes command.
type VotesReply struct {
	Votes []CommentVote `json:"votes"`
}

// EncodeVotesReply encodes a VotesReply into a JSON byte slice.
func EncodeVotesReply(vr VotesReply) ([]byte, error) {
	return json.Marshal(vr)
}

// DecodeVotesReply decodes a JSON byte slice into a VotesReply.
func DecodeVotesReply(payload []byte) (*VotesReply, error) {
	var vr VotesReply
	err := json.Unmarshal(payload, &vr)
	if err != nil {
		return nil, err
	}
	return &vr, nil
}
