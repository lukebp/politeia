// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/decredplugin"
	ticketvote "github.com/decred/politeia/plugins/ticketvote"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

// voteDetails calls ticketvote plugin command to get vote details.
func (p *politeiawww) voteDetails(token string) (*ticketvote.DetailsReply, error) {
	// Prep vote details payload
	vdp := ticketvote.Details{
		Token: token,
	}
	payload, err := ticketvote.EncodeDetails(vdp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdDetails, "",
		string(payload))
	vd, err := ticketvote.DecodeDetailsReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return vd, nil
}

// castVotes calls ticketvote plugin to retrieve cast votes information.
func (p *politeiawww) castVotes(token string) (*ticketvote.CastVotesReply, error) {
	// Prep cast votes payload
	csp := ticketvote.CastVotes{
		Token: token,
	}
	payload, err := ticketvote.EncodeCastVotes(csp)

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdCastVotes, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cv, err := ticketvote.DecodeCastVotesReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cv, nil
}

// ballot calls ticketvote plugin to cast bunch of votes.
func (p *politeiawww) ballot(ballot *www.Ballot) (*ticketvote.BallotReply, error) {
	// Prep plugin command
	var bp ticketvote.Ballot

	// Transale votes
	votes := make([]ticketvote.Vote, 0, len(ballot.Votes))
	for _, vote := range ballot.Votes {
		votes = append(votes, ticketvote.Vote{
			Token:     vote.Ticket,
			Ticket:    vote.Ticket,
			VoteBit:   vote.VoteBit,
			Signature: vote.Signature,
		})
	}
	bp.Votes = votes
	payload, err := ticketvote.EncodeBallot(bp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdBallot, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	b, err := ticketvote.DecodeBallotReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return b, nil
}

// summaries calls ticketvote plugin to get vote summaries information
func (p *politeiawww) summaries(tokens []string) (*ticketvote.SummariesReply, error) {
	// Prep plugin command
	smp := ticketvote.Summaries{
		Tokens: tokens,
	}
	payload, err := ticketvote.EncodeSummaries(smp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdSummaries, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	sm, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return sm, nil
}

func (p *politeiawww) convertVoteStatusToWWW(status ticketvote.VoteStatusT) www.PropVoteStatusT {
	switch status {
	case ticketvote.VoteStatusInvalid:
		return www.PropVoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return www.PropVoteStatusNotAuthorized
	case ticketvote.VoteStatusAuthorized:
		return www.PropVoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return www.PropVoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return www.PropVoteStatusFinished
	default:
		return www.PropVoteStatusInvalid
	}
}

func (p *politeiawww) convertVoteTypeToWWW(t ticketvote.VoteT) www.VoteT {
	switch t {
	case ticketvote.VoteTypeInvalid:
		return www.VoteTypeInvalid
	case ticketvote.VoteTypeStandard:
		return www.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return www.VoteTypeRunoff
	default:
		return www.VoteTypeInvalid
	}
}

func (p *politeiawww) convertVoteErrorCodeToWWW(errcode ticketvote.VoteErrorT) decredplugin.ErrorStatusT {
	switch errcode {
	case ticketvote.VoteErrorInvalid:
		return decredplugin.ErrorStatusInvalid
	case ticketvote.VoteErrorInternalError:
		return decredplugin.ErrorStatusInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return decredplugin.ErrorStatusProposalNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return decredplugin.ErrorStatusInvalidVoteBit
	case ticketvote.VoteErrorVoteStatusInvalid:
		return decredplugin.ErrorStatusVoteHasEnded
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return decredplugin.ErrorStatusDuplicateVote
	case ticketvote.VoteErrorTicketNotEligible:
		return decredplugin.ErrorStatusIneligibleTicket
	default:
		return decredplugin.ErrorStatusInternalError
	}
}
