// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	ticketvote "github.com/decred/politeia/politeiad/plugins/ticketvote"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func convertStateToWWW(state pi.PropStateT) www.PropStateT {
	switch state {
	case pi.PropStateInvalid:
		return www.PropStateInvalid
	case pi.PropStateUnvetted:
		return www.PropStateUnvetted
	case pi.PropStateVetted:
		return www.PropStateVetted
	default:
		return www.PropStateInvalid
	}
}

func convertStatusToWWW(status pi.PropStatusT) www.PropStatusT {
	switch status {
	case pi.PropStatusInvalid:
		return www.PropStatusInvalid
	case pi.PropStatusPublic:
		return www.PropStatusPublic
	case pi.PropStatusCensored:
		return www.PropStatusCensored
	case pi.PropStatusAbandoned:
		return www.PropStatusAbandoned
	default:
		return www.PropStatusInvalid
	}
}

func convertProposalToWWW(pr *pi.ProposalRecord) (*www.ProposalRecord, error) {
	// Decode metadata
	var pm *piplugin.ProposalMetadata
	for _, v := range pr.Metadata {
		if v.Hint == pi.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			pm, err = piplugin.DecodeProposalMetadata(b)
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert files
	files := make([]www.File, 0, len(pr.Files))
	for _, f := range pr.Files {
		files = append(files, www.File{
			Name:    f.Name,
			MIME:    f.MIME,
			Digest:  f.Digest,
			Payload: f.Payload,
		})
	}

	// Convert metadata
	metadata := make([]www.Metadata, 0, len(pr.Metadata))
	for _, md := range pr.Metadata {
		metadata = append(metadata, www.Metadata{
			Digest:  md.Digest,
			Hint:    md.Hint,
			Payload: md.Payload,
		})
	}

	var (
		publishedAt, censoredAt, abandonedAt int64
		changeMsg                            string
		changeMsgTimestamp                   int64
	)
	for _, v := range pr.Statuses {
		if v.Timestamp > changeMsgTimestamp {
			changeMsg = v.Reason
			changeMsgTimestamp = v.Timestamp
		}
		switch v.Status {
		case pi.PropStatusPublic:
			publishedAt = v.Timestamp
		case pi.PropStatusCensored:
			censoredAt = v.Timestamp
		case pi.PropStatusAbandoned:
			abandonedAt = v.Timestamp
		}
	}

	return &www.ProposalRecord{
		Name:                pm.Name,
		State:               convertStateToWWW(pr.State),
		Status:              convertStatusToWWW(pr.Status),
		Timestamp:           pr.Timestamp,
		UserId:              pr.UserID,
		Username:            pr.Username,
		PublicKey:           pr.PublicKey,
		Signature:           pr.Signature,
		NumComments:         uint(pr.Comments),
		Version:             pr.Version,
		StatusChangeMessage: changeMsg,
		PublishedAt:         publishedAt,
		CensoredAt:          censoredAt,
		AbandonedAt:         abandonedAt,
		LinkTo:              pm.LinkTo,
		LinkBy:              pm.LinkBy,
		LinkedFrom:          pr.LinkedFrom,
		Files:               files,
		Metadata:            metadata,
		CensorshipRecord: www.CensorshipRecord{
			Token:     pr.CensorshipRecord.Token,
			Merkle:    pr.CensorshipRecord.Merkle,
			Signature: pr.CensorshipRecord.Signature,
		},
	}, nil
}

func convertVoteStatusToWWW(status ticketvote.VoteStatusT) www.PropVoteStatusT {
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

func convertVoteTypeToWWW(t ticketvote.VoteT) www.VoteT {
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

func convertVoteErrorCodeToWWW(errcode ticketvote.VoteErrorT) decredplugin.ErrorStatusT {
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

func (p *politeiawww) processProposalDetails(ctx context.Context, pd www.ProposalsDetails, u *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails: %v", pd.Token)

	pr, err := p.proposalRecord(ctx, pi.PropStateVetted, pd.Token, pd.Version)
	if err != nil {
		return nil, err
	}
	pw, err := convertProposalToWWW(pr)
	if err != nil {
		return nil, err
	}

	return &www.ProposalDetailsReply{
		Proposal: *pw,
	}, nil
}

func (p *politeiawww) processBatchProposals(ctx context.Context, bp www.BatchProposals, u *user.User) (*www.BatchProposalsReply, error) {
	log.Tracef("processBatchProposals: %v", bp.Tokens)

	// Setup requests
	prs := make([]pi.ProposalRequest, 0, len(bp.Tokens))
	for _, t := range bp.Tokens {
		prs = append(prs, pi.ProposalRequest{
			Token: t,
		})
	}

	// Get proposals
	props, err := p.proposalRecords(ctx, pi.PropStateVetted, prs, false)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	propsw := make([]www.ProposalRecord, 0, len(bp.Tokens))
	for _, pr := range props {
		propw, err := convertProposalToWWW(&pr)
		if err != nil {
			return nil, err
		}
		propsw = append(propsw, *propw)
	}

	return &www.BatchProposalsReply{
		Proposals: propsw,
	}, nil
}

func (p *politeiawww) processVoteResultsWWW(ctx context.Context, token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResultsWWW: %v", token)

	// Get vote details
	vd, err := p.voteDetails(ctx, []string{token})
	if err != nil {
		return nil, err
	}
	vote, ok := vd.Votes[token]
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Convert to www
	startHeight := strconv.FormatUint(uint64(vote.Vote.StartBlockHeight), 10)
	endHeight := strconv.FormatUint(uint64(vote.Vote.EndBlockHeight), 10)
	options := make([]www.VoteOption, 0, len(vote.Vote.Params.Options))
	for _, o := range vote.Vote.Params.Options {
		options = append(options, www.VoteOption{
			Id:          o.ID,
			Description: o.Description,
			Bits:        o.Bit,
		})
	}

	// Get cast votes
	cv, err := p.castVotes(ctx, token)
	if err != nil {
		return nil, err
	}

	// Convert to www
	votes := make([]www.CastVote, 0, len(cv.Votes))
	for _, v := range cv.Votes {
		votes = append(votes, www.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
		})
	}

	return &www.VoteResultsReply{
		StartVote: www.StartVote{
			PublicKey: vote.Vote.PublicKey,
			Signature: vote.Vote.Signature,
			Vote: www.Vote{
				Token:            vote.Vote.Params.Token,
				Mask:             vote.Vote.Params.Mask,
				Duration:         vote.Vote.Params.Duration,
				QuorumPercentage: vote.Vote.Params.QuorumPercentage,
				PassPercentage:   vote.Vote.Params.PassPercentage,
				Options:          options,
			},
		},
		StartVoteReply: www.StartVoteReply{
			StartBlockHeight: startHeight,
			StartBlockHash:   vote.Vote.StartBlockHash,
			EndHeight:        endHeight,
			EligibleTickets:  vote.Vote.EligibleTickets,
		},
		CastVotes: votes,
	}, nil
}

func (p *politeiawww) processBatchVoteSummary(ctx context.Context, bvs www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary: %v", bvs.Tokens)

	// Get vote summaries
	sm, err := p.voteSummaries(ctx, bvs.Tokens)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	summaries := make(map[string]www.VoteSummary, len(sm.Summaries))
	for k, v := range sm.Summaries {
		results := make([]www.VoteOptionResult, 0, len(v.Results))
		for _, r := range v.Results {
			results = append(results, www.VoteOptionResult{
				VotesReceived: r.Votes,
				Option: www.VoteOption{
					Id:          r.ID,
					Description: r.Description,
					Bits:        r.VoteBit,
				},
			})
		}
		summaries[k] = www.VoteSummary{
			Status:           convertVoteStatusToWWW(v.Status),
			Type:             convertVoteTypeToWWW(v.Type),
			Approved:         v.Approved,
			EligibleTickets:  v.EligibleTickets,
			Duration:         v.Duration,
			EndHeight:        uint64(v.EndBlockHeight),
			QuorumPercentage: v.QuorumPercentage,
			PassPercentage:   v.PassPercentage,
			Results:          results,
		}
	}

	return &www.BatchVoteSummaryReply{
		Summaries: summaries,
		BestBlock: uint64(sm.BestBlock),
	}, nil
}

func (p *politeiawww) processCastVotes(ctx context.Context, ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	// Prepare plugin command
	votes := make([]ticketvote.CastVote, 0, len(ballot.Votes))
	for _, vote := range ballot.Votes {
		votes = append(votes, ticketvote.CastVote{
			Token:     vote.Ticket,
			Ticket:    vote.Ticket,
			VoteBit:   vote.VoteBit,
			Signature: vote.Signature,
		})
	}
	b := ticketvote.Ballot{
		Votes: votes,
	}
	payload, err := ticketvote.EncodeBallot(b)
	if err != nil {
		return nil, err
	}

	// Send plugin command
	r, err := p.pluginCommand(ctx, ticketvote.ID, ticketvote.CmdBallot,
		string(payload))
	if err != nil {
		return nil, err
	}
	br, err := ticketvote.DecodeBallotReply([]byte(r))
	if err != nil {
		return nil, err
	}

	// Prepare reply
	receipts := make([]www.CastVoteReply, 0, len(br.Receipts))
	for k, v := range br.Receipts {
		receipts = append(receipts, www.CastVoteReply{
			ClientSignature: ballot.Votes[k].Signature,
			Signature:       v.Receipt,
			Error:           v.ErrorContext,
			ErrorStatus:     convertVoteErrorCodeToWWW(v.ErrorCode),
		})
	}

	return &www.BallotReply{
		Receipts: receipts,
	}, nil
}

func (p *politeiawww) processTokenInventory(ctx context.Context, isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	// Get record inventory
	ir, err := p.inventoryByStatus(ctx)
	if err != nil {
		return nil, err
	}

	// Get vote inventory
	vir, err := p.piVoteInventory(ctx)
	if err != nil {
		return nil, err
	}

	// Unpack record inventory
	var (
		archived        = ir.Vetted[pd.RecordStatusArchived]
		unvetted        = ir.Unvetted[pd.RecordStatusNotReviewed]
		unvettedChanges = ir.Unvetted[pd.RecordStatusUnreviewedChanges]
		unreviewed      = append(unvetted, unvettedChanges...)
		censored        = ir.Unvetted[pd.RecordStatusCensored]
	)

	// Only return unvetted tokens to admins
	if isAdmin {
		unreviewed = nil
		censored = nil
	}

	return &www.TokenInventoryReply{
		Unreviewed: unreviewed,
		Censored:   censored,
		Pre:        append(vir.Unauthorized, vir.Authorized...),
		Active:     vir.Started,
		Approved:   vir.Approved,
		Rejected:   vir.Rejected,
		Abandoned:  archived,
	}, nil
}

/*
// TODO remove old vote code
func (p *politeiawww) processAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	// Make sure token is valid and not a prefix
	if !tokenIsValid(av.Token) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: []string{av.Token},
		}
	}

	// Validate the vote authorization
	pr, err := p.getProp(av.Token)
	if err != nil {
		if errors.Is(err, cache.ErrRecordNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(av.Token, bb)
	if err != nil {
		return nil, err
	}
	err = validateAuthorizeVoteStandard(av, *u, *pr, *vs)
	if err != nil {
		return nil, err
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteToDecred(av)
	payload, err := decredplugin.EncodeAuthorizeVote(dav)
	if err != nil {
		return nil, fmt.Errorf("EncodeAuthorizeVote: %v", err)
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdAuthorizeVote,
		CommandID: decredplugin.CmdAuthorizeVote + " " + av.Token,
		Payload:   string(payload),
	}

	// Send authorizevote plugin request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeAuthorizeVoteReply: %v", err)
	}

	if !p.test && avr.Action == decredplugin.AuthVoteActionAuthorize {
		// Emit event notification for proposal vote authorized
		p.eventManager.emit(eventProposalVoteAuthorized,
			dataProposalVoteAuthorized{
				token:    av.Token,
				name:     pr.Name,
				username: u.Username,
				email:    u.Email,
			})
	}

	return &www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}, nil
}

func (p *politeiawww) processStartVoteV2(sv www2.StartVote, u *user.User) (*www2.StartVoteReply, error) {
	log.Tracef("processStartVoteV2 %v", sv.Vote.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Fetch proposal and vote summary
	if !tokenIsValid(sv.Vote.Token) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: []string{sv.Vote.Token},
		}
	}
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		if errors.Is(err, cache.ErrRecordNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(sv.Vote.Token, bb)
	if err != nil {
		return nil, err
	}

	// Validate the start vote
	err = p.validateStartVoteStandard(sv, *u, *pr, *vs)
	if err != nil {
		return nil, err
	}

	// Tell decred plugin to start voting
	dsv := convertStartVoteV2ToDecred(sv)
	payload, err := decredplugin.EncodeStartVoteV2(dsv)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle reply
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(*dsvr)
	if err != nil {
		return nil, err
	}

	// Get author data
	author, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		return nil, err
	}

	// Emit event notification for proposal start vote
	p.eventManager.emit(eventProposalVoteStarted,
		dataProposalVoteStarted{
			token:   pr.CensorshipRecord.Token,
			name:    pr.Name,
			adminID: u.ID.String(),
			author:  *author,
		})

	return svr, nil
}

func (p *politeiawww) processStartVoteRunoffV2(sv www2.StartVoteRunoff, u *user.User) (*www2.StartVoteRunoffReply, error) {
	log.Tracef("processStartVoteRunoffV2 %v", sv.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Ensure authorize votes and start votes match
	auths := make(map[string]www2.AuthorizeVote, len(sv.AuthorizeVotes))
	starts := make(map[string]www2.StartVote, len(sv.StartVotes))
	for _, v := range sv.AuthorizeVotes {
		auths[v.Token] = v
	}
	for _, v := range sv.StartVotes {
		_, ok := auths[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("start vote found without matching authorize vote %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	for _, v := range sv.StartVotes {
		starts[v.Vote.Token] = v
	}
	for _, v := range sv.AuthorizeVotes {
		_, ok := starts[v.Token]
		if !ok {
			e := fmt.Sprintf("authorize vote found without matching start vote %v",
				v.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	if len(auths) == 0 {
		e := "start votes and authorize votes cannot be empty"
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidRunoffVote,
			ErrorContext: []string{e},
		}
	}

	// Slice used to send event notification for each proposal
	// starting a vote, at the end of this function.
	var proposalNotifications []*www.ProposalRecord

	// Validate authorize votes and start votes
	for _, v := range sv.StartVotes {
		// Fetch proposal and vote summary
		token := v.Vote.Token
		if !tokenIsValid(token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{token},
			}
		}
		pr, err := p.getProp(token)
		if err != nil {
			if errors.Is(err, cache.ErrRecordNotFound) {
				err = www.UserError{
					ErrorCode:    www.ErrorStatusProposalNotFound,
					ErrorContext: []string{token},
				}
			}
			return nil, err
		}

		proposalNotifications = append(proposalNotifications, pr)

		vs, err := p.voteSummaryGet(token, bb)
		if err != nil {
			return nil, err
		}

		// Validate authorize vote. The validation function requires a v1
		// AuthorizeVote. This is fine. There is no difference between v1
		// and v2.
		av := auths[v.Vote.Token]
		av1 := www.AuthorizeVote{
			Token:     av.Token,
			Action:    av.Action,
			PublicKey: av.PublicKey,
			Signature: av.Signature,
		}
		err = validateAuthorizeVoteRunoff(av1, *u, *pr, *vs)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			var uerr *www.UserError
			if errors.As(err, &uerr) {
				uerr.ErrorContext = append(uerr.ErrorContext, token)
				err = uerr
			}
			return nil, err
		}

		// Validate start vote
		err = validateStartVoteRunoff(v, *u, *pr, *vs,
			p.cfg.VoteDurationMin, p.cfg.VoteDurationMax)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			var uerr *www.UserError
			if errors.As(err, &uerr) {
				uerr.ErrorContext = append(uerr.ErrorContext, token)
				err = uerr
			}
			return nil, err
		}
	}

	// Validate the RFP proposal
	rfp, err := p.getProp(sv.Token)
	if err != nil {
		if errors.Is(err, cache.ErrRecordNotFound) {
			err = www.UserError{
				ErrorCode:    www.ErrorStatusProposalNotFound,
				ErrorContext: []string{sv.Token},
			}
		}
		return nil, err
	}
	switch {
	case rfp.LinkBy > time.Now().Unix() && !p.cfg.TestNet:
		// Vote cannot start on RFP submissions until the RFP linkby
		// deadline has been met. This validation is skipped when on
		// testnet.
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusLinkByDeadlineNotMet,
		}
	case len(rfp.LinkedFrom) == 0:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoLinkedProposals,
		}
	}

	// Compile a list of the public, non-abandoned RFP submissions.
	// This list will be used to ensure a StartVote exists for each
	// of the public, non-abandoned submissions.
	linkedFromProps, err := p.getProps(rfp.LinkedFrom)
	if err != nil {
		return nil, err
	}
	submissions := make(map[string]bool, len(rfp.LinkedFrom)) // [token]startVoteFound
	for _, v := range linkedFromProps {
		// Filter out abandoned submissions. These are not allowed
		// to be included in a runoff vote.
		if v.Status != www.PropStatusPublic {
			continue
		}

		// Set to false for now until we check that a StartVote
		// was included for this proposal.
		submissions[v.CensorshipRecord.Token] = false
	}

	// Verify that a StartVote exists for all public, non-abandoned
	// submissions and that there are no extra StartVotes.
	for _, v := range sv.StartVotes {
		_, ok := submissions[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("invalid start vote submission: %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}

		// A StartVote was included for this proposal
		submissions[v.Vote.Token] = true
	}
	for token, startVoteFound := range submissions {
		if !startVoteFound {
			e := fmt.Sprintf("missing start vote for rfp submission: %v",
				token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}

	// Setup plugin command
	dav := convertAuthorizeVotesV2ToDecred(sv.AuthorizeVotes)
	dsv := convertStartVotesV2ToDecred(sv.StartVotes)
	payload, err := decredplugin.EncodeStartVoteRunoff(
		decredplugin.StartVoteRunoff{
			Token:          sv.Token,
			AuthorizeVotes: dav,
			StartVotes:     dsv,
		})
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVoteRunoff,
		Payload:   string(payload),
	}

	// Send plugin command
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteRunoffReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(dsvr.StartVoteReply)
	if err != nil {
		return nil, err
	}

	// Emit event notification for each proposal starting vote
	for _, pn := range proposalNotifications {
		author, err := p.db.UserGetByPubKey(pn.PublicKey)
		if err != nil {
			return nil, err
		}
		p.eventManager.emit(eventProposalVoteStarted,
			dataProposalVoteStarted{
				token:   pn.CensorshipRecord.Token,
				name:    pn.Name,
				adminID: u.ID.String(),
				author:  *author,
			})
	}

	return &www2.StartVoteRunoffReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndBlockHeight,
		EligibleTickets:  svr.EligibleTickets,
	}, nil
}

func (p *politeiawww) processVoteDetailsV2(token string) (*www2.VoteDetailsReply, error) {
	log.Tracef("processVoteDetailsV2: %v", token)

	// Validate vote status
	dvdr, err := p.decredVoteDetails(token)
	if err != nil {
		if errors.Is(err, cache.ErrRecordNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	if dvdr.StartVoteReply.StartBlockHash == "" {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"voting has not started yet"},
		}
	}

	// Handle StartVote versioning
	var vdr *www2.VoteDetailsReply
	switch dvdr.StartVote.Version {
	case decredplugin.VersionStartVoteV1:
		b := []byte(dvdr.StartVote.Payload)
		dsv1, err := decredplugin.DecodeStartVoteV1(b)
		if err != nil {
			return nil, err
		}
		vdr, err = convertDecredStartVoteV1ToVoteDetailsReplyV2(*dsv1,
			dvdr.StartVoteReply)
		if err != nil {
			return nil, err
		}
	case decredplugin.VersionStartVoteV2:
		b := []byte(dvdr.StartVote.Payload)
		dsv2, err := decredplugin.DecodeStartVoteV2(b)
		if err != nil {
			return nil, err
		}
		vdr, err = convertDecredStartVoteV2ToVoteDetailsReplyV2(*dsv2,
			dvdr.StartVoteReply)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid StartVote version %v %v",
			token, dvdr.StartVote.Version)
	}

	return vdr, nil
}

// isRFP returns whether the proposal is a Request For Proposals (RFP).
func isRFP(pr www.ProposalRecord) bool {
	return pr.LinkBy != 0
}

func isRFPSubmission(pr www.ProposalRecord) bool {
	// Right now the only proposals that we allow linking to
	// are RFPs so if the linkto is set than this is an RFP
	// submission. This may change in the future, at which
	// point we'll actually have to check the linkto proposal
	// to see if its an RFP.
	return pr.LinkTo != ""
}

// validateVoteBit ensures that bit is a valid vote bit.
func validateVoteBit(vote www2.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}

func (p *politeiawww) linkByValidate(linkBy int64) error {
	min := time.Now().Unix() + p.linkByPeriodMin()
	max := time.Now().Unix() + p.linkByPeriodMax()
	switch {
	case linkBy < min:
		e := fmt.Sprintf("linkby %v is less than min required of %v",
			linkBy, min)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkBy,
			ErrorContext: []string{e},
		}
	case linkBy > max:
		e := fmt.Sprintf("linkby %v is more than max allowed of %v",
			linkBy, max)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkBy,
			ErrorContext: []string{e},
		}
	}
	return nil
}

// validateAuthorizeVote validates the authorize vote fields. A UserError is
// returned if any of the validation fails.
func validateAuthorizeVote(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	// Ensure the public key is the user's active key
	if av.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := av.Token + pr.Version + av.Action
	err := validateSignature(av.PublicKey, av.Signature, msg)
	if err != nil {
		return err
	}

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != decredplugin.AuthVoteActionAuthorize &&
		av.Action != decredplugin.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == decredplugin.AuthVoteActionAuthorize &&
		vs.Status == www.PropVoteStatusAuthorized:
		// Cannot authorize vote; vote has already been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == decredplugin.AuthVoteActionRevoke &&
		vs.Status != www.PropVoteStatusAuthorized:
		// Cannot revoke authorization; vote has not been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}

	return nil
}

// validateAuthorizeVoteStandard validates the authorize vote for a proposal that
// is participating in a standard vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteStandard(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
		err := validateAuthorizeVote(av, u, pr, vs)
		if err != nil {
			return err
		}

		// The rest of the validation is specific to authorize votes for
		// standard votes.
		switch {
		case isRFPSubmission(pr):
			return www.UserError{
				ErrorCode:    www.ErrorStatusWrongProposalType,
				ErrorContext: []string{"proposal is an rfp submission"},
			}
		case pr.PublicKey != av.PublicKey:
			// User is not the author. First make sure the author didn't
			// submit the proposal using an old identity.
			if !isProposalAuthor(pr, u) {
				return www.UserError{
					ErrorCode: www.ErrorStatusUserNotAuthor,
				}
			}
		}

	return nil
}

// validateAuthorizeVoteRunoff validates the authorize vote for a proposal that
// is participating in a runoff vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteRunoff(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateAuthorizeVote(av, u, pr, vs)
	if err != nil {
		return err
	}

	// The rest of the validation is specific to authorize votes for
	// runoff votes.
	switch {
	case !u.Admin:
		// User is not an admin
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidSigningKey,
			ErrorContext: []string{"user not an admin"},
		}
	}

	return nil
}

// validateVoteOptions verifies that the provided vote options
// specify a simple approve/reject vote and nothing else. A UserError is
// returned if this validation fails.
func validateVoteOptions(options []www2.VoteOption) error {
	if len(options) == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteOptions,
			ErrorContext: []string{"no vote options found"},
		}
	}
	optionIDs := map[string]bool{
		decredplugin.VoteOptionIDApprove: false,
		decredplugin.VoteOptionIDReject:  false,
	}
	for _, vo := range options {
		if _, ok := optionIDs[vo.Id]; !ok {
			e := fmt.Sprintf("invalid vote option id '%v'", vo.Id)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
		optionIDs[vo.Id] = true
	}
	for k, wasFound := range optionIDs {
		if !wasFound {
			e := fmt.Sprintf("missing vote option id '%v'", k)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
	}
	return nil
}

func validateStartVote(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	if !tokenIsValid(sv.Vote.Token) {
		// Sanity check since proposal has already been looked up and
		// passed in to this function.
		return fmt.Errorf("invalid token %v", sv.Vote.Token)
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err := validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			log.Debugf("validateStartVote: validateVoteBit '%v': %v",
				v.Id, err)
			return www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote options. Only simple yes/no votes are currently
	// allowed.
	err := validateVoteOptions(sv.Vote.Options)
	if err != nil {
		return err
	}

	// Validate vote params
	switch {
	case sv.Vote.Duration < durationMin:
		// Duration not large enough
		e := fmt.Sprintf("vote duration must be >= %v", durationMin)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.Duration > durationMax:
		// Duration too large
		e := fmt.Sprintf("vote duration must be <= %v", durationMax)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.QuorumPercentage > 100:
		// Quorum too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"quorum percentage cannot be >100"},
		}
	case sv.Vote.PassPercentage > 100:
		// Pass percentage too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"pass percentage cannot be >100"},
		}
	}

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	dsv := convertStartVoteV2ToDecred(sv)
	err = dsv.VerifySignature()
	if err != nil {
		log.Debugf("validateStartVote: VerifySignature: %v", err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Validate proposal
	votePropVersion := strconv.FormatUint(uint64(sv.Vote.ProposalVersion), 10)
	switch {
	case pr.Version != votePropVersion:
		// Vote is specifying the wrong version
		e := fmt.Sprintf("got %v, want %v", votePropVersion, pr.Version)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidProposalVersion,
			ErrorContext: []string{e},
		}
	case pr.Status != www.PropStatusPublic:
		// Proposal is not public
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"proposal is not public"},
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already started"},
		}
	}

	return nil
}

func (p *politeiawww) validateStartVoteStandard(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateStartVote(sv, u, pr, vs, p.cfg.VoteDurationMin,
		p.cfg.VoteDurationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeStandard.
	switch {
	case sv.Vote.Type != www2.VoteTypeStandard:
		// Not a standard vote
		e := fmt.Sprintf("vote type must be %v", www2.VoteTypeStandard)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}
	case vs.Status != www.PropVoteStatusAuthorized:
		// Vote has not been authorized
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote not authorized"},
		}
	case isRFPSubmission(pr):
		// The proposal is an an RFP submission. The voting period for
		// RFP submissions can only be started using the StartVoteRunoff
		// route.
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{"cannot be an rfp submission"},
		}
	}

	// Verify the LinkBy deadline for RFP proposals. The LinkBy policy
	// requirements are enforced at the time of starting the vote
	// because its purpose is to ensure that there is enough time for
	// RFP submissions to be submitted.
	if isRFP(pr) {
		err := p.linkByValidate(pr.LinkBy)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateStartVoteRunoff(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	err := validateStartVote(sv, u, pr, vs, durationMin, durationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeRunoff.

	token := sv.Vote.Token
	switch {
	case sv.Vote.Type != www2.VoteTypeRunoff:
		// Not a runoff vote
		e := fmt.Sprintf("%v vote type must be %v",
			token, www2.VoteTypeRunoff)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}

	case !isRFPSubmission(pr):
		// The proposal is not an RFP submission
		e := fmt.Sprintf("%v is not an rfp submission", token)
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{e},
		}

	case vs.Status != www.PropVoteStatusNotAuthorized:
		// Sanity check. This should not be possible.
		return fmt.Errorf("%v got vote status %v, want %v",
			token, vs.Status, www.PropVoteStatusNotAuthorized)
	}

	return nil
}

func voteIsApproved(vs www.VoteSummary) bool {
	if vs.Status != www.PropVoteStatusFinished {
		// Vote has not ended yet
		return false
	}

	var (
		total   uint64
		approve uint64
	)
	for _, v := range vs.Results {
		total += v.VotesReceived
		if v.Option.Id == decredplugin.VoteOptionIDApprove {
			approve = v.VotesReceived
		}
	}
	quorum := uint64(float64(vs.QuorumPercentage) / 100 * float64(vs.EligibleTickets))
	pass := uint64(float64(vs.PassPercentage) / 100 * float64(total))
	switch {
	case total < quorum:
		// Quorum not met
		return false
	case approve < pass:
		// Pass percentage not met
		return false
	}

	return true
}
*/
