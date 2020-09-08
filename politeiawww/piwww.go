// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"time"

	piplugin "github.com/decred/politeia/plugins/pi"
	pd "github.com/decred/politeia/politeiad/api/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

// TODO use pi policies

const (
	// MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
)

var (
	validProposalName = regexp.MustCompile(createProposalNameRegex())
)

// tokenIsValid returns whether the provided string is a valid politeiad
// censorship record token.
func tokenIsValid(token string) bool {
	b, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	if len(b) != pd.TokenSize {
		return false
	}
	return true
}

// proposalNameIsValid returns whether the provided name is a valid proposal
// name.
func proposalNameIsValid(name string) bool {
	return validProposalName.MatchString(name)
}

// createProposalNameRegex returns a regex string for validating the proposal
// name.
func createProposalNameRegex() string {
	var validProposalNameBuffer bytes.Buffer
	validProposalNameBuffer.WriteString("^[")

	for _, supportedChar := range www.PolicyProposalNameSupportedChars {
		if len(supportedChar) > 1 {
			validProposalNameBuffer.WriteString(supportedChar)
		} else {
			validProposalNameBuffer.WriteString(`\` + supportedChar)
		}
	}
	minNameLength := strconv.Itoa(www.PolicyMinProposalNameLength)
	maxNameLength := strconv.Itoa(www.PolicyMaxProposalNameLength)
	validProposalNameBuffer.WriteString("]{")
	validProposalNameBuffer.WriteString(minNameLength + ",")
	validProposalNameBuffer.WriteString(maxNameLength + "}$")

	return validProposalNameBuffer.String()
}

func convertUserErrFromSignatureErr(err error) pi.UserError {
	var e util.SignatureError
	var s pi.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = pi.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = pi.ErrorStatusSignatureInvalid
		}
	}
	return pi.UserError{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func convertFileFromMetadata(m pi.Metadata) pd.File {
	var name string
	switch m.Hint {
	case pi.HintProposalMetadata:
		name = piplugin.FilenameProposalMetadata
	}
	return pd.File{
		Name:    name,
		MIME:    mimeTypeTextUTF8,
		Digest:  m.Digest,
		Payload: m.Payload,
	}
}

func convertFileFromPi(f pi.File) pd.File {
	return pd.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertFilesFromPi(files []pi.File) []pd.File {
	f := make([]pd.File, 0, len(files))
	for _, v := range files {
		f = append(f, convertFileFromPi(v))
	}
	return f
}

func convertCensorshipRecordFromPD(cr pd.CensorshipRecord) pi.CensorshipRecord {
	return pi.CensorshipRecord{
		Token:     cr.Token,
		Merkle:    cr.Merkle,
		Signature: cr.Signature,
	}
}

// linkByPeriodMin returns the minimum amount of time, in seconds, that the
// LinkBy period must be set to. This is determined by adding 1 week onto the
// minimum voting period so that RFP proposal submissions have at least one
// week to be submitted after the proposal vote ends.
func (p *politeiawww) linkByPeriodMin() int64 {
	var (
		submissionPeriod int64 = 604800 // One week in seconds
		blockTime        int64          // In seconds
	)
	switch {
	case p.cfg.TestNet:
		blockTime = int64(testNet3Params.TargetTimePerBlock.Seconds())
	case p.cfg.SimNet:
		blockTime = int64(simNetParams.TargetTimePerBlock.Seconds())
	default:
		blockTime = int64(mainNetParams.TargetTimePerBlock.Seconds())
	}
	return (int64(p.cfg.VoteDurationMin) * blockTime) + submissionPeriod
}

// linkByPeriodMax returns the maximum amount of time, in seconds, that the
// LinkBy period can be set to. 3 months is currently hard coded with no real
// reason for deciding on 3 months besides that it sounds like a sufficient
// amount of time.  This can be changed if there is a valid reason to.
func (p *politeiawww) linkByPeriodMax() int64 {
	return 7776000 // 3 months in seconds
}

// proposalsPluginData fetches the plugin data for the provided proposals using
// the pi proposals plugin command.
func (p *politeiawww) proposalsPluginData(tokens []string) (map[string]piplugin.ProposalPluginData, error) {
	// Setup plugin command
	ps := piplugin.Proposals{
		Tokens: tokens,
	}
	payload, err := piplugin.EncodeProposals(ps)
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        piplugin.ID,
		Command:   piplugin.CmdProposals,
		Payload:   string(payload),
	}

	// Send plugin command
	resBody, err := p.makeRequest(http.MethodPost, pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}
	var pcr pd.PluginCommandReply
	err = json.Unmarshal(resBody, &pcr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pcr.Response)
	if err != nil {
		return nil, err
	}
	pr, err := piplugin.DecodeProposalsReply([]byte(pcr.Payload))
	if err != nil {
		return nil, err
	}

	return pr.Proposals, nil
}

// proposalRecord returns the proposal record for the provided token.
func (p *politeiawww) proposalRecord(token string) (*pi.ProposalRecord, error) {
	// TODO Get politeiad record
	var pr *pi.ProposalRecord

	// Get proposal plugin data
	ppd, err := p.proposalsPluginData([]string{token})
	if err != nil {
		return nil, err
	}
	pd, ok := ppd[token]
	if !ok {
		return nil, fmt.Errorf("proposal plugin data not found %v", token)
	}
	pr.Comments = pd.Comments
	pr.LinkedFrom = pd.LinkedFrom

	// Get user data
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		return nil, err
	}
	pr.UserID = u.ID.String()
	pr.Username = u.Username

	return nil, nil
}

func (p *politeiawww) proposalRecords(tokens []string) (map[string]pi.ProposalRecord, error) {
	// Get politeiad records
	// Get proposals plugin data

	// Get user data

	return nil, nil
}

func (p *politeiawww) verifyProposalMetadata(pm pi.ProposalMetadata) error {
	// Verify name
	if !proposalNameIsValid(pm.Name) {
		return pi.UserError{
			ErrorCode:    pi.ErrorStatusPropNameInvalid,
			ErrorContext: []string{createProposalNameRegex()},
		}
	}

	// Verify linkto
	if pm.LinkTo != "" {
		if !tokenIsValid(pm.LinkTo) {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"invalid token"},
			}
		}
	}

	// Verify linkby
	if pm.LinkBy != 0 {
		min := time.Now().Unix() + p.linkByPeriodMin()
		max := time.Now().Unix() + p.linkByPeriodMax()
		switch {
		case pm.LinkBy < min:
			e := fmt.Sprintf("linkby %v is less than min required of %v",
				pm.LinkBy, min)
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		case pm.LinkBy > max:
			e := fmt.Sprintf("linkby %v is more than max allowed of %v",
				pm.LinkBy, max)
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

func (p *politeiawww) verifyProposal(files []pi.File, metadata []pi.Metadata, publicKey, signature string) (*pi.ProposalMetadata, error) {
	if len(files) == 0 {
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusFileCountInvalid,
			ErrorContext: []string{"no files found"},
		}
	}

	// Verify the files adhere to all policy requirements
	var (
		countTextFiles  int
		countImageFiles int
		foundIndexFile  bool
	)
	filenames := make(map[string]struct{}, len(files))
	for _, v := range files {
		// Validate file name
		_, ok := filenames[v.Name]
		if ok {
			e := fmt.Sprintf("duplicate name %v", v.Name)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileNameInvalid,
				ErrorContext: []string{e},
			}
		}
		filenames[v.Name] = struct{}{}

		// Validate file payload
		if v.Payload == "" {
			e := fmt.Sprintf("file %v empty payload", v.Name)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}
		payloadb, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			e := fmt.Sprintf("file %v invalid base64", v.Name)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}

		// Verify computed file digest matches given file digest
		digest := util.Digest(payloadb)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileDigestInvalid,
				ErrorContext: []string{v.Name},
			}
		}
		if !bytes.Equal(digest, d[:]) {
			e := fmt.Sprintf("file %v digest got %v, want %x",
				v.Name, v.Digest, digest)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileDigestInvalid,
				ErrorContext: []string{e},
			}
		}

		// Verify detected MIME type matches given mime type
		ct := http.DetectContentType(payloadb)
		mimePayload, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return nil, err
		}
		mimeFile, _, err := mime.ParseMediaType(v.MIME)
		if err != nil {
			e := fmt.Sprintf("file %v mime '%v' not parsable", v.Name, v.MIME)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{e},
			}
		}
		if mimeFile != mimePayload {
			e := fmt.Sprintf("file %v mime got %v, want %v",
				v.Name, mimeFile, mimePayload)
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{e},
			}
		}

		// Run MIME type specific validation
		switch mimeFile {
		case mimeTypeText:
			countTextFiles++

			// Verify text file size
			if len(payloadb) > www.PolicyMaxMDSize {
				e := fmt.Sprintf("file %v size %v exceeds max size %v",
					v.Name, len(payloadb), www.PolicyMaxMDSize)
				return nil, pi.UserError{
					ErrorCode:    pi.ErrorStatusIndexFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

			// The only text file that is allowed is the index markdown
			// file.
			if v.Name != www.PolicyIndexFilename {
				e := fmt.Sprint("want %v, got %v", www.PolicyIndexFilename, v.Name)
				return nil, pi.UserError{
					ErrorCode:    pi.ErrorStatusIndexFileNameInvalid,
					ErrorContext: []string{e},
				}
			}
			if foundIndexFile {
				e := fmt.Sprintf("more than one %v file found",
					www.PolicyIndexFilename)
				return nil, pi.UserError{
					ErrorCode:    pi.ErrorStatusIndexFileCountInvalid,
					ErrorContext: []string{e},
				}
			}

			// Set index file as being found
			foundIndexFile = true

		case mimeTypePNG:
			countImageFiles++

			// Verify image file size
			if len(payloadb) > www.PolicyMaxImageSize {
				e := fmt.Sprintf("image %v size %v exceeds max size %v",
					v.Name, len(payloadb), www.PolicyMaxImageSize)
				return nil, pi.UserError{
					ErrorCode:    pi.ErrorStatusImageFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

		default:
			return nil, pi.UserError{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{v.MIME},
			}
		}
	}

	// Verify that an index file is present
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFilename)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusIndexFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify file counts are acceptable
	if countTextFiles > www.PolicyMaxMDs {
		e := fmt.Sprintf("got %v text files, max is %v",
			countTextFiles, www.PolicyMaxMDs)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusTextFileCountInvalid,
			ErrorContext: []string{e},
		}
	}
	if countImageFiles > www.PolicyMaxImages {
		e := fmt.Sprintf("got %v image files, max is %v",
			countImageFiles, www.PolicyMaxImages)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusImageFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify that the metadata contains a ProposalMetadata and only
	// a ProposalMetadata.
	switch {
	case len(metadata) == 0:
		e := fmt.Sprintf("metadata with hint %v not found",
			www.HintProposalMetadata)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataCountInvalid,
			ErrorContext: []string{e},
		}
	case len(metadata) > 1:
		e := fmt.Sprintf("metadata should only contain %v",
			www.HintProposalMetadata)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataCountInvalid,
			ErrorContext: []string{e},
		}
	}
	md := metadata[0]
	if md.Hint != www.HintProposalMetadata {
		e := fmt.Sprintf("unknown metadata hint %v", md.Hint)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataHintInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify metadata fields
	b, err := base64.StdEncoding.DecodeString(md.Payload)
	if err != nil {
		e := fmt.Sprintf("metadata with hint %v invalid base64 payload", md.Hint)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataPayloadInvalid,
			ErrorContext: []string{e},
		}
	}
	digest := util.Digest(b)
	if md.Digest != hex.EncodeToString(digest) {
		e := fmt.Sprintf("metadata with hint %v got digest %v, want %v",
			md.Hint, md.Digest, hex.EncodeToString(digest))
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataDigestInvalid,
			ErrorContext: []string{e},
		}
	}

	// Decode ProposalMetadata
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var pm pi.ProposalMetadata
	err = d.Decode(&pm)
	if err != nil {
		e := fmt.Sprintf("unable to decode %v payload", md.Hint)
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusMetadataPayloadInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify ProposalMetadata
	err = p.verifyProposalMetadata(pm)
	if err != nil {
		return nil, err
	}

	// Verify signature
	mr, err := wwwutil.MerkleRoot(files, metadata)
	if err != nil {
		return nil, err
	}
	err = util.VerifySignature(signature, publicKey, mr)
	if err != nil {
		return nil, convertUserErrFromSignatureErr(err)
	}

	return &pm, nil
}

func (p *politeiawww) processProposalNew(pn pi.ProposalNew, usr user.User) (*pi.ProposalNewReply, error) {
	log.Tracef("processProposalNew: %v", usr.Username)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, pi.UserError{
			ErrorCode: pi.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user has a proposal credit
	if !p.userHasProposalCredits(usr) {
		return nil, pi.UserError{
			ErrorCode: pi.ErrorStatusUserBalanceInsufficient,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != pn.PublicKey {
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not user's active identity"},
		}
	}

	// Verify proposal
	pm, err := p.verifyProposal(pn.Files, pn.Metadata,
		pn.PublicKey, pn.Signature)
	if err != nil {
		return nil, err
	}

	// Setup politeiad files. The Metadata objects are converted to
	// politeiad files instead of metadata streams since they contain
	// user defined data that needs to be included in the merkle root
	// that politeiad signs.
	files := convertFilesFromPi(pn.Files)
	for _, v := range pn.Metadata {
		switch v.Hint {
		case pi.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup metadata stream
	timestamp := time.Now().Unix()
	pg := piplugin.ProposalGeneral{
		PublicKey: pn.PublicKey,
		Signature: pn.Signature,
		Timestamp: timestamp,
	}
	b, err := piplugin.EncodeProposalGeneral(pg)
	if err != nil {
		return nil, err
	}
	metadata := []pd.MetadataStream{
		{
			ID:      piplugin.MDStreamIDProposalGeneral,
			Payload: string(b),
		},
	}

	// Send politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	nr := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata:  metadata,
		Files:     files,
	}
	resBody, err := p.makeRequest(http.MethodPost, pd.NewRecordRoute, nr)
	if err != nil {
		return nil, err
	}
	var nrr pd.NewRecordReply
	err = json.Unmarshal(resBody, &nrr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, nrr.Response)
	if err != nil {
		return nil, err
	}
	cr := convertCensorshipRecordFromPD(nrr.CensorshipRecord)

	// Deduct proposal credit from author's account
	err = p.spendProposalCredit(&usr, cr.Token)
	if err != nil {
		return nil, err
	}

	// Fire off a new proposal event
	p.eventManager.emit(eventProposalSubmitted,
		dataProposalSubmitted{
			token:    cr.Token,
			name:     pm.Name,
			username: usr.Username,
		})

	log.Infof("Proposal submitted: %v %v", cr.Token, pm.Name)
	for k, f := range pn.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	return &pi.ProposalNewReply{
		Timestamp:        timestamp,
		CensorshipRecord: cr,
	}, nil
}

// filesToDel returns the names of the files that are included in current but
// are not included in updated. These are the files that need to be deleted
// from a proposal on update.
func filesToDel(current []pi.File, updated []pi.File) []string {
	curr := make(map[string]struct{}, len(current)) // [name]struct
	for _, v := range updated {
		curr[v.Name] = struct{}{}
	}

	del := make([]string, 0, len(current))
	for _, v := range current {
		_, ok := curr[v.Name]
		if !ok {
			del = append(del, v.Name)
		}
	}

	return del
}

func (p *politeiawww) processProposalEdit(pe pi.ProposalEdit, usr user.User) (*pi.ProposalEditReply, error) {
	log.Tracef("processProposalEdit: %v", pe.Token)

	// Verify user signed using active identity
	if usr.PublicKey() != pe.PublicKey {
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not user's active identity"},
		}
	}

	// Verify proposal
	pm, err := p.verifyProposal(pe.Files, pe.Metadata,
		pe.PublicKey, pe.Signature)
	if err != nil {
		return nil, err
	}

	// Get the current proposal
	if !tokenIsValid(pe.Token) {
		return nil, pi.UserError{
			ErrorCode:    pi.ErrorStatusPropTokenInvalid,
			ErrorContext: []string{pe.Token},
		}
	}
	curr, err := p.proposalRecord(pe.Token)
	if err != nil {
		// TODO pi.ErrorStatusProposalNotFound
		return nil, err
	}

	// Verify the user is the author. The public keys are not static
	// values so the user IDs must be compared directly.
	if curr.UserID != usr.ID.String() {
		return nil, pi.UserError{
			ErrorCode: pi.ErrorStatusUserIsNotAuthor,
		}
	}

	// Setup politeiad files. The Metadata objects are converted to
	// politeiad files instead of metadata streams since they contain
	// user defined data that needs to be included in the merkle root
	// that politeiad signs.
	files := convertFilesFromPi(pe.Files)
	for _, v := range pe.Metadata {
		switch v.Hint {
		case pi.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup metadata stream
	timestamp := time.Now().Unix()
	pg := piplugin.ProposalGeneral{
		PublicKey: pe.PublicKey,
		Signature: pe.Signature,
		Timestamp: timestamp,
	}
	b, err := piplugin.EncodeProposalGeneral(pg)
	if err != nil {
		return nil, err
	}
	metadata := []pd.MetadataStream{
		{
			ID:      piplugin.MDStreamIDProposalGeneral,
			Payload: string(b),
		},
	}

	// Setup politeiad request
	var route string
	switch pe.State {
	case pi.PropStateUnvetted:
		route = pd.UpdateUnvettedRoute
	case pi.PropStateVetted:
		route = pd.UpdateVettedRoute
	default:
		return nil, pi.UserError{
			ErrorCode: pi.ErrorStatusPropStateInvalid,
		}
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	ur := pd.UpdateRecord{
		Token:       pe.Token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: metadata,
		FilesAdd:    files,
		FilesDel:    filesToDel(curr.Files, pe.Files),
	}

	// Send politeiad request
	resBody, err := p.makeRequest(http.MethodPost, route, ur)
	if err != nil {
		// TODO verify that this will throw an error if no proposal files
		// were changed.
		return nil, err
	}
	var urr pd.UpdateRecordReply
	err = json.Unmarshal(resBody, &urr)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, urr.Response)
	if err != nil {
		return nil, err
	}

	// TODO Emit an edit proposal event

	log.Infof("Proposal edited: %v %v", pe.Token, pm.Name)
	for k, f := range pe.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	return &pi.ProposalEditReply{
		// TODO CensorshipRecord: cr,
		Timestamp: timestamp,
	}, nil
}
