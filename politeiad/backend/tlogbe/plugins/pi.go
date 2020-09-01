// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/plugins/pi"
	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
)

const (
	// Filenames of memoized data saved to the data dir.
	filenameLinkedFrom = "{token}-linkedfrom.json"
)

var (
	_ tlogbe.Plugin = (*piPlugin)(nil)
)

// piPlugin satisfies the Plugin interface.
type piPlugin struct {
	sync.Mutex
	backend *tlogbe.TlogBackend

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

func isRFP(pm pi.ProposalMetadata) bool {
	return pm.LinkBy != 0
}

// proposalMetadataFromFiles parses and returns the ProposalMetadata from the
// provided files. If a ProposalMetadata is not found, nil is returned.
func proposalMetadataFromFiles(files []backend.File) (*pi.ProposalMetadata, error) {
	var pm *pi.ProposalMetadata
	for _, v := range files {
		if v.Name == pi.FilenameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			pm, err = pi.DecodeProposalMetadata(b)
			if err != nil {
				return nil, err
			}
		}
	}
	return pm, nil
}

// TODO saving the proposalLinkedFrom to the filesystem is not scalable between
// multiple politeiad instances. The plugin needs to have a tree that can be
// used to share state between the different politeiad instances.

// proposalLinkedFrom is the the structure that is updated and cached for
// proposal A when proposal B links to proposal A. The list contains all
// proposals that have linked to proposal A. The linked from list will only
// contain public proposals.
//
// Example: an RFP proposal's linked from list will contain all public RFP
// submissions since they have all linked to the RFP proposal.
type proposalLinkedFrom struct {
	Tokens map[string]struct{} `json:"tokens"`
}

func (p *piPlugin) cachedLinkedFromPath(token string) string {
	fn := strings.Replace(filenameLinkedFrom, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn)
}

// This function must be called WITH the lock held.
func (p *piPlugin) cachedLinkedFromLocked(token string) (*proposalLinkedFrom, error) {
	fp := p.cachedLinkedFromPath(token)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist
			return nil, errRecordNotFound
		}
	}

	var plf proposalLinkedFrom
	err = json.Unmarshal(b, &plf)
	if err != nil {
		return nil, err
	}

	return &plf, nil
}

func (p *piPlugin) cachedLinkedFrom(token string) (*proposalLinkedFrom, error) {
	p.Lock()
	defer p.Unlock()

	return p.cachedLinkedFromLocked(token)
}

func (p *piPlugin) cachedLinkedFromAdd(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	plf, err := p.cachedLinkedFromLocked(parentToken)
	if err == errRecordNotFound {
		// List doesn't exist. Create a new one.
		plf = &proposalLinkedFrom{
			Tokens: make(map[string]struct{}, 0),
		}
	} else if err != nil {
		return fmt.Errorf("cachedLinkedFromLocked %v: %v", parentToken, err)
	}

	// Update list
	plf.Tokens[childToken] = struct{}{}

	// Save list
	b, err := json.Marshal(plf)
	if err != nil {
		return err
	}
	fp := p.cachedLinkedFromPath(parentToken)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}

	return nil
}

func (p *piPlugin) cachedLinkedFromDel(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	plf, err := p.cachedLinkedFromLocked(parentToken)
	if err != nil {
		return fmt.Errorf("cachedLinkedFromLocked %v: %v", parentToken, err)
	}

	// Update list
	delete(plf.Tokens, childToken)

	// Save list
	b, err := json.Marshal(plf)
	if err != nil {
		return err
	}
	fp := p.cachedLinkedFromPath(parentToken)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}

	return nil
}

func (p *piPlugin) Setup() error {
	log.Tracef("pi Setup")

	return nil
}

func (p *piPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("pi Cmd: %v %v", cmd, payload)

	return "", nil
}

func (p *piPlugin) hookNewRecordPre(payload string) error {
	nrp, err := tlogbe.DecodeNewRecordPre([]byte(payload))
	if err != nil {
		return err
	}

	// Decode ProposalMetadata
	var pm *pi.ProposalMetadata
	for _, v := range nrp.Files {
		if v.Name == pi.FilenameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			pm, err = pi.DecodeProposalMetadata(b)
			if err != nil {
				return err
			}
			break
		}
	}
	if pm == nil {
		return fmt.Errorf("proposal metadata not found")
	}

	// Verify the linkto is an RFP and that the RFP is eligible to be
	// linked to. We currently only allow linking to RFP proposals that
	// have been approved by a ticket vote.
	if pm.LinkTo != "" {
		if isRFP(*pm) {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"an rfp cannot have linkto set"},
			}
		}
		tokenb, err := hex.DecodeString(pm.LinkTo)
		if err != nil {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"invalid hex"},
			}
		}
		r, err := p.backend.GetVetted(tokenb, "")
		if err != nil {
			if err == backend.ErrRecordNotFound {
				return pi.UserError{
					ErrorCode:    pi.ErrorStatusLinkToInvalid,
					ErrorContext: []string{"proposal not found"},
				}
			}
			return err
		}
		linkToPM, err := proposalMetadataFromFiles(r.Files)
		if err != nil {
			return err
		}
		if linkToPM == nil {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if !isRFP(*linkToPM) {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if time.Now().Unix() > linkToPM.LinkBy {
			// Link by deadline has expired. New links are not allowed.
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"rfp link by deadline expired"},
			}
		}
		s := ticketvote.Summaries{
			Tokens: []string{pm.LinkTo},
		}
		b, err := ticketvote.EncodeSummaries(s)
		if err != nil {
			return err
		}
		reply, err := p.backend.Plugin(ticketvote.ID,
			ticketvote.CmdSummaries, string(b))
		if err != nil {
			return fmt.Errorf("Plugin %v %v: %v",
				ticketvote.ID, ticketvote.CmdSummaries, err)
		}
		sr, err := ticketvote.DecodeSummariesReply([]byte(reply))
		if err != nil {
			return err
		}
		summary, ok := sr.Summaries[pm.LinkTo]
		if !ok {
			return fmt.Errorf("summary not found %v", pm.LinkTo)
		}
		if !summary.Approved {
			return pi.UserError{
				ErrorCode:    pi.ErrorStatusLinkToInvalid,
				ErrorContext: []string{"rfp vote not approved"},
			}
		}
	}

	return nil
}

func (p *piPlugin) hookSetRecordStatusPost(payload string) error {
	srsp, err := tlogbe.DecodeSetRecordStatusPost([]byte(payload))
	if err != nil {
		return err
	}

	// If the LinkTo field has been set then the proposalLinkedFrom
	// list might need to be updated for the proposal that is being
	// linked to, depending on the status change that is being made.
	pm, err := proposalMetadataFromFiles(srsp.Record.Files)
	if err != nil {
		return err
	}
	if pm != nil && pm.LinkTo != "" {
		// Link from has been set. Check if the status change requires
		// the parent proposal's linked from list to be updated.
		var (
			parentToken = pm.LinkTo
			childToken  = srsp.RecordMetadata.Token
		)
		switch srsp.RecordMetadata.Status {
		case backend.MDStatusVetted:
			// Proposal has been made public. Add child token to parent
			// token's linked from list.
			err := p.cachedLinkedFromAdd(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("cachedLinkedFromAdd: %v", err)
			}
		case backend.MDStatusCensored:
			// Proposal has been censored. Delete child token from parent
			// token's linked from list.
			err := p.cachedLinkedFromDel(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("cachedLinkedFromDel: %v", err)
			}
		}
	}

	return nil
}

func (p *piPlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("pi Hook: %v", tlogbe.Hooks[h])

	switch h {
	case tlogbe.HookNewRecordPre:
		return p.hookNewRecordPre(payload)
	case tlogbe.HookSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

func (p *piPlugin) Fsck() error {
	log.Tracef("pi Fsck")

	// proposalLinkedFrom cache

	return nil
}

func NewPiPlugin(backend *tlogbe.TlogBackend, settings []backend.PluginSetting) *piPlugin {
	// TODO these should be passed in as plugin settings
	var (
		dataDir string
	)
	return &piPlugin{
		dataDir: dataDir,
		backend: backend,
	}
}
