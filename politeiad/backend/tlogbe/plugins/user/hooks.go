// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s user.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = user.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = user.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     user.PluginID,
		ErrorCode:    int(s),
		ErrorContext: e.ErrorContext,
	}
}

// userMetadataDecode decodes and returns the UserMetadata from the provided
// backend metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(metadata []backend.MetadataStream) (*user.UserMetadata, error) {
	var userMD *user.UserMetadata
	for _, v := range metadata {
		if v.ID == user.MDStreamIDUserMetadata {
			var um user.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
			userMD = &um
			break
		}
	}
	return userMD, nil
}

// userMetadataVerify parses a UserMetadata from the metadata streams and
// verifies its contents are valid.
func userMetadataVerify(metadata []backend.MetadataStream, files []backend.File) error {
	// Decode user metadata
	um, err := userMetadataDecode(metadata)
	if err != nil {
		return err
	}
	if um == nil {
		return backend.PluginError{
			PluginID:  user.PluginID,
			ErrorCode: int(user.ErrorCodeUserMetadataNotFound),
		}
	}

	// Verify user ID
	_, err = uuid.Parse(um.UserID)
	if err != nil {
		return backend.PluginError{
			PluginID:  user.PluginID,
			ErrorCode: int(user.ErrorCodeUserIDInvalid),
		}
	}

	// Verify signature
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	m, err := util.MerkleRoot(digests)
	if err != nil {
		return err
	}
	err = util.VerifySignature(um.Signature, um.PublicKey, string(m[:]))
	if err != nil {
		return convertSignatureError(err)
	}

	return nil
}

// userMetadataPreventUpdates errors if the UserMetadata is being updated.
func userMetadataPreventUpdates(current, update []backend.MetadataStream) error {
	// Decode user metadata
	c, err := userMetadataDecode(current)
	if err != nil {
		return err
	}
	u, err := userMetadataDecode(update)
	if err != nil {
		return err
	}

	// Verify user metadata has not changed
	switch {
	case u.UserID != c.UserID:
		e := fmt.Sprintf("user id cannot change: got %v, want %v",
			u.UserID, c.UserID)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeUserIDInvalid),
			ErrorContext: e,
		}

	case u.PublicKey != c.PublicKey:
		e := fmt.Sprintf("public key cannot change: got %v, want %v",
			u.PublicKey, c.PublicKey)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodePublicKeyInvalid),
			ErrorContext: e,
		}

	case c.Signature != c.Signature:
		e := fmt.Sprintf("signature cannot change: got %v, want %v",
			u.Signature, c.Signature)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeSignatureInvalid),
			ErrorContext: e,
		}
	}

	return nil
}

func (p *userPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	return userMetadataVerify(nr.Metadata, nr.Files)
}

func (p *userPlugin) hookNewRecordPost(payload string) error {
	var nr plugins.HookNewRecordPost
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Decode user metadata
	um, err := userMetadataDecode(nr.Metadata)
	if err != nil {
		return err
	}

	// Add token to the user cache
	err = p.userCacheAddToken(um.UserID, nr.RecordMetadata.Token)
	if err != nil {
		return err
	}

	return nil
}

func (p *userPlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify user metadata
	err = userMetadataVerify(er.Metadata, er.Files)
	if err != nil {
		return err
	}

	// Verify user ID has not changed
	um, err := userMetadataDecode(er.Metadata)
	if err != nil {
		return err
	}
	umCurr, err := userMetadataDecode(er.Current.Metadata)
	if err != nil {
		return err
	}
	if um.UserID != umCurr.UserID {
		e := fmt.Sprintf("user id cannot change: got %v, want %v",
			um.UserID, umCurr.UserID)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeUserIDInvalid),
			ErrorContext: e,
		}
	}

	return nil
}

func (p *userPlugin) hookEditMetadataPre(payload string) error {
	var em plugins.HookEditMetadata
	err := json.Unmarshal([]byte(payload), &em)
	if err != nil {
		return err
	}

	// User metadata should not change on metadata updates
	return userMetadataPreventUpdates(em.Current.Metadata, em.Metadata)
}

// statusChangesDecode decodes a []StatusChange from the provided metadata
// streams. If a status change metadata stream is not found, nil is returned.
func statusChangesDecode(metadata []backend.MetadataStream) ([]user.StatusChangeMetadata, error) {
	var statuses []user.StatusChangeMetadata
	for _, v := range metadata {
		if v.ID == user.MDStreamIDUserMetadata {
			d := json.NewDecoder(strings.NewReader(v.Payload))
			for {
				var sc user.StatusChangeMetadata
				err := d.Decode(&sc)
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return nil, err
				}
				statuses = append(statuses, sc)
			}
		}
		break
	}
	return statuses, nil
}

var (
	// statusReasonRequired contains the list of record statuses that
	// require an accompanying reason to be given in the status change.
	statusReasonRequired = map[backend.MDStatusT]struct{}{
		backend.MDStatusCensored: {},
		backend.MDStatusArchived: {},
	}
)

// statusChangeMetadataVerify parses the status change metadata from the
// metadata streams and verifies that its contents are valid.
func statusChangeMetadataVerify(rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Decode status change metadata
	statusChanges, err := statusChangesDecode(metadata)
	if err != nil {
		return err
	}

	// Verify that status change metadata is present
	if len(statusChanges) == 0 {
		return backend.PluginError{
			PluginID:  user.PluginID,
			ErrorCode: int(user.ErrorCodeStatusChangeMetadataNotFound),
		}
	}
	scm := statusChanges[len(statusChanges)-1]

	// Verify token matches
	if scm.Token != rm.Token {
		e := fmt.Sprintf("status change token does not match record "+
			"metadata token: got %v, want %v", scm.Token, rm.Token)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify status matches
	if scm.Status != int(rm.Status) {
		e := fmt.Sprintf("status from metadata does not match status from "+
			"record metadata: got %v, want %v", scm.Status, rm.Status)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeStatusInvalid),
			ErrorContext: e,
		}
	}

	// Verify reason was included on required status changes
	_, ok := statusReasonRequired[rm.Status]
	if ok && scm.Reason == "" {
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeReasonInvalid),
			ErrorContext: "a reason must be given for this status change",
		}
	}

	// Verify signature
	msg := scm.Token + scm.Version + strconv.Itoa(scm.Status) + scm.Reason
	err = util.VerifySignature(scm.Signature, scm.PublicKey, msg)
	if err != nil {
		return convertSignatureError(err)
	}

	return nil
}

func (p *userPlugin) hookSetRecordStatusPre(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// User metadata should not change on status changes
	err = userMetadataPreventUpdates(srs.Current.Metadata, srs.Metadata)
	if err != nil {
		return err
	}

	// Verify status change metadata
	err = statusChangeMetadataVerify(srs.RecordMetadata, srs.Metadata)
	if err != nil {
		return err
	}

	return nil
}
