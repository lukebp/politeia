// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"errors"
	"testing"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

func TestNewRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the New endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err := tlogBackend.New(test.metadata, test.files)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						contentError.Error(),
						test.err.Error())
				}
			}
		})
	}

	// Test success case
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	_, err = tlogBackend.New(md, fs)
	if err != nil {
		t.Errorf("success case failed with %v", err)
	}
}

func TestUpdateUnvettedRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		t.Error(err)
	}

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateUnvettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := util.ConvertStringToken(rec.Token)
			if err != nil {
				t.Error(err)
			}

			// Make backend call
			_, err = tlogBackend.UpdateUnvettedRecord(token, test.metadata,
				[]backend.MetadataStream{}, test.files, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						contentError.Error(),
						test.err.Error())
				}
			}
		})
	}

	// Random png image file to include in edit payload
	imageRandom := newBackendFilePNG(t)

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	err = tlogBackend.unvetted.treeFreeze(treeIDFromToken(tokenFrozen),
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateUnvettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{},
			[]string{},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.UpdateUnvettedRecord(test.token,
				test.mdAppend, test.mdOverwrite, test.filesAdd, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						contentError.Error(),
						test.wantContentErr.Error())
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateVettedRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		t.Error(err)
	}

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, backend.MetadataStream{
		ID:      2,
		Payload: "",
	})

	// Publish the created record
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateVettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := util.ConvertStringToken(rec.Token)
			if err != nil {
				t.Error(err)
			}

			// Make backend call
			_, err = tlogBackend.UpdateVettedRecord(token, test.metadata,
				[]backend.MetadataStream{}, test.files, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						contentError.Error(),
						test.err.Error())
				}
			}
		})
	}

	// Random png image file to include in edit payload
	imageRandom := newBackendFilePNG(t)

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, backend.MetadataStream{
		ID:      3,
		Payload: "",
	})
	err = tlogBackend.unvettedPublish(tokenFrozen, *recFrozen, md, fs)
	if err != nil {
		t.Error(err)
	}
	treeIDFrozenVetted := tlogBackend.vettedTreeIDs[recFrozen.Token]
	err = tlogBackend.vetted.treeFreeze(treeIDFrozenVetted,
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateVettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwirte []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{},
			[]string{},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.UpdateVettedRecord(test.token,
				test.mdAppend, test.mdOverwirte, test.filesAdd, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						contentError.Error(),
						test.wantContentErr.Error())
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}
