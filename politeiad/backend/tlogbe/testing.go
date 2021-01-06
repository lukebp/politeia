// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/util"
)

func setupTestDataDir(t *testing.T) (string, string, func(s string)) {
	t.Helper()

	testDir, err := ioutil.TempDir("", "tlog.backend.test")
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}

	testDataDir := filepath.Join(testDir, "data")

	return testDir, testDataDir, func(dir string) {
		err = os.RemoveAll(dir)
		if err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
	}
}

func newBackendFile(t *testing.T, fileName string) backend.File {
	t.Helper()

	r, err := util.Random(64)
	if err != nil {
		r = []byte{0, 0, 0} // random byte data
	}

	payload := hex.EncodeToString(r)
	digest := hex.EncodeToString(util.Digest([]byte(payload)))
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))

	return backend.File{
		Name:    fileName,
		MIME:    mime.DetectMimeType([]byte(payload)),
		Digest:  digest,
		Payload: b64,
	}
}

func newBackendFileJPEG(t *testing.T) backend.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	err := jpeg.Encode(b, img, &jpeg.Options{})
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return backend.File{
		Name:    hex.EncodeToString(r) + ".jpeg",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

func newBackendFilePNG(t *testing.T) backend.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	err := png.Encode(b, img)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return backend.File{
		Name:    hex.EncodeToString(r) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

func newBackendMetadataStream(t *testing.T, id uint64, payload string) backend.MetadataStream {
	t.Helper()

	return backend.MetadataStream{
		ID:      id,
		Payload: payload,
	}
}

// newTestTlog returns a tlog used for testing.
func newTestTlog(t *testing.T, dir, id string) (*tlog, error) {
	dir, err := ioutil.TempDir(dir, id)
	if err != nil {
		t.Fatalf("TempDir: %v", err)
	}

	store := filesystem.New(dir)

	tclient, err := newTestTClient(t)
	if err != nil {
		return nil, err
	}

	tlog := tlog{
		id:            id,
		encryptionKey: nil,
		trillian:      tclient,
		store:         store,
	}

	return &tlog, nil
}

// newTestTlogBackend returns a tlog backend for testing. It wraps
// tlog and trillian client, providing the framework needed for
// writing tlog backend tests.
func newTestTlogBackend(t *testing.T, homeDir, dataDir string) (*tlogBackend, error) {
	tlogVetted, err := newTestTlog(t, homeDir, "vetted")
	if err != nil {
		return nil, err
	}
	tlogUnvetted, err := newTestTlog(t, homeDir, "unvetted")
	if err != nil {
		return nil, err
	}

	tlogBackend := tlogBackend{
		homeDir:       homeDir,
		dataDir:       dataDir,
		unvetted:      tlogUnvetted,
		vetted:        tlogVetted,
		plugins:       make(map[string]plugin),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
		inv: recordInventory{
			unvetted: make(map[backend.MDStatusT][]string),
			vetted:   make(map[backend.MDStatusT][]string),
		},
	}

	err = tlogBackend.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &tlogBackend, nil
}

// recordContentTests defines the type used to describe the content
// verification error tests.
type recordContentTest struct {
	description string
	metadata    []backend.MetadataStream
	files       []backend.File
	filesDel    []string
	err         backend.ContentVerificationError
}

// setupRecordContentTests returns the list of tests for the verifyContent
// function. These tests are used on all backend api endpoints that verify
// content.
func setupRecordContentTests(t *testing.T) []recordContentTest {
	t.Helper()

	var rct []recordContentTest

	// Invalid metadata ID error
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, v1.MetadataStreamsMax+1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel := []string{}
	err := backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate metadata ID error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid filename error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "invalid/filename.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid filename error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid filename in filesDel error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{"invalid/filename.md"}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid filename in filesDel error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Empty files error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{}
	fsDel = []string{}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusEmpty,
	}
	rct = append(rct, recordContentTest{
		description: "Empty files error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate filename error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		newBackendFile(t, "index.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate filename error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate filename in filesDel error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{
		"duplicate.md",
		"duplicate.md",
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate filename in filesDel error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid file digest error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFileDigest,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid file digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid base64 error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	f := newBackendFile(t, "index.md")
	f.Payload = "*"
	fs = []backend.File{f}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidBase64,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid file digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid payload digest error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	f = newBackendFile(t, "index.md")
	f.Payload = "rand"
	fs = []backend.File{f}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFileDigest,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid payload digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid MIME type from payload error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	jpeg := newBackendFileJPEG(t)
	jpeg.Payload = "rand"
	payload, er := base64.StdEncoding.DecodeString(jpeg.Payload)
	if er != nil {
		t.Fatalf(er.Error())
	}
	jpeg.Digest = hex.EncodeToString(util.Digest(payload))
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		jpeg,
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidMIMEType,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid MIME type from payload error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Unsupported MIME type error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	jpeg = newBackendFileJPEG(t)
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		jpeg,
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusUnsupportedMIMEType,
	}
	rct = append(rct, recordContentTest{
		description: "Unsupported MIME type error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	return rct
}
