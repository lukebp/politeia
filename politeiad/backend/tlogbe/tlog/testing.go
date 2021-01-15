// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/marcopeereboom/sbox"
)

func newTestTlog(t *testing.T, tlogID, dataDir string, encrypt bool) *Tlog {
	t.Helper()

	// Setup datadir for this tlog instance
	dataDir = filepath.Join(dataDir, tlogID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	// Setup key-value store
	fp := filepath.Join(dataDir, defaultStoreDirname)
	err = os.MkdirAll(fp, 0700)
	if err != nil {
		t.Fatal(err)
	}
	store := filesystem.New(fp)

	// Setup encryptin key if specified
	var ek *encryptionKey
	if encrypt {
		key, err := sbox.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		ek = newEncryptionKey(key)
	}

	return &Tlog{
		id:            tlogID,
		encryptionKey: ek,
		trillian:      newTestTClient(t),
		store:         store,
	}
}

func NewTestTlogEncrypted(t *testing.T, tlogID, dataDir string) *Tlog {
	return newTestTlog(t, tlogID, dataDir, true)
}

func NewTestTlogUnencrypted(t *testing.T, tlogID, dataDir string) *Tlog {
	return newTestTlog(t, tlogID, dataDir, false)
}