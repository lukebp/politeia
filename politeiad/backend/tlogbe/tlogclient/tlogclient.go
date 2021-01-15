// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogclient

import (
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

// Client provides an API for the plugins to interact with a tlog instance.
// Plugins are allowed to save, delete, and get plugin data to/from the tlog
// backend. Editing plugin data is not allowed.
type Client interface {
	// BlobSave saves a BlobEntry to the tlog backend. The BlobEntry
	// will be encrypted prior to being written to disk if the tlog
	// instance has an encryption key set. The merkle leaf hash for the
	// blob will be returned. This merkle leaf hash can be though of as
	// the blob ID and can be used to retrieve or delete the blob.
	BlobSave(treeID int64, keyPrefix string, be store.BlobEntry) ([]byte, error)

	// BlobsDel deletes the blobs that correspond to the provided
	// merkle leaf hashes.
	BlobsDel(treeID int64, merkles [][]byte) error

	// BlobsByMerkle returns the blobs with the provided merkle leaf
	// hashes. If a blob does not exist it will not be included in the
	// returned map.
	BlobsByMerkle(treeID int64, merkles [][]byte) (map[string][]byte, error)

	// BlobsByKeyPrefix returns all blobs that match the key prefix.
	BlobsByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error)

	// MerklesByKeyPrefix returns the merkle leaf hashes for all blobs
	// that match the key prefix.
	MerklesByKeyPrefix(treeID int64, keyPrefix string) ([][]byte, error)

	// Timestamp returns the timestamp for the blob that correpsonds
	// to the merkle leaf hash.
	Timestamp(treeID int64, merkle []byte) (*backend.Timestamp, error)
}
