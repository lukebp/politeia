// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/robfig/cron"
	"google.golang.org/grpc/codes"
)

const (
	// Blob entry data descriptors
	dataDescriptorFile           = "file"
	dataDescriptorRecordMetadata = "recordmetadata"
	dataDescriptorMetadataStream = "metadatastream"
	dataDescriptorRecordIndex    = "recordindex"
	dataDescriptorFreezeRecord   = "freezerecord"
	dataDescriptorAnchor         = "anchor"

	// The keys for kv store blobs are saved by stuffing them into the
	// ExtraData field of their corresponding trillian log leaf. The
	// keys are prefixed with one of the follwing identifiers before
	// being added to the log leaf so that we can correlate the leaf
	// to the type of data it represents without having to pull the
	// data out of the store, which can become an issue in situations
	// such as searching for a record index that has been buried by
	// thousands of leaves from plugin data.
	keyPrefixRecordIndex   = "recordindex:"
	keyPrefixRecordContent = "record:"
	keyPrefixFreezeRecord  = "freeze:"
	keyPrefixAnchorRecord  = "anchor:"
)

var (
	// errRecordNotFound is emitted when a record is not found. This
	// can be because a tree does not exists for the provided tree id
	// or when a tree does exist but the specified record version does
	// not exist.
	errRecordNotFound = errors.New("record not found")

	// errNoFileChanges is emitted when there are no files being
	// changed.
	errNoFileChanges = errors.New("no file changes")

	// errNoMetadataChanges is emitted when there are no metadata
	// changes being made.
	errNoMetadataChanges = errors.New("no metadata changes")

	// errFreezeRecordNotFound is emitted when a freeze record does not
	// exist for a tree.
	errFreezeRecordNotFound = errors.New("freeze record not found")

	// errTreeIsFrozen is emitted when a frozen tree is attempted to be
	// altered.
	errTreeIsFrozen = errors.New("tree is frozen")
)

// We do not unwind.
type tlog struct {
	sync.Mutex
	// TODO shutdown      bool
	id            string
	dataDir       string
	encryptionKey *encryptionKey
	trillian      *trillianClient
	store         store.Blob_
	dcrtimeHost   string
	cron          *cron.Cron

	// droppingAnchor indicates whether tlog is in the process of
	// dropping an anchor, i.e. timestamping unanchored trillian trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool
}

// recordIndex contains the merkle leaf hashes of all the record content for a
// specific record version and iteration. The record index can be used to
// lookup the trillian log leaves for the record content. The ExtraData field
// of each log leaf contains the key-value store key for the record content
// data blob.
//
// Appending the record index leaf to the trillian tree is the last operation
// that occurs when updating a record, so if a record index leaf exists then
// the record update is considered valid and you can be sure that the data
// blobs were successfully saved to the key-value store.
type recordIndex struct {
	// Version represents the version of the record. The version is
	// only incremented when the record files are updated.
	Version uint32 `json:"version"`

	// Iteration represents the iteration of the record. The iteration
	// is incremented anytime any record content changes. This includes
	// file changes that bump the version as well metadata stream and
	// record metadata changes that don't bump the version.
	//
	// Note this is not the same as the RecordMetadata iteration field,
	// which does not get incremented on metadata updates.
	Iteration uint32 `json:"iteration"`

	// The following fields contain the merkle leaf hashes of the
	// trillian log leaves for the record content. The merkle leaf hash
	// can be used to lookup the log leaf. The log leaf ExtraData field
	// contains the key for the record content in the key-value store.
	RecordMetadata []byte            `json:"recordmetadata"`
	Metadata       map[uint64][]byte `json:"metadata"` // [metadataID]merkle
	Files          map[string][]byte `json:"files"`    // [filename]merkle
}

func treeIDFromToken(token []byte) int64 {
	return int64(binary.LittleEndian.Uint64(token))
}

func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	// Converting between int64 and uint64 doesn't change the sign bit,
	// only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

// blobIsEncrypted returns whether the provided blob has been prefixed with an
// sbox header, indicating that it is an encrypted blob.
func blobIsEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}

// treeIsFrozen deterimes if the tree is frozen given the full list of the
// tree's leaves. A tree is considered frozen if the last leaf on the tree
// corresponds to a freeze record.
func treeIsFrozen(leaves []*trillian.LogLeaf) bool {
	return leafIsFreezeRecord(leaves[len(leaves)-1])
}

func leafIsRecordIndex(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixRecordIndex))
}

func leafIsRecordContent(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixRecordContent))
}

func leafIsFreezeRecord(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixFreezeRecord))
}

func leafIsAnchorRecord(l *trillian.LogLeaf) bool {
	return bytes.HasPrefix(l.ExtraData, []byte(keyPrefixAnchorRecord))
}

func extractKeyFromLeaf(l *trillian.LogLeaf) (string, error) {
	s := bytes.SplitAfter(l.ExtraData, []byte(":"))
	if len(s) != 2 {
		return "", fmt.Errorf("invalid key %s", l.ExtraData)
	}
	return string(s[1]), nil
}

func convertBlobEntryFromFile(f backend.File) (*store.BlobEntry, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorFile,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromMetadataStream(ms backend.MetadataStream) (*store.BlobEntry, error) {
	data, err := json.Marshal(ms)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorMetadataStream,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromRecordMetadata(rm backend.RecordMetadata) (*store.BlobEntry, error) {
	data, err := json.Marshal(rm)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorRecordMetadata,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromRecordIndex(ri recordIndex) (*store.BlobEntry, error) {
	data, err := json.Marshal(ri)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorRecordIndex,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromFreezeRecord(fr freezeRecord) (*store.BlobEntry, error) {
	data, err := json.Marshal(fr)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorFreezeRecord,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromAnchor(a anchor) (*store.BlobEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAnchor,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertFreezeRecordFromBlobEntry(be store.BlobEntry) (*freezeRecord, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorFreezeRecord {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorFreezeRecord)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var fr freezeRecord
	err = json.Unmarshal(b, &fr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal freezeRecord: %v", err)
	}

	return &fr, nil
}

func convertRecordIndexFromBlobEntry(be store.BlobEntry) (*recordIndex, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorRecordIndex {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorRecordIndex)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var ri recordIndex
	err = json.Unmarshal(b, &ri)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordIndex: %v", err)
	}

	return &ri, nil
}

func (t *tlog) treeNew() (int64, error) {
	tree, _, err := t.trillian.treeNew()
	if err != nil {
		return 0, err
	}
	return tree.TreeId, nil
}

func (t *tlog) treeExists(treeID int64) bool {
	_, err := t.trillian.tree(treeID)
	if err == nil {
		return true
	}
	return false
}

type freezeRecord struct {
	TreeID int64 `json:"treeid,omitempty"`
}

// treeFreeze freezes the trillian tree for the provided token. Once a tree
// has been frozen it is no longer able to be appended to. The last leaf in a
// frozen tree will correspond to a freeze record in the key-value store. A
// tree is frozen when the status of the corresponding record is updated to a
// status that locks the record, such as when a record is censored.
//
// It's possible for this function to fail in between the append leaves call
// and the call that updates the tree status to frozen. If this happens the
// freeze record will still be the last leaf on the tree but the tree state
// will not be frozen. The tree is still considered frozen and no new leaves
// should be appended to it. The tree state will be updated in the next fsck.
// Functions that append new leaves onto the tree MUST ensure that the last
// leaf does not contain a freeze record.
func (t *tlog) treeFreeze(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, fr freezeRecord) error {
	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll: %v", err)
	}

	// Prepare kv store blobs for metadata
	args := recordBlobsPrepareArgs{
		encryptionKey: t.encryptionKey,
		leaves:        leavesAll,
		recordMD:      rm,
		metadata:      metadata,
	}
	rbpr, err := recordBlobsPrepare(args)
	if err != nil {
		return err
	}

	// Ensure metadata has been changed
	if len(rbpr.blobs) == 0 {
		return errNoMetadataChanges
	}

	// Save metadata blobs
	idx, err := t.recordBlobsSave(treeID, *rbpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and add the unchanged fields to
	// the new record index. The version and files will remain the
	// same.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version
	idx.Files = oldIdx.Files

	// Increment the iteration
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check. The record index should be fully populated at this
	// point.
	switch {
	case idx.Version != oldIdx.Version:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version)
	case idx.Version != oldIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(oldIdx.Files):
		return fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(oldIdx.Files))
	}

	// Blobify the record index and freeze record
	blobs := make([][]byte, 0, 2)
	be, err := convertBlobEntryFromRecordIndex(*idx)
	if err != nil {
		return err
	}
	idxHash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}
	blobs = append(blobs, b)

	be, err = convertBlobEntryFromFreezeRecord(fr)
	if err != nil {
		return err
	}
	freezeRecordHash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err = store.Blobify(*be)
	if err != nil {
		return err
	}
	blobs = append(blobs, b)

	// Save record index and freeze record blobs to the store
	keys, err := t.store.Put(blobs)
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 2 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Append record index and freeze record leaves to trillian tree
	leaves := []*trillian.LogLeaf{
		logLeafNew(idxHash, []byte(keyPrefixRecordIndex+keys[0])),
		logLeafNew(freezeRecordHash, []byte(keyPrefixFreezeRecord+keys[1])),
	}
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if len(queued) != 2 {
		return fmt.Errorf("wrong number of queud leaves: got %v, want 2",
			len(queued))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("append leaves failed: %v", failed)
	}

	// Update tree status to frozen
	_, err = t.trillian.treeFreeze(treeID)
	if err != nil {
		return fmt.Errorf("treeFreeze: %v", err)
	}

	return nil
}

// lastLeaf returns the last leaf of the given trillian tree.
func (t *tlog) lastLeaf(treeID int64) (*trillian.LogLeaf, error) {
	tree, err := t.trillian.tree(treeID)
	if err != nil {
		return nil, errRecordNotFound
	}
	_, lr, err := t.trillian.signedLogRootForTree(tree)
	if err != nil {
		return nil, fmt.Errorf("signedLogRootForTree: %v", err)
	}
	leaves, err := t.trillian.leavesByRange(treeID, int64(lr.TreeSize)-1, 1)
	if err != nil {
		return nil, fmt.Errorf("leavesByRange: %v", err)
	}
	if len(leaves) != 1 {
		return nil, fmt.Errorf("unexpected leaves count: got %v, want 1",
			len(leaves))
	}
	return leaves[0], nil
}

// freeze record returns the freeze record of the provided tree if one exists.
// If one does not exists a errFreezeRecordNotFound error is returned.
func (t *tlog) freezeRecord(treeID int64) (*freezeRecord, error) {
	// Check if the last leaf of the tree is a freeze record
	l, err := t.lastLeaf(treeID)
	if err != nil {
		return nil, fmt.Errorf("lastLeaf %v: %v", treeID, err)
	}
	if !leafIsFreezeRecord(l) {
		// Leaf is not a freeze record
		return nil, errFreezeRecordNotFound
	}

	// The leaf is a freeze record. Get it from the store.
	k, err := extractKeyFromLeaf(l)
	if err != nil {
		return nil, err
	}
	blobs, err := t.store.Get([]string{k})
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != 1 {
		return nil, fmt.Errorf("unexpected blobs count: got %v, want 1",
			len(blobs))
	}

	// Decode freeze record
	b, ok := blobs[k]
	if !ok {
		return nil, fmt.Errorf("blob not found %v", k)
	}
	be, err := store.Deblob(b)
	if err != nil {
		return nil, err
	}
	fr, err := convertFreezeRecordFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return fr, nil
}

func (t *tlog) recordIndexSave(treeID int64, ri recordIndex) error {
	// Save record index to the store
	be, err := convertBlobEntryFromRecordIndex(ri)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}
	keys, err := t.store.Put([][]byte{b})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Append record index leaf to trillian tree
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	prefixedKey := []byte(keyPrefixRecordIndex + keys[0])
	queued, _, err := t.trillian.leavesAppend(treeID, []*trillian.LogLeaf{
		logLeafNew(h, prefixedKey),
	})
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queud leaves: got %v, want 1",
			len(queued))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("append leaves failed: %v", failed)
	}

	return nil
}

func (t *tlog) recordIndexVersion(leaves []*trillian.LogLeaf, version uint32) (*recordIndex, error) {
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return nil, err
	}

	// Return the record index for the specified version
	var ri *recordIndex
	if version == 0 {
		// A version of 0 indicates that the most recent version should
		// be returned.
		ri = &indexes[len(indexes)-1]
	} else {
		// Walk the indexes backwards so the most recent iteration of the
		// specified version is selected.
		for i := len(indexes) - 1; i >= 0; i-- {
			r := indexes[i]
			if r.Version == version {
				ri = &r
				break
			}
		}
	}
	if ri == nil {
		// The specified version does not exist
		return nil, errRecordNotFound
	}

	return ri, nil
}

func (t *tlog) recordIndexLatest(leaves []*trillian.LogLeaf) (*recordIndex, error) {
	return t.recordIndexVersion(leaves, 0)
}

func (t *tlog) recordIndexes(leaves []*trillian.LogLeaf) ([]recordIndex, error) {
	// Walk the leaves and compile the keys for all record indexes. It
	// is possible for multiple indexes to exist for the same record
	// version (they will have different iterations due to metadata
	// only updates) so we have to pull the index blobs from the store
	// in order to find the most recent iteration for the specified
	// version.
	keys := make([]string, 0, 64)
	for _, v := range leaves {
		if leafIsRecordIndex(v) {
			// This is a record index leaf. Extract they kv store key.
			k, err := extractKeyFromLeaf(v)
			if err != nil {
				return nil, err
			}
			keys = append(keys, k)
		}
	}

	if len(keys) == 0 {
		// No records have been added to this tree yet
		return nil, errRecordNotFound
	}

	// Get record indexes from store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	missing := make([]string, 0, len(keys))
	for _, v := range keys {
		if _, ok := blobs[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("record index not found: %v", missing)
	}

	indexes := make([]recordIndex, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		ri, err := convertRecordIndexFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		indexes = append(indexes, *ri)
	}

	// Sanity check. Index iterations should start with 1 and be
	// sequential. Index versions should start with 1 and also be
	// sequential, but duplicate versions can exist as long as the
	// iteration has been incremented.
	var versionPrev uint32
	var i uint32 = 1
	for _, v := range indexes {
		if v.Iteration != i {
			return nil, fmt.Errorf("invalid record index iteration: "+
				"got %v, want %v", v.Iteration, i)
		}
		diff := v.Version - versionPrev
		if diff != 0 && diff != 1 {
			return nil, fmt.Errorf("invalid record index version: "+
				"curr version %v, prev version %v", v.Version, versionPrev)
		}

		i++
		versionPrev = v.Version
	}

	return indexes, nil
}

type recordHashes struct {
	recordMetadata string            // Record metadata hash
	metadata       map[string]uint64 // [hash]metadataID
	files          map[string]string // [hash]filename
}

type recordBlobsPrepareArgs struct {
	encryptionKey *encryptionKey
	leaves        []*trillian.LogLeaf
	recordMD      backend.RecordMetadata
	metadata      []backend.MetadataStream
	files         []backend.File
}

type recordBlobsPrepareReply struct {
	recordIndex  recordIndex
	recordHashes recordHashes

	// blobs and hashes MUST share the same ordering
	blobs  [][]byte
	hashes [][]byte
}

// TODO test this function
func recordBlobsPrepare(args recordBlobsPrepareArgs) (*recordBlobsPrepareReply, error) {
	// Ensure tree is not frozen. A tree is considered frozen if the
	// last leaf on the tree is a freeze record.
	lastLeaf := args.leaves[len(args.leaves)-1]
	if leafIsFreezeRecord(lastLeaf) {
		return nil, errTreeIsFrozen
	}

	// Check if any of the content already exists. Different record
	// versions that reference the same data is fine, but this data
	// should not be saved to the store again. We can find duplicates
	// by walking the trillian tree and comparing the hash of the
	// provided record content to the log leaf data, which will be the
	// same for duplicates.

	// Compute record content hashes
	rhashes := recordHashes{
		metadata: make(map[string]uint64, len(args.metadata)),
		files:    make(map[string]string, len(args.files)),
	}
	b, err := json.Marshal(args.recordMD)
	if err != nil {
		return nil, err
	}
	rhashes.recordMetadata = hex.EncodeToString(util.Digest(b))
	for _, v := range args.metadata {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.metadata[h] = v.ID
	}
	for _, v := range args.files {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		h := hex.EncodeToString(util.Digest(b))
		rhashes.files[h] = v.Name
	}

	// Compare leaf data to record content hashes to find duplicates
	var (
		// Dups tracks duplicates so we know which blobs should be
		// skipped when saving the blob to the store.
		dups = make(map[string]struct{}, 64)

		// Any duplicates that are found are added to the record index
		// since we already have the leaf data for them.
		index = recordIndex{
			Metadata: make(map[uint64][]byte, len(args.metadata)),
			Files:    make(map[string][]byte, len(args.files)),
		}
	)
	for _, v := range args.leaves {
		h := hex.EncodeToString(v.LeafValue)

		// Check record metadata
		if h == rhashes.recordMetadata {
			dups[h] = struct{}{}
			index.RecordMetadata = v.MerkleLeafHash
			continue
		}

		// Check metadata streams
		id, ok := rhashes.metadata[h]
		if ok {
			dups[h] = struct{}{}
			index.Metadata[id] = v.MerkleLeafHash
			continue
		}

		// Check files
		fn, ok := rhashes.files[h]
		if ok {
			dups[h] = struct{}{}
			index.Files[fn] = v.MerkleLeafHash
			continue
		}
	}

	// Prepare kv store blobs. The hashes of the record content are
	// also aggregated and will be used to create the log leaves that
	// are appended to the trillian tree.
	l := len(args.metadata) + len(args.files) + 1
	hashes := make([][]byte, 0, l)
	blobs := make([][]byte, 0, l)
	be, err := convertBlobEntryFromRecordMetadata(args.recordMD)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	b, err = store.Blobify(*be)
	if err != nil {
		return nil, err
	}
	_, ok := dups[be.Hash]
	if !ok {
		// Not a duplicate. Save blob to the store.
		hashes = append(hashes, h)
		blobs = append(blobs, b)
	}

	for _, v := range args.metadata {
		be, err := convertBlobEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Hash)
		if err != nil {
			return nil, err
		}
		b, err := store.Blobify(*be)
		if err != nil {
			return nil, err
		}
		_, ok := dups[be.Hash]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	for _, v := range args.files {
		be, err := convertBlobEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(be.Hash)
		if err != nil {
			return nil, err
		}
		b, err := store.Blobify(*be)
		if err != nil {
			return nil, err
		}
		// Encypt file blobs if encryption key has been set
		if args.encryptionKey != nil {
			b, err = args.encryptionKey.encrypt(0, b)
			if err != nil {
				return nil, err
			}
		}
		_, ok := dups[be.Hash]
		if !ok {
			// Not a duplicate. Save blob to the store.
			hashes = append(hashes, h)
			blobs = append(blobs, b)
		}
	}

	return &recordBlobsPrepareReply{
		recordIndex:  index,
		recordHashes: rhashes,
		blobs:        blobs,
		hashes:       hashes,
	}, nil
}

func (t *tlog) recordBlobsSave(treeID int64, rbpr recordBlobsPrepareReply) (*recordIndex, error) {
	var (
		index   = rbpr.recordIndex
		rhashes = rbpr.recordHashes
		blobs   = rbpr.blobs
		hashes  = rbpr.hashes
	)

	// Save blobs to store
	keys, err := t.store.Put(blobs)
	if err != nil {
		return nil, fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != len(blobs) {
		return nil, fmt.Errorf("wrong number of keys: got %v, want %v",
			len(keys), len(blobs))
	}

	// Prepare log leaves. hashes and keys share the same ordering.
	leaves := make([]*trillian.LogLeaf, 0, len(blobs))
	for k := range blobs {
		pk := []byte(keyPrefixRecordContent + keys[k])
		leaves = append(leaves, logLeafNew(hashes[k], pk))
	}

	// Append leaves to trillian tree
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if err != nil {
		return nil, fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != len(leaves) {
		return nil, fmt.Errorf("wrong number of queued leaves: got %v, want %v",
			len(queued), len(leaves))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return nil, fmt.Errorf("append leaves failed: %v", failed)
	}

	// Update the new record index with the log leaves
	for _, v := range queued {
		// Figure out what piece of record content this leaf represents
		h := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)

		// Check record metadata
		if h == rhashes.recordMetadata {
			index.RecordMetadata = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Check metadata streams
		id, ok := rhashes.metadata[h]
		if ok {
			index.Metadata[id] = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Check files
		fn, ok := rhashes.files[h]
		if ok {
			index.Files[fn] = v.QueuedLeaf.Leaf.MerkleLeafHash
			continue
		}

		// Something went wrong. None of the record content matches the
		// leaf.
		return nil, fmt.Errorf("record content does not match leaf: %x",
			v.QueuedLeaf.Leaf.MerkleLeafHash)
	}

	return &index, nil
}

// We do not unwind.
func (t *tlog) recordSave(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return errRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll %v: %v", treeID, err)
	}

	// Ensure tree is not frozen
	if treeIsFrozen(leavesAll) {
		return errTreeIsFrozen
	}

	// Prepare kv store blobs
	args := recordBlobsPrepareArgs{
		encryptionKey: t.encryptionKey,
		leaves:        leavesAll,
		recordMD:      rm,
		metadata:      metadata,
		files:         files,
	}
	rbpr, err := recordBlobsPrepare(args)
	if err != nil {
		return err
	}

	// Ensure file changes are being made
	if len(rbpr.recordIndex.Files) == len(files) {
		return errNoFileChanges
	}

	// Save blobs
	idx, err := t.recordBlobsSave(treeID, *rbpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and use it to bump the version and
	// iteration of the new record index.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err == errRecordNotFound {
		// No record versions exist yet. This is fine. The version and
		// iteration will be incremented to 1.
	} else if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version + 1
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check. The record index should be fully populated at this
	// point.
	switch {
	case idx.Version != oldIdx.Version+1:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version+1)
	case idx.Iteration != oldIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(files):
		return fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(files))
	}

	// Save record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

func (t *tlog) recordMetadataUpdate(treeID int64, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return errRecordNotFound
	}

	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return fmt.Errorf("leavesAll: %v", err)
	}

	// Ensure tree is not frozen
	if treeIsFrozen(leavesAll) {
		return errTreeIsFrozen
	}

	// Prepare kv store blobs
	args := recordBlobsPrepareArgs{
		encryptionKey: t.encryptionKey,
		leaves:        leavesAll,
		recordMD:      rm,
		metadata:      metadata,
	}
	bpr, err := recordBlobsPrepare(args)
	if err != nil {
		return err
	}

	// Ensure metadata has been changed
	if len(bpr.blobs) == 0 {
		return errNoMetadataChanges
	}

	// Save the blobs
	idx, err := t.recordBlobsSave(treeID, *bpr)
	if err != nil {
		return fmt.Errorf("blobsSave: %v", err)
	}

	// Get the existing record index and add the unchanged fields to
	// the new record index. The version and files will remain the
	// same.
	oldIdx, err := t.recordIndexLatest(leavesAll)
	if err != nil {
		return fmt.Errorf("recordIndexLatest: %v", err)
	}
	idx.Version = oldIdx.Version
	idx.Files = oldIdx.Files

	// Increment the iteration
	idx.Iteration = oldIdx.Iteration + 1

	// Sanity check. The record index should be fully populated at this
	// point.
	switch {
	case idx.Version != oldIdx.Version:
		return fmt.Errorf("invalid index version: got %v, want %v",
			idx.Version, oldIdx.Version)
	case idx.Version != oldIdx.Iteration+1:
		return fmt.Errorf("invalid index iteration: got %v, want %v",
			idx.Iteration, oldIdx.Iteration+1)
	case idx.RecordMetadata == nil:
		return fmt.Errorf("invalid index record metadata")
	case len(idx.Metadata) != len(metadata):
		return fmt.Errorf("invalid index metadata: got %v, want %v",
			len(idx.Metadata), len(metadata))
	case len(idx.Files) != len(oldIdx.Files):
		return fmt.Errorf("invalid index files: got %v, want %v",
			len(idx.Files), len(oldIdx.Files))
	}

	// Save record index
	err = t.recordIndexSave(treeID, *idx)
	if err != nil {
		return fmt.Errorf("recordIndexSave: %v", err)
	}

	return nil
}

// recordDel walks the provided tree and deletes all blobs in the store that
// correspond to record files. This is done for all versions of the record.
func (t *tlog) recordDel(treeID int64) error {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return errRecordNotFound
	}

	// Get all tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return err
	}

	// Ensure tree is frozen. Deleting files from the store is only
	// allowed on frozen trees.
	if treeIsFrozen(leaves) {
		return errTreeIsFrozen
	}

	// Retrieve all the record indexes
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return fmt.Errorf("recordIndexes: %v", err)
	}

	// Aggregate the keys for all file blobs of all versions. The
	// record index points to the log leaf merkle leaf hash. The log
	// leaf contains the kv store key.
	merkles := make(map[string]struct{}, len(leaves))
	for _, v := range indexes {
		for _, merkle := range v.Files {
			merkles[hex.EncodeToString(merkle)] = struct{}{}
		}
	}
	keys := make([]string, 0, len(merkles))
	for _, v := range leaves {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if ok {
			key, err := extractKeyFromLeaf(v)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
	}

	// Delete file blobs from the store
	err = t.store.Del(keys)
	if err != nil {
		return fmt.Errorf("store Del: %v", err)
	}

	return nil
}

func (t *tlog) recordVersion(treeID int64, version uint32) (*backend.Record, error) {
	// Ensure tree exists
	if !t.treeExists(treeID) {
		return nil, errRecordNotFound
	}

	// Get tree leaves
	leaves, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll %v: %v", treeID, err)
	}

	// Get the record index for the specified version
	index, err := t.recordIndexVersion(leaves, version)
	if err != nil {
		return nil, err
	}

	// Use the record index to pull the record content from the store.
	// The keys for the record content first need to be extracted from
	// their associated log leaf.

	// Compile merkle root hashes of record content
	merkles := make(map[string]struct{}, 64)
	merkles[hex.EncodeToString(index.RecordMetadata)] = struct{}{}
	for _, v := range index.Metadata {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}
	for _, v := range index.Files {
		merkles[hex.EncodeToString(v)] = struct{}{}
	}

	// Walk the tree and extract the record content keys
	keys := make([]string, 0, len(index.Metadata)+len(index.Files)+1)
	for _, v := range leaves {
		_, ok := merkles[hex.EncodeToString(v.MerkleLeafHash)]
		if !ok {
			// Not part of the record content
			continue
		}

		// Leaf is part of record content. Extract the kv store key.
		key, err := extractKeyFromLeaf(v)
		if err != nil {
			return nil, fmt.Errorf("extractKeyForRecordContent %x",
				v.MerkleLeafHash)
		}

		keys = append(keys, key)
	}

	// Get record content from store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != len(keys) {
		// One or more blobs were not found
		missing := make([]string, 0, len(keys))
		for _, v := range keys {
			_, ok := blobs[v]
			if !ok {
				missing = append(missing, v)
			}
		}
		return nil, fmt.Errorf("blobs not found: %v", missing)
	}

	// Decode blobs
	entries := make([]store.BlobEntry, 0, len(keys))
	for _, v := range blobs {
		var be *store.BlobEntry
		if t.encryptionKey != nil && blobIsEncrypted(v) {
			v, _, err = t.encryptionKey.decrypt(v)
			if err != nil {
				return nil, err
			}
		}
		be, err := store.Deblob(v)
		if err != nil {
			// Check if this is an encrypted blob that was not decrypted
			if t.encryptionKey == nil && blobIsEncrypted(v) {
				return nil, fmt.Errorf("blob is encrypted but no encryption " +
					"key found to decrypt blob")
			}
			return nil, err
		}
		entries = append(entries, *be)
	}

	// Decode blob entries
	var (
		recordMD *backend.RecordMetadata
		metadata = make([]backend.MetadataStream, 0, len(index.Metadata))
		files    = make([]backend.File, 0, len(index.Files))
	)
	for _, v := range entries {
		// Decode the data hint
		b, err := base64.StdEncoding.DecodeString(v.DataHint)
		if err != nil {
			return nil, fmt.Errorf("decode DataHint: %v", err)
		}
		var dd store.DataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return nil, fmt.Errorf("unmarshal DataHint: %v", err)
		}
		if dd.Type != store.DataTypeStructure {
			return nil, fmt.Errorf("invalid data type; got %v, want %v",
				dd.Type, store.DataTypeStructure)
		}

		// Decode the data
		b, err = base64.StdEncoding.DecodeString(v.Data)
		if err != nil {
			return nil, fmt.Errorf("decode Data: %v", err)
		}
		hash, err := hex.DecodeString(v.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode Hash: %v", err)
		}
		if !bytes.Equal(util.Digest(b), hash) {
			return nil, fmt.Errorf("data is not coherent; got %x, want %x",
				util.Digest(b), hash)
		}
		switch dd.Descriptor {
		case dataDescriptorRecordMetadata:
			var rm backend.RecordMetadata
			err = json.Unmarshal(b, &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal RecordMetadata: %v", err)
			}
			recordMD = &rm
		case dataDescriptorMetadataStream:
			var ms backend.MetadataStream
			err = json.Unmarshal(b, &ms)
			if err != nil {
				return nil, fmt.Errorf("unmarshal MetadataStream: %v", err)
			}
			metadata = append(metadata, ms)
		case dataDescriptorFile:
			var f backend.File
			err = json.Unmarshal(b, &f)
			if err != nil {
				return nil, fmt.Errorf("unmarshal File: %v", err)
			}
			files = append(files, f)
		default:
			return nil, fmt.Errorf("invalid descriptor %v", dd.Descriptor)
		}
	}

	// Sanity checks
	switch {
	case recordMD == nil:
		return nil, fmt.Errorf("record metadata not found")
	case len(metadata) != len(index.Metadata):
		return nil, fmt.Errorf("invalid number of metadata; got %v, want %v",
			len(metadata), len(index.Metadata))
	case len(files) != len(index.Files):
		return nil, fmt.Errorf("invalid number of files; got %v, want %v",
			len(files), len(index.Files))
	}

	return &backend.Record{
		Version:        strconv.FormatUint(uint64(version), 10),
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}, nil
}

func (t *tlog) recordLatest(treeID int64) (*backend.Record, error) {
	return t.recordVersion(treeID, 0)
}

func (t *tlog) recordProof(treeID int64, version uint32) {}

func (t *tlog) fsck() {
	// Failed freeze
	// Failed censor
}

func (t *tlog) close() {
	// Close connections
	t.store.Close()
	t.trillian.close()

	// Zero out encryption key
	if t.encryptionKey != nil {
		t.encryptionKey.Zero()
	}
}

func tlogNew() (*tlog, error) {
	return &tlog{}, nil
}