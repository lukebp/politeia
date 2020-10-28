package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/sharedconfig"
	"github.com/google/trillian"
)

const (
	defaultTrillianHostUnvetted = "localhost:8090"
	defaultTrillianHostVetted   = "localhost:8094"
	defaultTrillianKeyUnvetted  = "unvetted-trillian.key"
	defaultTrillianKeyVetted    = "vetted-trillian.key"
)

var (
	// Tool setup
	fsStore       store.Blob
	tclient       tlogbe.TrillianClient
	encryptionKey tlogbe.EncryptionKey

	// Config params
	defaultHomeDir = sharedconfig.DefaultHomeDir
	defaultDataDir = filepath.Join(defaultHomeDir,
		sharedconfig.DefaultDataDirname)
	defaultEncryptionKey     = filepath.Join(defaultHomeDir, "tlogbe.key")
	defaultMaxLeavesLength   = 30
	defaultNetworkDirTestnet = "testnet3"
	defaultNetworkDirMainnet = "mainnet"

	// Errors
	errRecordContent = errors.New("Record content not present in any record " +
		"index. This indicates that an update failed, and that this leaf " +
		"is invalid.\n")
	errInputParams = errors.New("Must provide correct input params")

	// Flags
	flagTestnet  = flag.Bool("testnet", false, "Use testnet network")
	flagBlobs    = flag.Bool("blobs", false, "Print leaf blobs")
	flagKey      = flag.String("key", defaultEncryptionKey, "Encryption key")
	flagTrillian = flag.String("trillian", "", "Trillian database name "+
		"(vetted/unvetted)")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiatlog [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  tree <trillian> [treeID]   - Retrieve "+
		"trillian tree\n")
	fmt.Fprintf(os.Stderr, "  leaves <trillian> [treeID] - Retrieve "+
		"trillian tree leaves\n")
	fmt.Fprintf(os.Stderr, "  leavesByRange <trillian> [treeID] "+
		"[startIndex] [count] - Retrieve trillian tree leaves by range\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func printTree(tree *trillian.Tree) {
	fmt.Printf("TreeID        : %v\n", tree.TreeId)
	fmt.Printf("TreeState     : %v\n", tree.TreeState)
	fmt.Printf("TreeType      : %v\n", tree.TreeType)
	fmt.Printf("HashStrategy  : %v\n", tree.HashStrategy)
	fmt.Printf("HashAlgorithm : %v\n", tree.HashAlgorithm)
	fmt.Printf("SignatureAlgo.: %v\n", tree.SignatureAlgorithm)
	fmt.Printf("CreateTime    : %v\n", tree.CreateTime)
	fmt.Printf("UpdateTime    : %v\n", tree.UpdateTime)
	fmt.Printf("Deleted       : %v\n", tree.Deleted)
	fmt.Printf("DeleteTime    : %v\n", tree.DeleteTime)
}

func printLogLeaf(leaf *trillian.LogLeaf) {
	fmt.Println()
	fmt.Printf("MerkleLeafHash: %x\n", leaf.MerkleLeafHash)
	fmt.Printf("LeafValue     : %x\n", leaf.LeafValue)
	fmt.Printf("ExtraData     : %s\n", leaf.ExtraData)
	fmt.Printf("LeafIndex     : %v\n", leaf.LeafIndex)
	fmt.Printf("Timestamp     : %v\n", leaf.IntegrateTimestamp)
}

func printJSON(body interface{}) error {
	// Pretty print the body
	b, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return fmt.Errorf("MarshalIndent: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", b)

	return nil
}

// leavesParse parses the tree leaves to print relevant information.
// This function does the following:
//   1. Fetch blobs from store
//   2. Create merkleHashes map from all record indexes
//   3. Iterate over each leaf doing
//       1. Print log leaf data
//       2. Check if blob exists in store for that leaf hash (orphan?)
//       3. Decode blob
//       4. If record content, check if it's contained in a record index (update failed?)
//       5. Print leaf blob data
func leavesParse(leaves []*trillian.LogLeaf) error {
	// Get blob leaf keys
	keys := make([]string, 0, len(leaves))
	indexes := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		key, err := tlogbe.ExtractKeyFromLeaf(leaf)
		if err != nil {
			return err
		}
		keys = append(keys, key)
		// Save record indexes key separately
		if tlogbe.LeafIsRecordIndex(leaf) {
			indexes = append(indexes, key)
		}
	}

	// Fetch blobs
	blobs, err := fsStore.Get(keys)
	if err != nil {
		return fmt.Errorf("store Get: %v", err)
	}

	// Get record indexes for record content verification. MerkleHashes is used
	// to directly check if a record content's leaf merkle hash is contained
	// in any of the record indexes of the tree. If it is not contained, then
	// a record update happened that wasn't successful, and that did not
	// append the latest record index to the tree, which is the last step of
	// a successful record update.
	merkleHashes := make(map[string]bool)
	for _, key := range indexes {
		be, err := store.Deblob(blobs[key])
		if err != nil {
			return err
		}
		ri, err := tlogbe.ConvertRecordIndexFromBlobEntry(*be)
		if err != nil {
			return err
		}
		// Add record metadata merkle leaf hash
		merkleHashes[hex.EncodeToString(ri.RecordMetadata)] = true
		// Add metadata merkle leaf hashes
		for _, md := range ri.Metadata {
			merkleHashes[hex.EncodeToString(md)] = true
		}
		// Add files merkle leaf hashes
		for _, f := range ri.Files {
			merkleHashes[hex.EncodeToString(f)] = true
		}
	}

	// Iterate over each leaf, deblog it's data from the store and print
	// relevant information
	for _, leaf := range leaves {
		key, err := tlogbe.ExtractKeyFromLeaf(leaf)
		if err != nil {
			return err
		}

		// Print trillian log leaf data
		printLogLeaf(leaf)

		if tlogbe.LeafIsRecordContent(leaf) {
			// Check if this record content leaf is contained in a record index
			_, ok := merkleHashes[hex.EncodeToString(leaf.MerkleLeafHash)]
			if !ok {
				// If it's not, skip blob data and print error
				fmt.Println(errRecordContent)
				continue
			}
		}

		// Sanity checks for leaf blob
		blob, ok := blobs[key]
		if !ok {
			// Leaf is orphan, no blob exists in store
			fmt.Println("No blob exists in store for this leaf. It is " +
				"considered an orphan leaf.")
			if !tlogbe.LeafIsRecordContent(leaf) {
				// Orphan leaf is not a record content
				return fmt.Errorf("This leaf is not a record content and is " +
					"orphaned. Something went wrong.")
			}
			continue
		}

		if !*flagBlobs {
			continue
		}

		// Decode blob
		if tlogbe.BlobIsEncrypted(blob) {
			blob, _, err = encryptionKey.Decrypt(blob)
			if err != nil {
				return err
			}
		}
		be, err := store.Deblob(blob)
		if err != nil {
			return err
		}

		// Decode data hint and data descriptor
		b, err := base64.StdEncoding.DecodeString(be.DataHint)
		if err != nil {
			return err
		}
		var dd store.DataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return err
		}

		fmt.Printf("Descriptor    : %v\n", dd.Descriptor)

		// Print blob data
		d, err := base64.StdEncoding.DecodeString(be.Data)
		if err != nil {
			return err
		}
		switch dd.Descriptor {
		case tlogbe.DataDescriptorRecordMetadata:
			var rm backend.RecordMetadata
			err = json.Unmarshal(d, &rm)
			if err != nil {
				return err
			}
			printJSON(rm)
		case tlogbe.DataDescriptorMetadataStream:
			var ms backend.MetadataStream
			err = json.Unmarshal(d, &ms)
			if err != nil {
				return err
			}
			printJSON(ms)
		case tlogbe.DataDescriptorFile:
			var f backend.File
			err = json.Unmarshal(d, &f)
			if err != nil {
				return err
			}
			// Clean field
			f.Payload = "removed by politeiatlog for readability"
			printJSON(f)
		case tlogbe.DataDescriptorAnchor:
			var anchor tlogbe.Anchor
			err = json.Unmarshal(d, &anchor)
			if err != nil {
				return err
			}
			// Clean field
			anchor.VerifyDigest.ChainInformation.MerklePath.Hashes = nil
			printJSON(anchor)
		case tlogbe.DataDescriptorRecordIndex:
			var ri tlogbe.RecordIndex
			err = json.Unmarshal(d, &ri)
			if err != nil {
				return err
			}
			printJSON(ri)
		case tlogbe.DataDescriptorFreezeRecord:
		case tlogbe.DataDescriptorCommentAdd:
			var c comments.CommentAdd
			err = json.Unmarshal(d, &c)
			if err != nil {
				return err
			}
			printJSON(c)
		case tlogbe.DataDescriptorCommentDel:
			var c comments.CommentDel
			err = json.Unmarshal(d, &c)
			if err != nil {
				return err
			}
			printJSON(c)
		case tlogbe.DataDescriptorCommentVote:
			var c comments.CommentVote
			err = json.Unmarshal(d, &c)
			if err != nil {
				return err
			}
			printJSON(c)
		case tlogbe.DataDescriptorAuthorizeDetails:
			var ad ticketvote.AuthorizeDetails
			err = json.Unmarshal(b, &ad)
			if err != nil {
				return err
			}
			printJSON(ad)
		case tlogbe.DataDescriptorVoteDetails:
			var vd ticketvote.VoteDetails
			err = json.Unmarshal(b, &vd)
			if err != nil {
				return err
			}
			// Clean field
			vd.EligibleTickets = nil
			printJSON(vd)
		case tlogbe.DataDescriptorCastVoteDetails:
			var cvd ticketvote.CastVoteDetails
			err = json.Unmarshal(b, &cvd)
			if err != nil {
				return err
			}
			printJSON(cvd)
		default:
			fmt.Printf("Unknown data descriptor %v\n", dd.Descriptor)
		}
	}

	return nil
}

func tree() error {
	args := flag.Args()[1:] // Args without action
	if len(args) != 1 {
		usage()
		return errInputParams
	}

	treeID, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}

	tree, err := tclient.Tree(treeID)
	if err != nil {
		return fmt.Errorf("Tree ID %v not found on %v database",
			treeID, *flagTrillian)
	}

	printTree(tree)

	return nil
}

func leavesAll() error {
	args := flag.Args()[1:] // Args without action
	if len(args) != 1 {
		usage()
		return errInputParams
	}

	treeID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}

	leaves, err := tclient.LeavesAll(treeID)
	if err != nil {
		return err
	}

	// Prompt user to proceed with printing if tree has many leaves
	if len(leaves) > defaultMaxLeavesLength {
		fmt.Printf("There is a total of %d leaves. Are you sure you want"+
			" to proceed? (yes/no) (y/n)\n", len(leaves))
		t, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if t != "y" && t != "yes" {
			return nil
		}
	}

	err = leavesParse(leaves)
	if err != nil {
		return err
	}

	return nil
}

func leavesByRange() error {
	args := flag.Args()[1:] // Args without action
	if len(args) != 3 {
		usage()
		return errInputParams
	}

	treeID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}
	startIndex, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	count, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return err
	}

	leaves, err := tclient.LeavesByRange(treeID, startIndex, count)
	if err != nil {
		return err
	}

	// Prompt user to proceed with printing if tree has many leaves
	if len(leaves) > defaultMaxLeavesLength {
		fmt.Printf("There is a total of %d leaves. Are you sure you want"+
			" to proceed? (yes/no) (y/n)\n", len(leaves))
		t, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if t != "y" && t != "yes" {
			return nil
		}
	}

	err = leavesParse(leaves)
	if err != nil {
		return err
	}

	return nil
}

func _main() error {
	flag.Parse()
	args := flag.Args()

	// Validate arguments
	switch {
	case len(args) == 0:
		usage()
		return fmt.Errorf("Must provide command action")
	case *flagTrillian == "":
		usage()
		return fmt.Errorf("Must provide the trillian database name")
	case *flagKey == "":
		usage()
		return fmt.Errorf("Must provide the encryption key path")
	}

	// Set encryption key
	f, err := os.Open(*flagKey)
	if err != nil {
		return err
	}
	var k [32]byte
	n, err := f.Read(k[:])
	if err != nil {
		return err
	}
	if n != len(k) {
		return fmt.Errorf("Invalid encryption key length")
	}
	f.Close()
	encryptionKey = *tlogbe.NewEncryptionKey(&k)

	// Set tlog client
	var host, key string
	switch *flagTrillian {
	case "unvetted":
		host = defaultTrillianHostUnvetted
		key = filepath.Join(defaultHomeDir, defaultTrillianKeyUnvetted)
	case "vetted":
		host = defaultTrillianHostVetted
		key = filepath.Join(defaultHomeDir, defaultTrillianKeyVetted)
	default:
		usage()
		return fmt.Errorf("Invalid database name")
	}
	tc, err := tlogbe.NewTrillianClient(host, key)
	if err != nil {
		return err
	}
	tclient = *tc

	// Set store (assuming filesystem)
	network := defaultNetworkDirMainnet
	if *flagTestnet {
		network = defaultNetworkDirTestnet
	}
	fp := filepath.Join(defaultDataDir, network, *flagTrillian)
	fsStore = &fileSystem{
		root: fp,
	}

	// Parse action
	switch args[0] {
	case "tree":
		return tree()
	case "leaves":
		return leavesAll()
	case "leavesByRange":
		return leavesByRange()
	default:
		usage()
		return fmt.Errorf("Must choose a valid action")
	}
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
