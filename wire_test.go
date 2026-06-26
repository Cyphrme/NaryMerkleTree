package narymerkletree

import (
	"bytes"
	"crypto"
	"encoding/json"
	"testing"
)

func TestInclusionProofJSONRoundTrip(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b"), []byte("c")}); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateInclusionProof(1)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}

	var decoded InclusionProof
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyInclusion(&decoded, tree.Root())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("decoded inclusion proof did not verify")
	}
}

func TestConsistencyProofJSONRoundTrip(t *testing.T) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = false
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a"), []byte("b"), []byte("c"), []byte("d")); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(2)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ConsistencyProof
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OldSize != proof.OldSize {
		t.Fatalf("OldSize = %d, want %d", decoded.OldSize, proof.OldSize)
	}
	if len(decoded.Hashes) != len(proof.Hashes) {
		t.Fatalf("len(Hashes) = %d, want %d", len(decoded.Hashes), len(proof.Hashes))
	}

	root2, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	root4, err := tree.mthRange(0, 4)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyConsistency(root2, root4, 2, 4, &decoded, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("decoded consistency proof did not verify")
	}
}

func TestUnmarshalDuplicatePath(t *testing.T) {
	raw := `{
		"hash": 5,
		"nodes": [
			{"path": [0], "digest": "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"},
			{"path": [0], "digest": "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"}
		]
	}`

	var tree Tree
	if err := json.Unmarshal([]byte(raw), &tree); err != ErrDuplicatePath {
		t.Fatalf("UnmarshalJSON() = %v, want ErrDuplicatePath", err)
	}
}

func TestNodeCount(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if tree.NodeCount() != 0 {
		t.Fatalf("NodeCount() = %d, want 0", tree.NodeCount())
	}
	if tree.LeafCount() != 0 {
		t.Fatalf("LeafCount() = %d, want 0", tree.LeafCount())
	}

	if err := tree.Insert([]int{0}, sha256Sum([]byte("a"))); err != nil {
		t.Fatal(err)
	}
	if tree.LeafCount() != 1 {
		t.Fatalf("LeafCount() = %d, want 1", tree.LeafCount())
	}
	if tree.NodeCount() != 2 {
		t.Fatalf("NodeCount() = %d, want 2 (leaf + root)", tree.NodeCount())
	}
}

func TestAppendBatchEquivalence(t *testing.T) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = false
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	oneByOne, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")} {
		if err := oneByOne.Append(leaf); err != nil {
			t.Fatal(err)
		}
	}

	batch, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := batch.Append(
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"),
	); err != nil {
		t.Fatal(err)
	}

	if oneByOne.LeafCount() != batch.LeafCount() {
		t.Fatalf("LeafCount mismatch: %d vs %d", oneByOne.LeafCount(), batch.LeafCount())
	}
	if !bytes.Equal(oneByOne.Root(), batch.Root()) {
		t.Fatalf("Root mismatch:\n one-by-one: %s\n batch: %s", oneByOne.Root(), batch.Root())
	}
}

func TestHashPairNullCases(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	got, err := tree.hashPair(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("hashPair(nil,nil) = %s, want nil", got)
	}

	right := sha256Sum([]byte("r"))
	got, err = tree.hashPair(nil, right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, right) {
		t.Fatalf("hashPair(nil,right) = %s, want %s", got, right)
	}

	left := sha256Sum([]byte("l"))
	got, err = tree.hashPair(left, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, left) {
		t.Fatalf("hashPair(left,nil) = %s, want %s", got, left)
	}
}

func TestConsistencyProofIntermediateSize(t *testing.T) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = false
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")); err != nil {
		t.Fatal(err)
	}

	root2, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	root5, err := tree.mthRange(0, 5)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(2)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyConsistency(root2, root5, 2, 5, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("consistency proof 2->5 did not verify")
	}
}

func TestGetLeafOutOfRange(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.GetLeaf(-1); err != ErrIndexOutOfRange {
		t.Fatalf("GetLeaf(-1) = %v, want ErrIndexOutOfRange", err)
	}
	if _, err := tree.GetLeaf(1); err != ErrIndexOutOfRange {
		t.Fatalf("GetLeaf(1) = %v, want ErrIndexOutOfRange", err)
	}
}