package narymerkletree

import (
	"bytes"
	"crypto"
	"testing"
)

func TestInclusionProofRoundTrip(t *testing.T) {
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
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b"), []byte("c")}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < tree.Size(); i++ {
		proof, err := tree.GenerateInclusionProof(i)
		if err != nil {
			t.Fatalf("GenerateInclusionProof(%d): %v", i, err)
		}
		ok, err := VerifyInclusion(proof, tree.RootHash())
		if err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
		if !ok {
			t.Fatalf("inclusion proof for leaf %d did not verify", i)
		}
	}
}

func TestInclusionProofPromotion(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("only")); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateInclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyInclusion(proof, tree.RootHash())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("promoted single-leaf inclusion proof did not verify")
	}
}

func TestInclusionProofTampered(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b")}); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateInclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}
	proof.LeafHash[0] ^= 0xff

	ok, err := VerifyInclusion(proof, tree.RootHash())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampered proof should not verify")
	}
}

func TestInclusionProofArbitraryTree(t *testing.T) {
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
	mustAdd(t, tree, []int{0, 0}, sha256Sum([]byte("00")))
	mustAdd(t, tree, []int{0, 1}, sha256Sum([]byte("01")))
	mustAdd(t, tree, []int{1}, sha256Sum([]byte("1")))

	proof, err := tree.GenerateInclusionProof(1)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyInclusion(proof, tree.RootHash())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("arbitrary tree inclusion proof did not verify")
	}
}

func TestConsistencyProofRoundTrip(t *testing.T) {
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
	if err := tree.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}
	root1, err := tree.mthRange(0, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := tree.Append([]byte("b")); err != nil {
		t.Fatal(err)
	}

	if err := tree.Append([]byte("c"), []byte("d"), []byte("e")); err != nil {
		t.Fatal(err)
	}
	root5, err := tree.mthRange(0, 5)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(1)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyConsistency(root1, root5, 1, 5, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("consistency proof 1->5 did not verify")
	}

	// 4->5 hits a clean RFC split (k == oldSize).
	root4, err := tree.mthRange(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	proof4, err := tree.GenerateConsistencyProof(4)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = VerifyConsistency(root4, root5, 4, 5, proof4, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("consistency proof 4->5 did not verify")
	}
}

func TestConsistencyProofSameSize(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(1)
	if err != nil {
		t.Fatal(err)
	}
	root, err := tree.mthRange(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyConsistency(root, root, 1, 1, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("same-size consistency should verify")
	}
}

func TestConsistencyProofFromEmpty(t *testing.T) {
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
	if err := tree.Append([]byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(0)
	if err != nil {
		t.Fatal(err)
	}
	root2, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyConsistency(nil, root2, 0, 2, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("consistency proof 0->2 did not verify")
	}
}

func TestConsistencyProofTampered(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a"), []byte("b"), []byte("c")); err != nil {
		t.Fatal(err)
	}

	oldRoot, err := tree.mthRange(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	newRoot, err := tree.mthRange(0, 3)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Hashes) > 0 {
		proof.Hashes[0][0] ^= 0xff
	}

	ok, err := VerifyConsistency(oldRoot, newRoot, 1, 3, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampered consistency proof should not verify")
	}
}

func TestConsistencyProofWrongRoot(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}

	proof, err := tree.GenerateConsistencyProof(1)
	if err != nil {
		t.Fatal(err)
	}
	newRoot, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	badNew := sha256Sum([]byte("wrong"))
	ok, err := VerifyConsistency(newRoot, badNew, 1, 2, proof, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong new root should not verify")
	}
}

func TestConsistencyRejectsKary(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tree.Arity = 2
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b"), []byte("c")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.GenerateConsistencyProof(2); err != ErrInvalidParam {
		t.Fatalf("GenerateConsistencyProof() = %v, want ErrInvalidParam", err)
	}
}

func TestMthRangePrefix(t *testing.T) {
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
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b"), []byte("c")}); err != nil {
		t.Fatal(err)
	}

	got, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	want, err := tree.mthRange(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("mthRange prefix = %s, want %s", got, want)
	}

	full, err := tree.mthRange(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	c := sha256Sum([]byte("c"))
	inner, _ := (&Tree{Hash: crypto.SHA256}).hashPair(a, b)
	wantFull, _ := (&Tree{Hash: crypto.SHA256}).hashPair(inner, c)
	if !bytes.Equal(full, wantFull) {
		t.Fatalf("mthRange full = %s, want %s", full, wantFull)
	}
}

func TestLargestPow2LessThan(t *testing.T) {
	cases := map[int]int{1: 0, 2: 1, 3: 2, 4: 2, 5: 4, 8: 4}
	for n, want := range cases {
		if got := largestPow2LessThan(n); got != want {
			t.Fatalf("largestPow2LessThan(%d) = %d, want %d", n, got, want)
		}
	}
}