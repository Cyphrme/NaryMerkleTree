package narymerkletree

import (
	"crypto"
	"fmt"
)

func ExampleTree_Append() {
	tree, err := New(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	if err := tree.Append([]byte("commit-1"), []byte("commit-2")); err != nil {
		panic(err)
	}
	fmt.Println(tree.LeafCount())
	// Output: 2
}

func ExampleTree_GenerateInclusionProof() {
	tree, err := New(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b")}); err != nil {
		panic(err)
	}

	proof, err := tree.GenerateInclusionProof(0)
	if err != nil {
		panic(err)
	}
	ok, err := VerifyInclusion(proof, tree.Root())
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output: true
}

func ExampleVerifyConsistency() {
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
		panic(err)
	}
	if err := tree.Append([]byte("a")); err != nil {
		panic(err)
	}
	rootA, err := tree.mthRange(0, 1)
	if err != nil {
		panic(err)
	}

	if err := tree.Append([]byte("b"), []byte("c")); err != nil {
		panic(err)
	}
	rootB, err := tree.mthRange(0, 3)
	if err != nil {
		panic(err)
	}

	proof, err := tree.GenerateConsistencyProof(1)
	if err != nil {
		panic(err)
	}
	ok, err := VerifyConsistency(rootA, rootB, 1, 3, proof, crypto.SHA256)
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output: true
}