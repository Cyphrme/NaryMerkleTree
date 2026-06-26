package narymerkletree

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/cyphrme/coz"
)

func TestLeafPathsFlat(t *testing.T) {
	got := leafPaths(3, 0)
	want := []Path{{0}, {1}, {2}}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !pathsEqual(got[i], want[i]) {
			t.Fatalf("leafPaths[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestLeafPathsBinary(t *testing.T) {
	got := leafPaths(3, 2)
	want := []Path{{0, 0}, {0, 1}, {1, 0}}
	for i := range want {
		if !pathsEqual(got[i], want[i]) {
			t.Fatalf("leafPaths[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestBuildFromLeavesFlat(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	if err := tree.BuildFromLeaves(leaves); err != nil {
		t.Fatal(err)
	}

	if tree.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", tree.Size())
	}

	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	wantRoot := sha256Sum(append(append([]byte{}, a...), b...)) // promote off? default promote on
	// With promotion: 3 children at root - no promote (len=3)
	// hash(a||b||c)
	c := sha256Sum([]byte("c"))
	var buf []byte
	buf = append(buf, a...)
	buf = append(buf, b...)
	buf = append(buf, c...)
	wantRoot = sha256Sum(buf)

	if !bytes.Equal(tree.Root(), wantRoot) {
		t.Fatalf("Root() = %s, want %s", tree.Root(), wantRoot)
	}

	leaf, err := tree.Get(2)
	if err != nil {
		t.Fatal(err)
	}
	if !pathsEqual(leaf.Path, Path{2}) {
		t.Fatalf("Get(2).Path = %v, want [2]", leaf.Path)
	}
}

func TestBuildFromLeavesBinary(t *testing.T) {
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
	tree.Arity = 2

	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	if err := tree.BuildFromLeaves(leaves); err != nil {
		t.Fatal(err)
	}

	if tree.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", tree.Size())
	}

	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	c := sha256Sum([]byte("c"))
	inner0 := sha256Sum(append(append([]byte{}, a...), b...))
	inner1 := sha256Sum(append([]byte{}, c...)) // single child under [1], promote off
	wantRoot := sha256Sum(append(append([]byte{}, inner0...), inner1...))

	if !bytes.Equal(tree.Root(), wantRoot) {
		t.Fatalf("Root() = %s, want %s", tree.Root(), wantRoot)
	}
}

func TestAppendFlat(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if err := tree.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("b"), []byte("c")); err != nil {
		t.Fatal(err)
	}

	if tree.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", tree.Size())
	}

	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	c := sha256Sum([]byte("c"))
	var buf []byte
	buf = append(buf, a...)
	buf = append(buf, b...)
	buf = append(buf, c...)
	wantRoot := sha256Sum(buf)

	if !bytes.Equal(tree.Root(), wantRoot) {
		t.Fatalf("Root() = %s, want %s", tree.Root(), wantRoot)
	}
}

func TestAppendBinaryCompatible(t *testing.T) {
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
	tree.Arity = 2

	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	if err := tree.BuildFromLeaves(leaves); err != nil {
		t.Fatal(err)
	}
	root3 := append(coz.B64(nil), tree.Root()...)

	if err := tree.Append([]byte("d")); err != nil {
		t.Fatal(err)
	}

	if tree.Size() != 4 {
		t.Fatalf("Size() = %d, want 4", tree.Size())
	}

	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	c := sha256Sum([]byte("c"))
	d := sha256Sum([]byte("d"))
	inner0 := sha256Sum(append(append([]byte{}, a...), b...))
	inner1 := sha256Sum(append(append([]byte{}, c...), d...))
	wantRoot := sha256Sum(append(append([]byte{}, inner0...), inner1...))

	if !bytes.Equal(tree.Root(), wantRoot) {
		t.Fatalf("Root() = %s, want %s", tree.Root(), wantRoot)
	}
	if bytes.Equal(tree.Root(), root3) {
		t.Fatal("root should change after append")
	}
}

func TestAppendBinaryRestructure(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tree.Arity = 2

	if err := tree.BuildFromLeaves([][]byte{[]byte("a"), []byte("b")}); err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("c")); err != ErrAppendRestructure {
		t.Fatalf("Append() = %v, want ErrAppendRestructure", err)
	}
}

func TestAppendOnlyInsert(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tree.AppendOnly = true

	if err := tree.Insert([]int{0}, sha256Sum([]byte("skip"))); err != ErrAppendOnly {
		t.Fatalf("Insert() = %v, want ErrAppendOnly", err)
	}
	if err := tree.Append([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := tree.Append([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if tree.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", tree.Size())
	}
}