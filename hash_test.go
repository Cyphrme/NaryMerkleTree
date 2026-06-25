package narymerkletree

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/cyphrme/coz"
)

func mustAdd(t *testing.T, tree *Tree, path []int, digest coz.B64) {
	t.Helper()
	if err := tree.Add(path, digest); err != nil {
		t.Fatal(err)
	}
}

func TestNullDigest(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tree.nullDigest()
	if err != nil {
		t.Fatal(err)
	}
	want := sha256Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("nullDigest() = %s, want %s", got, want)
	}
}

func TestPromotion(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	leaf := sha256Sum([]byte("leaf"))
	mustAdd(t, tree, []int{0}, leaf)

	got := tree.RootHash()
	if !bytes.Equal(got, leaf) {
		t.Fatalf("RootHash() = %s, want promoted leaf %s", got, leaf)
	}
	if tree.Size() != 1 {
		t.Fatalf("Size() = %d, want 1", tree.Size())
	}
}

func TestCollapse(t *testing.T) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = true
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	d := sha256Sum([]byte("same"))
	mustAdd(t, tree, []int{0}, d)
	mustAdd(t, tree, []int{1}, d)

	got := tree.RootHash()
	if !bytes.Equal(got, d) {
		t.Fatalf("RootHash() = %s, want collapsed %s", got, d)
	}
}

func TestConcatOrder(t *testing.T) {
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

	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	mustAdd(t, tree, []int{0}, a)
	mustAdd(t, tree, []int{1}, b)

	var buf []byte
	buf = append(buf, a...)
	buf = append(buf, b...)
	want := sha256Sum(buf)

	got := tree.RootHash()
	if !bytes.Equal(got, want) {
		t.Fatalf("RootHash() = %s, want %s", got, want)
	}
}

func TestArbitraryTree(t *testing.T) {
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

	d00 := sha256Sum([]byte("00"))
	d01 := sha256Sum([]byte("01"))
	d1 := sha256Sum([]byte("1"))
	mustAdd(t, tree, []int{0, 0}, d00)
	mustAdd(t, tree, []int{0, 1}, d01)
	mustAdd(t, tree, []int{1}, d1)

	inner0 := sha256Sum(append(append([]byte{}, d00...), d01...))
	wantRoot := sha256Sum(append(append([]byte{}, inner0...), d1...))

	got := tree.RootHash()
	if !bytes.Equal(got, wantRoot) {
		t.Fatalf("RootHash() = %s, want %s", got, wantRoot)
	}
	if tree.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", tree.Size())
	}

	leaf, err := tree.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if !pathsEqual(leaf.Path, []int{0, 1}) {
		t.Fatalf("Get(1).Path = %v, want [0 1]", leaf.Path)
	}
}

func TestNullChildrenParentNull(t *testing.T) {
	oldPromote := Promote
	Promote = false
	defer func() { Promote = oldPromote }()

	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// Only explicit null leaves; parent should be null.
	mustAdd(t, tree, []int{0}, nil)
	mustAdd(t, tree, []int{1}, nil)

	if tree.RootHash() != nil {
		t.Fatalf("RootHash() = %s, want nil for all-null children", tree.RootHash())
	}
}

func TestRebuildIdempotent(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, tree, []int{0}, sha256Sum([]byte("a")))
	mustAdd(t, tree, []int{1}, sha256Sum([]byte("b")))

	first := append(coz.B64(nil), tree.RootHash()...)
	if err := tree.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tree.RootHash(), first) {
		t.Fatalf("second Rebuild changed root: %s -> %s", first, tree.RootHash())
	}
}

func TestPromoteDisabled(t *testing.T) {
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

	leaf := sha256Sum([]byte("only"))
	mustAdd(t, tree, []int{0}, leaf)

	want := sha256Sum(append([]byte{}, leaf...))
	got := tree.RootHash()
	if !bytes.Equal(got, want) {
		t.Fatalf("RootHash() = %s, want hashed single child %s", got, want)
	}
}