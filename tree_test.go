package narymerkletree

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cyphrme/coz"
)

func sha256Sum(data []byte) coz.B64 {
	sum := sha256.Sum256(data)
	return coz.B64(sum[:])
}

func TestNewSHA256(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Hash != crypto.SHA256 {
		t.Fatalf("hash = %v, want crypto.SHA256", tree.Hash)
	}
	if got := tree.RootHash(); got != nil {
		t.Fatalf("RootHash() = %s, want nil for empty tree", got)
	}
	if tree.Size() != 0 {
		t.Fatalf("Size() = %d, want 0", tree.Size())
	}
}

func TestSHA256KnownVectors(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		},
		{
			input: "hello",
			want:  "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
		},
	}

	for _, tc := range tests {
		got := sha256Sum([]byte(tc.input))
		want := coz.MustDecode(tc.want)
		if !bytes.Equal(got, want) {
			t.Fatalf("SHA-256(%q) = %s, want %s", tc.input, got, want)
		}
	}
}

func TestAddSortPaths(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	tree.Add([]int{}, sha256Sum([]byte("a")))
	tree.Add([]int{1}, sha256Sum([]byte("c")))
	tree.Add([]int{0}, sha256Sum([]byte("b")))
	tree.Add([]int{0, 1}, sha256Sum([]byte("d")))
	tree.Add([]int{0, 0}, sha256Sum([]byte("e")))
	tree.Sort()

	wantPaths := [][]int{
		{},
		{0},
		{0, 0},
		{0, 1},
		{1},
	}
	if len(tree.Nodes) != len(wantPaths) {
		t.Fatalf("len(Nodes) = %d, want %d", len(tree.Nodes), len(wantPaths))
	}
	for i, want := range wantPaths {
		if !pathsEqual(tree.Nodes[i].Path, want) {
			t.Fatalf("Nodes[%d].Path = %v, want %v", i, tree.Nodes[i].Path, want)
		}
	}
}

func TestMarshalJSONDeterministicSHA256(t *testing.T) {
	tree, err := New(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	tree.Add([]int{1}, sha256Sum([]byte("leaf-1")))
	tree.Add([]int{0}, sha256Sum([]byte("leaf-0")))
	tree.Add([]int{0, 1}, sha256Sum([]byte("leaf-0-1")))

	first, err := tree.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	tree.Sort()
	second, err := tree.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("MarshalJSON not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}

	if strings.Contains(string(first), "=") {
		t.Fatalf("JSON must use b64ut without padding, got: %s", first)
	}

	var decoded Tree
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash != crypto.SHA256 {
		t.Fatalf("decoded.Hash = %v, want crypto.SHA256", decoded.Hash)
	}
	if len(decoded.Nodes) != 3 {
		t.Fatalf("decoded.Nodes len = %d, want 3", len(decoded.Nodes))
	}

	wantDigests := map[string]coz.B64{
		"[0]":    sha256Sum([]byte("leaf-0")),
		"[1]":    sha256Sum([]byte("leaf-1")),
		"[0,1]":  sha256Sum([]byte("leaf-0-1")),
	}
	for _, node := range decoded.Nodes {
		key := pathKey(node.Path)
		want, ok := wantDigests[key]
		if !ok {
			t.Fatalf("unexpected path %v in decoded JSON", node.Path)
		}
		if !bytes.Equal(node.Digest, want) {
			t.Fatalf("digest for %s = %s, want %s", key, node.Digest, want)
		}
	}
}

func pathsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pathKey(path Path) string {
	b, err := json.Marshal(path)
	if err != nil {
		panic(err)
	}
	return string(b)
}