// Package narymerkletree implements a configurable, arbitrarily structured
// n-ary Merkle Tree with inclusion and consistency proofs.
//
// By default functions assume left filled, but the tree may be constructed as
// desired.
//
// Leafs may be interpreted as leafs, or be known as inner nodes by future
// proofs.
//
// Supports
//   - Singleton Promotion (shorthand: "promotion): If a node has only one
//     child, the parent assumes the value of the child without rehashing.
//   - Collapse: if all children are the same value, the parent assumes that
//     value without re-hashing; mostly useful for null values
//   - Null node values (including promotion and collapse). A null parent may
//     only have null children and can never have populated values.
//
// This primitive does not do mutlihash projection.  That may be enforced by a
// parent library.
package narymerkletree

import (
	"crypto"
	"encoding/json"
	"sort"

	"github.com/cyphrme/coz" // imported for base64
)

// Global options
var (
	Promote  = true
	Collapse = true
)

// Path represents a single node with its exact coordinate from the root. This
// is useful for serialization, marshalling, and unmarshalling.
//
// [] is root. [0] is first child of root. [1] is second child of root. [2] is
// the third child of root. [0,0] is the first child of the first child. JSON
// example:
//
//	[
//	 { "path": [],          "digest": "..." }, // Root
//	 { "path": [0],         "digest": "..." }, // First child form root
//	 { "path": [0, 0],      "digest": "..." }, // First child of the first child
//	 { "path": [0, 1],      "digest": "..." }, // Second child of the first child
//	 { "path": [0, 2],      "digest": "..." }, // Third child of the first child
//	 { "path": [1],         "digest": "..." }, // Second child from root
//	 { "path": [1, 0, 2],   "digest": "..." }  // Third child of the first child of the second child from root
//	]
type Path []int

// Null represents an empty value node.
var Null coz.B64

// Node is a tree node (root, internal, or leaf). The hashing algorithm of a
// node is defined by the containing tree. For this library, a node is null when
// Digest == nil.
type Node struct {
	Digest   coz.B64 `json:"digest,omitempty"`
	Children []*Node `json:"-"`              // Nodes are positionally ordered.
	Path     Path    `json:"path,omitempty"` // May be empty
}

// Tree is an n-ary Merkle Tree.
//
// Assumes there is one hash for the whole tree.
type Tree struct {
	Hash  crypto.Hash `json:"hash"`
	Nodes []Node      `json:"nodes,omitempty"` // Nodes includes root at path [].

	// Arity controls append-only leaf placement. 0 or 1 is n-ary: leaves are
	// direct root children [0..n-1]. Values >= 2 fix a static k-ary layout for
	// BuildFromLeaves and Append. Internal fanout at each node is determined by
	// child paths during Rebuild(), not by Arity.
	Arity int `json:"arity,omitempty"`
	// AppendOnly restricts Add to the next append-order leaf path.
	AppendOnly bool `json:"append_only,omitempty"`

	// Derived values; Nodes remains the source of truth.
	leafPaths   []Path     // Left-to-right leaf paths. Empty if uncalculated.
	leafDigests []*coz.B64 // Hashed leaves aligned with leafPaths.

}

// New returns a new empty n-ary Merkle Tree.
func New(h crypto.Hash) (*Tree, error) {
	return &Tree{Hash: h}, nil
}

// Sort sorts the nodes in lexicographical path order.  This makes the output
// deterministic.
func (t *Tree) Sort() {
	sort.Slice(t.Nodes, func(i, j int) bool {
		return comparePaths(t.Nodes[i].Path, t.Nodes[j].Path) < 0
	})
}

// MarshalJSON returns a nicely sorted JSON representation.
func (t *Tree) MarshalJSON() ([]byte, error) {
	t.Sort() // ensure deterministic output
	type alias Tree
	return json.Marshal(alias(*t))
}

// UnmarshalJSON automatically sorts after loading.
func (t *Tree) UnmarshalJSON(data []byte) error {
	type alias Tree
	if err := json.Unmarshal(data, (*alias)(t)); err != nil {
		return err
	}
	t.Sort()
	return t.Rebuild()
}

// comparePaths returns negative if a < b, 0 if equal, positive if a > b
func comparePaths(a, b []int) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return len(a) - len(b)
}

// Add adds a node with its path. Does not check for duplicates.
func (t *Tree) Add(path []int, digest coz.B64) error {
	if t.AppendOnly {
		next, err := t.nextLeafPath()
		if err != nil {
			return err
		}
		if !pathsEqual(Path(path), next) {
			return ErrAppendOnly
		}
	}
	t.Nodes = append(t.Nodes, Node{
		Path:   append([]int(nil), path...), // copy
		Digest: append(coz.B64(nil), digest...),
	})
	return t.Rebuild()
}

// Root returns the current root digest (path [] in Nodes).
func (t *Tree) Root() coz.B64 {
	return t.digestAt(Path{})
}

// Size returns the number of leaves.
func (t *Tree) Size() int {
	return len(t.leafPaths)
}

// Get returns the leaf at index (left-to-right path order).
func (t *Tree) Get(index int) (*Node, error) {
	if index < 0 || index >= len(t.leafPaths) {
		return nil, ErrIndexOutOfRange
	}
	path := t.leafPaths[index]
	return &Node{
		Path:   append(Path(nil), path...),
		Digest: append(coz.B64(nil), t.digestAt(path)...),
	}, nil
}

// Errors
var (
	ErrInvalidParam      = &Error{"invalid parameter"}
	ErrIndexOutOfRange   = &Error{"index out of range"}
	ErrInvalidProof      = &Error{"invalid proof"}
	ErrAppendOnly        = &Error{"append only: path must be next leaf position"}
	ErrAppendRestructure = &Error{"append would restructure k-ary leaf paths"}
)

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
