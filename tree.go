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

	"github.com/cyphrme/coz" // imported for base64
)

// Package-level hashing options. Both default to true.
var (
	// Promote enables singleton promotion: a parent with one child inherits
	// the child's effective digest without rehashing.
	Promote = true
	// Collapse enables collapse: when all children share the same effective
	// digest, the parent inherits it without rehashing.
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
	Children []*Node `json:"-"`              // Ephemeral; used during Rebuild and proofs.
	Path     Path    `json:"path,omitempty"` // May be empty
}

// Tree is an n-ary Merkle Tree.
//
// Assumes there is one hash for the whole tree.
type Tree struct {
	Hash crypto.Hash `json:"hash"`
	// Nodes is keyed by pathKey(path). JSON marshals as a sorted array of nodes.
	Nodes map[string]Node `json:"-"`

	// Arity controls append-only leaf placement. 0 or 1 is n-ary: leaves are
	// direct root children [0..n-1]. Values >= 2 fix a static k-ary layout for
	// BuildFromLeaves and Append. Internal fanout at each node is determined by
	// child paths during Rebuild(), not by Arity.
	Arity int `json:"arity,omitempty"`
	// AppendOnly forbids Insert; new leaves must be added via Append.
	AppendOnly bool `json:"append_only,omitempty"`

	// Derived values; Nodes remains the source of truth.
	leafPaths   []Path     // Left-to-right leaf paths. Empty if uncalculated.
	leafDigests []*coz.B64 // Hashed leaves aligned with leafPaths.
}

// New returns a new empty n-ary Merkle Tree.
func New(h crypto.Hash) (*Tree, error) {
	return &Tree{Hash: h}, nil
}

// Root returns the current root digest (path [] in Nodes).
func (t *Tree) Root() coz.B64 {
	return t.digestAt(Path{})
}

// LeafCount returns the number of leaves.
func (t *Tree) LeafCount() int {
	return len(t.leafPaths)
}

// NodeCount returns the number of nodes stored in the tree (leaves and internals).
func (t *Tree) NodeCount() int {
	if t.Nodes == nil {
		return 0
	}
	return len(t.Nodes)
}

// GetLeaf returns the leaf at index in left-to-right path order.
func (t *Tree) GetLeaf(index int) (*Node, error) {
	if index < 0 || index >= len(t.leafPaths) {
		return nil, ErrIndexOutOfRange
	}
	path := t.leafPaths[index]
	return &Node{
		Path:   append(Path(nil), path...),
		Digest: append(coz.B64(nil), t.digestAt(path)...),
	}, nil
}

// Insert adds a node at an arbitrary path. Returns ErrDuplicatePath if the path
// exists. Returns ErrAppendOnly when the tree is append-only (use Append).
func (t *Tree) Insert(path []int, digest coz.B64) error {
	if t.AppendOnly {
		return ErrAppendOnly
	}
	return t.insertAt(Path(path), digest)
}

// storeNode records a node digest at path without rebuilding derived state.
func (t *Tree) storeNode(path Path, digest coz.B64) error {
	if t.Nodes == nil {
		t.Nodes = make(map[string]Node)
	}
	key := pathKey(path)
	if _, ok := t.Nodes[key]; ok {
		return ErrDuplicatePath
	}
	t.Nodes[key] = Node{
		Path:   append(Path(nil), path...),
		Digest: append(coz.B64(nil), digest...),
	}
	return nil
}

// insertAt adds a node at path and rebuilds the tree.
func (t *Tree) insertAt(path Path, digest coz.B64) error {
	if err := t.storeNode(path, digest); err != nil {
		return err
	}
	return t.Rebuild()
}

// comparePaths lexicographically compares paths. Returns negative if a < b,
// zero if equal, positive if a > b.
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

// Errors
var (
	ErrInvalidParam      = &Error{"invalid parameter"}
	ErrIndexOutOfRange   = &Error{"index out of range"}
	ErrInvalidProof      = &Error{"invalid proof"}
	ErrDuplicatePath     = &Error{"duplicate path"}
	ErrAppendOnly        = &Error{"append only: use Append, not Insert"}
	ErrAppendRestructure = &Error{"append would restructure k-ary leaf paths"}
)

// Error is a package-level sentinel error value.
type Error struct{ msg string }

// Error returns the error message.
func (e *Error) Error() string { return e.msg }
