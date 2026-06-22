// Package narymerkletree implements a configurable, arbitrarily structured
// n-ary Merkle Tree with inclusion and consistency proofs.
//
// Supports
//   - Singleton Promotion - If a node has only one child, the parent assumes the
//     value of the child without rehashing.
//   - Collapse (if all children are the same value, the parent assumes that value
//     without re-hashing; mostly useful for null values)
//   - Null node values.
package narymerkletree

var (
	Promote  = true
	Collapse = true
)

// Null represents an absent leaf value.
var Null = []byte{} // distinct from any valid hash

// Node is a tree node (root, internal, or leaf). The hashing algorithm of a
// node is defined by the containing tree.  A node is null when Digest == nil.
type Node struct {
	Digest   []byte
	Children []*Node
}

// HashFunc computes a cryptographic hash of the input.
type HashFunc func([]byte) ([]byte, error)

// Tree is an n-ary Merkle Tree (n >= 2).
type Tree struct {
	Root     *Node
	Arity    int // Arity may be unknown.
	HashFunc HashFunc
	leaves   []*byte // hashed leaves
}

// New returns a new empty n-ary Merkle Tree.
func New(hf HashFunc) (*Tree, error) {
	if hf == nil {
		return nil, ErrInvalidParam
	}
	return &Tree{HashFunc: hf}, nil
}

// BuildFromLeaves constructs the tree from data (hashed via HashFunc).
func (t *Tree) BuildFromLeaves(data [][]byte) error { return nil }

// Append adds leaves and updates the tree incrementally.
func (t *Tree) Append(data ...[]byte) error { return nil }

// RootHash returns the current root hash.
func (t *Tree) RootHash() []byte {
	if t.Root == nil {
		return nil
	}
	return t.Root.Digest
}

// Size returns the number of leaves.
func (t *Tree) Size() int { return len(t.leaves) }

// Get returns the node at leaf index.
func (t *Tree) Get(index int) (*Node, error)

// GenerateInclusionProof returns a proof for the leaf at index.
func (t *Tree) GenerateInclusionProof(index int) (*InclusionProof, error) {
	return nil, nil
}

// InclusionProof proves a leaf is in the tree.
type InclusionProof struct {
	LeafHash []byte
	Path     []ProofElement
}

// ProofElement is one step in an inclusion path.
type ProofElement struct {
	Hash     []byte // sibling subtree hash
	Position int    // index in parent (0..Arity-1)
}

// VerifyInclusion checks an inclusion proof against a known root.
func VerifyInclusion(proof *InclusionProof, root []byte, hf HashFunc) (bool, error) {
	return false, nil
}

// ConsistencyProof proves one tree is a consistent extension of another.
type ConsistencyProof struct {
	OldSize int
	Hashes  [][]byte
}

// GenerateConsistencyProof returns a proof that the current tree
// is a consistent append of a previous tree of size oldSize.
func (t *Tree) GenerateConsistencyProof(oldSize int) (*ConsistencyProof, error) {
	return nil, nil
}

// VerifyConsistency verifies that rootB is a consistent extension of rootA.
func VerifyConsistency(rootA []byte, sizeA int, rootB []byte, sizeB int, proof *ConsistencyProof, hf HashFunc) (bool, error) {
	return false, nil
}

// Errors
var (
	ErrInvalidParam    = &Error{"invalid parameter"}
	ErrIndexOutOfRange = &Error{"index out of range"}
	ErrInvalidProof    = &Error{"invalid proof"}
)

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
