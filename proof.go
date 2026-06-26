package narymerkletree

import (
	"bytes"
	"crypto"
	"math/bits"

	"github.com/cyphrme/coz"
)

// InclusionProof proves a leaf is in the tree.
type InclusionProof struct {
	LeafHash coz.B64     `json:"leaf_hash"`
	LeafPath Path        `json:"leaf_path,omitempty"`
	Steps    []ProofStep `json:"steps"`
	Hash     crypto.Hash `json:"hash"`
}

// ProofStep is one level walking from leaf toward root.
type ProofStep struct {
	Position int       `json:"position"`
	Width    int       `json:"width"`
	Slots    []coz.B64 `json:"slots"` // sibling digests; Slots[Position] is ignored
}

// ConsistencyProof proves one tree is a consistent extension of another.
type ConsistencyProof struct {
	OldSize int       `json:"old_size"`
	Hashes  []coz.B64 `json:"hashes"`
}

// proofStepAt builds one inclusion-proof step at parent for child position pos.
func (t *Tree) proofStepAt(parent Path, pos int) (ProofStep, error) {
	paths := collectPaths(t.Nodes)
	nodeMap := linkedNodeMap(t.Nodes, paths)
	children := gatherChildren(parent, nodeMap, paths)
	if children == nil {
		return ProofStep{}, ErrInvalidProof
	}
	if pos < 0 || pos >= len(children) {
		return ProofStep{}, ErrInvalidProof
	}

	step := ProofStep{
		Position: pos,
		Width:    len(children),
		Slots:    make([]coz.B64, len(children)),
	}
	for i, child := range children {
		if i != pos {
			step.Slots[i] = append(coz.B64(nil), child.Digest...)
		}
	}
	return step, nil
}

// climbStep hashes accum with sibling slots from one proof step toward the root.
func (t *Tree) climbStep(accum coz.B64, step ProofStep) (coz.B64, error) {
	if step.Width <= 0 || step.Position < 0 || step.Position >= step.Width {
		return nil, ErrInvalidProof
	}
	if len(step.Slots) != step.Width {
		return nil, ErrInvalidProof
	}

	children := make([]*Node, step.Width)
	for i := 0; i < step.Width; i++ {
		if i == step.Position {
			children[i] = &Node{Digest: accum}
		} else {
			children[i] = &Node{Digest: append(coz.B64(nil), step.Slots[i]...)}
		}
	}
	return t.digestChildren(children)
}

// GenerateInclusionProof returns a proof for the leaf at index.
func (t *Tree) GenerateInclusionProof(index int) (*InclusionProof, error) {
	if len(t.Nodes) == 0 {
		return nil, ErrInvalidParam
	}
	leaf, err := t.GetLeaf(index)
	if err != nil {
		return nil, err
	}

	proof := &InclusionProof{
		LeafHash: append(coz.B64(nil), leaf.Digest...),
		LeafPath: append(Path(nil), leaf.Path...),
		Hash:     t.Hash,
	}

	path := append(Path(nil), leaf.Path...)
	for len(path) > 0 {
		parentPath := path[:len(path)-1]
		pos := path[len(path)-1]

		step, err := t.proofStepAt(parentPath, pos)
		if err != nil {
			return nil, err
		}
		proof.Steps = append(proof.Steps, step)
		path = parentPath
	}

	return proof, nil
}

// VerifyInclusion checks an inclusion proof against a known root.
func VerifyInclusion(proof *InclusionProof, root coz.B64) (bool, error) {
	if proof == nil {
		return false, ErrInvalidProof
	}
	if proof.Hash == 0 {
		return false, ErrInvalidProof
	}

	t := &Tree{Hash: proof.Hash}
	accum := append(coz.B64(nil), proof.LeafHash...)
	for _, step := range proof.Steps {
		var err error
		accum, err = t.climbStep(accum, step)
		if err != nil {
			return false, err
		}
	}

	return bytes.Equal(accum, root), nil
}

// mthRange returns the root of a binary-composed Merkle tree over leaves
// [start,end), using the same digestChildren rules as the main tree.
func (t *Tree) mthRange(start, end int) (coz.B64, error) {
	n := end - start
	if n <= 0 {
		return nil, nil
	}
	if n == 1 {
		return append(coz.B64(nil), t.digestAt(t.leafPaths[start])...), nil
	}

	k := largestPow2LessThan(n)
	left, err := t.mthRange(start, start+k)
	if err != nil {
		return nil, err
	}
	right, err := t.mthRange(start+k, end)
	if err != nil {
		return nil, err
	}
	return t.hashPair(left, right)
}

// largestPow2LessThan returns the largest power of two strictly less than n.
func largestPow2LessThan(n int) int {
	if n <= 1 {
		return 0
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// consistencySnapshot builds a proof that rootB extends rootA under binary MTH.
// When oldSize equals largestPow2LessThan(newSize), the proof is a single suffix
// hash. Otherwise intermediate subtree hashes are included.
func (t *Tree) consistencySnapshot(oldSize, newSize int) ([]coz.B64, error) {
	if oldSize >= newSize {
		return nil, nil
	}
	if oldSize == 0 {
		root, err := t.mthRange(0, newSize)
		if err != nil {
			return nil, err
		}
		return []coz.B64{root}, nil
	}

	k := largestPow2LessThan(newSize)
	if oldSize == k {
		suffix, err := t.mthRange(oldSize, newSize)
		if err != nil {
			return nil, err
		}
		return []coz.B64{suffix}, nil
	}
	if oldSize < k {
		right, err := t.mthRange(k, newSize)
		if err != nil {
			return nil, err
		}
		rest, err := t.consistencySnapshot(oldSize, k)
		if err != nil {
			return nil, err
		}
		return append([]coz.B64{right}, rest...), nil
	}
	return t.consistencySnapshot(oldSize-k, newSize-k)
}

// rootFromConsistencyProof recomputes the new root from a consistency proof.
func rootFromConsistencyProof(oldSize, newSize int, proof []coz.B64, rootA coz.B64, hash crypto.Hash) (coz.B64, error) {
	t := &Tree{Hash: hash}
	if oldSize >= newSize {
		return append(coz.B64(nil), rootA...), nil
	}
	if oldSize == 0 {
		if len(proof) != 1 {
			return nil, ErrInvalidProof
		}
		return append(coz.B64(nil), proof[0]...), nil
	}

	k := largestPow2LessThan(newSize)
	if oldSize == k {
		if len(proof) != 1 {
			return nil, ErrInvalidProof
		}
		return t.hashPair(rootA, proof[0])
	}
	if oldSize < k {
		if len(proof) == 0 {
			return nil, ErrInvalidProof
		}
		left, err := rootFromConsistencyProof(oldSize, k, proof[1:], rootA, hash)
		if err != nil {
			return nil, err
		}
		return t.hashPair(left, proof[0])
	}
	return rootFromConsistencyProof(oldSize-k, newSize-k, proof, rootA, hash)
}

// GenerateConsistencyProof returns a proof that the current tree is a
// consistent append of a previous tree of size oldSize.
//
// Consistency proofs use a binary-composed MTH over leaf order (RFC 6962
// section 2.1.3) and require a flat append layout (Arity <= 1).
func (t *Tree) GenerateConsistencyProof(oldSize int) (*ConsistencyProof, error) {
	newSize := t.LeafCount()
	if oldSize < 0 || oldSize > newSize {
		return nil, ErrInvalidParam
	}
	if t.Arity >= 2 {
		return nil, ErrInvalidParam
	}

	hashes, err := t.consistencySnapshot(oldSize, newSize)
	if err != nil {
		return nil, err
	}
	return &ConsistencyProof{OldSize: oldSize, Hashes: hashes}, nil
}

// hashPair combines two subtree digests using digestChildren rules.
func (t *Tree) hashPair(left, right coz.B64) (coz.B64, error) {
	if left == nil && right == nil {
		return nil, nil
	}
	if left == nil {
		return append(coz.B64(nil), right...), nil
	}
	if right == nil {
		return append(coz.B64(nil), left...), nil
	}
	children := []*Node{{Digest: left}, {Digest: right}}
	return t.digestChildren(children)
}

// VerifyConsistency verifies that rootB is a consistent extension of rootA.
// rootA is treated as a trusted input; the proof demonstrates rootB extends it.
func VerifyConsistency(rootA, rootB coz.B64, sizeA, sizeB int, proof *ConsistencyProof, hash crypto.Hash) (bool, error) {
	if proof == nil || sizeA < 0 || sizeB < 0 || sizeA > sizeB {
		return false, ErrInvalidProof
	}
	if proof.OldSize != sizeA {
		return false, ErrInvalidProof
	}

	if sizeA == sizeB {
		return bytes.Equal(rootA, rootB), nil
	}

	computed, err := rootFromConsistencyProof(sizeA, sizeB, proof.Hashes, rootA, hash)
	if err != nil {
		return false, err
	}
	return bytes.Equal(computed, rootB), nil
}