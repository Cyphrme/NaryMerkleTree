package narymerkletree

// // InclusionProof proves a leaf is in the tree.
// type InclusionProof struct {
// 	LeafHash []byte
// 	Path     []ProofElement
// 	Hash     crypto.Hash
// }

// // ProofElement is one step in an inclusion path.
// type ProofElement struct {
// 	Hash     []byte // sibling subtree hash
// 	Position int    // index in parent (0..Arity-1)
// }

// // VerifyInclusion checks an inclusion proof against a known root.
// func VerifyInclusion(proof *InclusionProof, root []byte) (bool, error) {
// 	return false, nil
// }

// // ConsistencyProof proves one tree is a consistent extension of another.
// type ConsistencyProof struct {
// 	OldSize int
// 	Hashes  [][]byte
// }

// // GenerateConsistencyProof returns a proof that the current tree
// // is a consistent append of a previous tree of size oldSize.
// func (t *Tree) GenerateConsistencyProof(oldSize int) (*ConsistencyProof, error) {
// 	return nil, nil
// }

// // VerifyConsistency verifies that rootB is a consistent extension of rootA.
// func VerifyConsistency(rootA []byte, sizeA int, rootB []byte, sizeB int, proof *ConsistencyProof) (bool, error) {
// 	return false, nil
// }

// // GenerateInclusionProof returns a proof for the leaf at index.
// func (t *Tree) GenerateInclusionProof(index int) (*InclusionProof, error) {
// 	return nil, nil
// }
