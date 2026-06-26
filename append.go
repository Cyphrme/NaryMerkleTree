package narymerkletree

import (
	"math"

	"github.com/cyphrme/coz"
)

// Append adds hashed leaf payloads at the next append-order paths.
// When Arity >= 2, paths are computed for the final leaf count and existing
// leaves must already occupy the matching prefix of that layout.
// All payloads are inserted before a single Rebuild.
func (t *Tree) Append(data ...[]byte) error {
	if len(data) == 0 {
		return nil
	}

	startN := t.LeafCount()
	finalN := startN + len(data)
	for n := startN; n < finalN; n++ {
		if !pathsCompatible(n, n+1, t.Arity) {
			return ErrAppendRestructure
		}
	}

	paths := leafPaths(finalN, t.Arity)
	for i, payload := range data {
		digest, err := t.hashLeaf(payload)
		if err != nil {
			return err
		}
		if err := t.storeNode(paths[startN+i], digest); err != nil {
			return err
		}
	}
	return t.Rebuild()
}

// leafPaths returns the left-to-right leaf paths for n leaves in a left-filled
// k-ary tree. Arity <= 1 places all leaves as root children [0..n-1].
func leafPaths(n, arity int) []Path {
	if n <= 0 {
		return nil
	}
	if arity <= 1 {
		paths := make([]Path, n)
		for i := 0; i < n; i++ {
			paths[i] = Path{i}
		}
		return paths
	}
	depth := karyDepth(n, arity)
	slots := allSlotsAtDepth(depth, arity)
	return slots[:n]
}

// karyDepth returns the depth of a left-filled k-ary tree holding n leaves.
func karyDepth(n, arity int) int {
	if n <= 1 {
		return 1
	}
	d := 1
	capacity := arity
	for capacity < n {
		d++
		capacity *= arity
	}
	return d
}

// allSlotsAtDepth returns every leaf path at depth in index order.
func allSlotsAtDepth(depth, arity int) []Path {
	total := int(math.Pow(float64(arity), float64(depth)))
	paths := make([]Path, total)
	for i := 0; i < total; i++ {
		paths[i] = indexToPath(i, depth, arity)
	}
	return paths
}

// indexToPath maps a left-to-right leaf index to its path at depth.
func indexToPath(index, depth, arity int) Path {
	path := make(Path, depth)
	for i := 0; i < depth; i++ {
		pow := 1
		for j := 0; j < depth-1-i; j++ {
			pow *= arity
		}
		path[i] = (index / pow) % arity
	}
	return path
}

// nextLeafPath returns the path for the next append-order leaf.
func (t *Tree) nextLeafPath() (Path, error) {
	n := len(t.leafPaths)
	paths := leafPaths(n+1, t.Arity)
	if len(paths) <= n {
		return nil, ErrInvalidParam
	}
	return paths[n], nil
}

// pathsEqual reports whether two paths are identical.
func pathsEqual(a, b Path) bool {
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

// pathsCompatible reports whether k-ary leaf paths for oldN leaves are a
// prefix of the layout for newN leaves. Always true when arity <= 1.
func pathsCompatible(oldN, newN, arity int) bool {
	if arity <= 1 {
		return true
	}
	if oldN == 0 {
		return true
	}
	old := leafPaths(oldN, arity)
	next := leafPaths(newN, arity)
	if len(next) < oldN {
		return false
	}
	for i := 0; i < oldN; i++ {
		if !pathsEqual(old[i], next[i]) {
			return false
		}
	}
	return true
}

// hashLeaf hashes a leaf payload with the tree's hash algorithm.
func (t *Tree) hashLeaf(data []byte) (coz.B64, error) {
	return t.hash(data)
}

// BuildFromLeaves replaces the tree with an append-order log built from payloads.
func (t *Tree) BuildFromLeaves(leaves [][]byte) error {
	t.Nodes = nil
	t.leafPaths = nil
	t.leafDigests = nil

	if len(leaves) == 0 {
		return nil
	}

	t.Nodes = make(map[string]Node, len(leaves))
	paths := leafPaths(len(leaves), t.Arity)
	for i, data := range leaves {
		digest, err := t.hashLeaf(data)
		if err != nil {
			return err
		}
		p := append(Path(nil), paths[i]...)
		t.Nodes[pathKey(p)] = Node{
			Path:   p,
			Digest: digest,
		}
	}
	return t.Rebuild()
}
