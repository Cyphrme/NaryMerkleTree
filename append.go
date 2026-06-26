package narymerkletree

import (
	"math"

	"github.com/cyphrme/coz"
)

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

func allSlotsAtDepth(depth, arity int) []Path {
	total := int(math.Pow(float64(arity), float64(depth)))
	paths := make([]Path, total)
	for i := 0; i < total; i++ {
		paths[i] = indexToPath(i, depth, arity)
	}
	return paths
}

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

func (t *Tree) nextLeafPath() (Path, error) {
	n := len(t.leafPaths)
	paths := leafPaths(n+1, t.Arity)
	if len(paths) <= n {
		return nil, ErrInvalidParam
	}
	return paths[n], nil
}

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

// Append adds hashed leaf payloads at the next append-order paths.
// When Arity >= 2, paths are computed for the final leaf count and existing
// leaves must already occupy the matching prefix of that layout.
func (t *Tree) Append(data ...[]byte) error {
	if len(data) == 0 {
		return nil
	}

	for _, payload := range data {
		path, err := t.nextLeafPath()
		if err != nil {
			return err
		}

		if !pathsCompatible(len(t.leafPaths), len(t.leafPaths)+1, t.Arity) {
			return ErrAppendRestructure
		}

		digest, err := t.hashLeaf(payload)
		if err != nil {
			return err
		}

		t.ensureNodes()
		p := append(Path(nil), path...)
		t.Nodes[pathKey(p)] = Node{
			Path:   p,
			Digest: digest,
		}
		if err := t.Rebuild(); err != nil {
			return err
		}
	}
	return nil
}