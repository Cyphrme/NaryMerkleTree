package narymerkletree

import (
	"bytes"
	"sort"
	"strconv"

	"github.com/cyphrme/coz"
)

// pathKey returns a canonical in-memory map key for a path.
func pathKey(path Path) string {
	if len(path) == 0 {
		return ""
	}
	if len(path) == 1 {
		return strconv.Itoa(path[0])
	}
	b := make([]byte, 0, len(path)*4)
	for i, v := range path {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendInt(b, int64(v), 10)
	}
	return string(b)
}

// pathLayout indexes paths for rebuild and proof walks.
type pathLayout struct {
	paths    []Path
	internal map[string]struct{}
	maxChild map[string]int
}

// buildPathLayout gathers explicit and implicit ancestor paths from nodes.
func buildPathLayout(nodes map[string]Node) pathLayout {
	seen := make(map[string]Path)
	internal := make(map[string]struct{})
	maxChild := make(map[string]int)

	for _, n := range nodes {
		path := n.Path
		for i := 0; i <= len(path); i++ {
			p := path[:i]
			key := pathKey(p)
			if _, ok := seen[key]; !ok {
				seen[key] = append(Path(nil), p...)
			}
			if i > 0 {
				parentKey := pathKey(path[:i-1])
				internal[parentKey] = struct{}{}
				idx := path[i-1]
				if v, ok := maxChild[parentKey]; !ok || idx > v {
					maxChild[parentKey] = idx
				}
			}
		}
	}

	paths := make([]Path, 0, len(seen))
	for _, p := range seen {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return comparePaths(paths[i], paths[j]) < 0
	})

	return pathLayout{
		paths:    paths,
		internal: internal,
		maxChild: maxChild,
	}
}

// hash computes a digest for raw bytes using the tree's hash algorithm.
func (t *Tree) hash(data []byte) (coz.B64, error) {
	h := t.Hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return coz.B64(h.Sum(nil)), nil
}

// nullDigest returns hash(empty), the digest contributed by null children.
func (t *Tree) nullDigest() (coz.B64, error) {
	if t.nullDigestCache != nil {
		return t.nullDigestCache, nil
	}
	d, err := t.hash(nil)
	if err != nil {
		return nil, err
	}
	t.nullDigestCache = d
	return d, nil
}

// effectiveDigest returns the digest used when combining children into a parent.
// Null nodes (Digest == nil) contribute the null digest hash(empty).
func (t *Tree) effectiveDigest(n *Node) (coz.B64, error) {
	if n.Digest != nil {
		return n.Digest, nil
	}
	return t.nullDigest()
}

// digestChildren computes a parent digest from its children using Promote,
// Collapse, and concat rules.
func (t *Tree) digestChildren(children []*Node) (coz.B64, error) {
	if len(children) == 0 {
		return nil, nil
	}

	allNull := true
	for _, c := range children {
		if c.Digest != nil {
			allNull = false
			break
		}
	}
	if allNull {
		return nil, nil
	}

	if Promote && len(children) == 1 {
		return t.effectiveDigest(children[0])
	}

	effective := make([]coz.B64, len(children))
	for i, c := range children {
		d, err := t.effectiveDigest(c)
		if err != nil {
			return nil, err
		}
		effective[i] = d
	}

	if Collapse {
		allEqual := true
		for i := 1; i < len(effective); i++ {
			if !bytes.Equal(effective[i], effective[0]) {
				allEqual = false
				break
			}
		}
		if allEqual {
			return append(coz.B64(nil), effective[0]...), nil
		}
	}

	var buf []byte
	for _, d := range effective {
		buf = append(buf, d...)
	}
	return t.hash(buf)
}

// isPrefix reports whether prefix is a prefix of path.
func isPrefix(prefix, path Path) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}
	return true
}

// collectPaths gathers every explicit and implicit ancestor path from nodes.
func collectPaths(nodes map[string]Node) []Path {
	return buildPathLayout(nodes).paths
}

// pathsByDepthDesc returns paths sorted deepest-first, then lexicographically.
func pathsByDepthDesc(paths []Path) []Path {
	sorted := make([]Path, len(paths))
	copy(sorted, paths)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) > len(sorted[j])
		}
		return comparePaths(sorted[i], sorted[j]) < 0
	})
	return sorted
}

// gatherChildren returns direct children of parent, left-filled with null nodes.
func gatherChildren(parent Path, nodeMap map[string]*Node, maxChild map[string]int) []*Node {
	maxIdx, ok := maxChild[pathKey(parent)]
	if !ok {
		return nil
	}

	children := make([]*Node, maxIdx+1)
	for i := 0; i <= maxIdx; i++ {
		childPath := append(append(Path(nil), parent...), i)
		key := pathKey(childPath)
		if n, ok := nodeMap[key]; ok {
			children[i] = n
		} else {
			children[i] = &Node{Path: childPath}
		}
	}
	return children
}

// digestAt returns the stored digest at path, or nil if absent.
func (t *Tree) digestAt(path Path) coz.B64 {
	if t.Nodes == nil {
		return nil
	}
	if n, ok := t.Nodes[pathKey(path)]; ok {
		return n.Digest
	}
	return nil
}

// linkedNodeMap builds a mutable node map including implicit ancestor nodes.
func linkedNodeMap(nodes map[string]Node, paths []Path) map[string]*Node {
	nodeMap := make(map[string]*Node, len(paths))
	for key, n := range nodes {
		node := &Node{Path: append(Path(nil), n.Path...)}
		if n.Digest != nil {
			node.Digest = append(coz.B64(nil), n.Digest...)
		}
		nodeMap[key] = node
	}
	for _, p := range paths {
		key := pathKey(p)
		if _, ok := nodeMap[key]; !ok {
			nodeMap[key] = &Node{Path: append(Path(nil), p...)}
		}
	}
	return nodeMap
}

func isFlatLayout(nodes map[string]Node) bool {
	for _, n := range nodes {
		if len(n.Path) > 1 {
			return false
		}
	}
	return true
}

// flatMaxChildIndex returns the highest root-child index among flat nodes.
func flatMaxChildIndex(nodes map[string]Node) int {
	maxIdx := -1
	for _, n := range nodes {
		if len(n.Path) == 1 && n.Path[0] > maxIdx {
			maxIdx = n.Path[0]
		}
	}
	return maxIdx
}

func (t *Tree) flatLeafCount() int {
	count := 0
	for _, n := range t.Nodes {
		if len(n.Path) == 1 {
			count++
		}
	}
	return count
}

func (t *Tree) leafMetadataCurrent() bool {
	return t.leafPaths != nil && len(t.leafPaths) == t.flatLeafCount()
}

func (t *Tree) syncLeavesFlat() {
	type flatLeaf struct {
		idx    int
		digest coz.B64
	}
	leaves := make([]flatLeaf, 0, t.flatLeafCount())
	for _, n := range t.Nodes {
		if len(n.Path) == 1 {
			leaves = append(leaves, flatLeaf{n.Path[0], n.Digest})
		}
	}
	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].idx < leaves[j].idx
	})

	t.leafPaths = make([]Path, len(leaves))
	t.leafDigests = make([]*coz.B64, len(leaves))
	for i, leaf := range leaves {
		t.leafPaths[i] = Path{leaf.idx}
		if leaf.digest != nil {
			digest := append(coz.B64(nil), leaf.digest...)
			t.leafDigests[i] = &digest
		}
	}
}

func (t *Tree) syncNodesFrom(nodeMap map[string]*Node, layout pathLayout) {
	t.Nodes = make(map[string]Node, len(layout.paths))
	for _, p := range layout.paths {
		key := pathKey(p)
		n := nodeMap[key]
		t.Nodes[key] = Node{
			Digest: append(coz.B64(nil), n.Digest...),
			Path:   append(Path(nil), n.Path...),
		}
	}
}

func (t *Tree) syncLeavesFrom(nodeMap map[string]*Node, layout pathLayout) {
	var leafPaths []Path
	for _, p := range layout.paths {
		if _, ok := layout.internal[pathKey(p)]; ok {
			continue
		}
		leafPaths = append(leafPaths, append(Path(nil), p...))
	}

	t.leafPaths = leafPaths
	t.leafDigests = make([]*coz.B64, len(leafPaths))
	for i, p := range leafPaths {
		if d := nodeMap[pathKey(p)].Digest; d != nil {
			digest := append(coz.B64(nil), d...)
			t.leafDigests[i] = &digest
		}
	}
}

// rebuildFlat handles the common append-only case where all leaves are direct
// root children (Arity <= 1 and no deeper paths).
func (t *Tree) rebuildFlat() error {
	maxIdx := flatMaxChildIndex(t.Nodes)
	if maxIdx < 0 {
		t.leafPaths = nil
		t.leafDigests = nil
		delete(t.Nodes, pathKey(Path{}))
		return nil
	}

	children := make([]*Node, maxIdx+1)
	for i := 0; i <= maxIdx; i++ {
		child := &Node{Path: Path{i}}
		if n, ok := t.Nodes[pathKey(Path{i})]; ok {
			child.Digest = n.Digest
		}
		children[i] = child
	}

	digest, err := t.digestChildren(children)
	if err != nil {
		return err
	}

	rootKey := pathKey(Path{})
	root := t.Nodes[rootKey]
	root.Path = Path{}
	root.Digest = digest
	t.Nodes[rootKey] = root

	if !t.leafMetadataCurrent() {
		t.syncLeavesFlat()
	}
	return nil
}

// Rebuild computes internal digests bottom-up from flat Nodes and refreshes
// derived leaf metadata. The root lives at path [] in Nodes.
func (t *Tree) Rebuild() error {
	if len(t.Nodes) == 0 {
		t.leafPaths = nil
		t.leafDigests = nil
		return nil
	}

	if t.Arity <= 1 && isFlatLayout(t.Nodes) {
		return t.rebuildFlat()
	}

	layout := buildPathLayout(t.Nodes)
	nodeMap := linkedNodeMap(t.Nodes, layout.paths)

	for _, p := range pathsByDepthDesc(layout.paths) {
		key := pathKey(p)
		if _, ok := layout.internal[key]; !ok {
			continue
		}
		n := nodeMap[key]
		children := gatherChildren(p, nodeMap, layout.maxChild)
		n.Children = children

		digest, err := t.digestChildren(children)
		if err != nil {
			return err
		}
		n.Digest = digest
	}

	t.syncNodesFrom(nodeMap, layout)
	t.syncLeavesFrom(nodeMap, layout)
	return nil
}