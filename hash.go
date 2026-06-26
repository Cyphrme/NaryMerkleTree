package narymerkletree

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/cyphrme/coz"
)

// pathKey returns a canonical string key for a path.
func pathKey(path Path) string {
	if len(path) == 0 {
		path = Path{}
	}
	b, err := json.Marshal(path)
	if err != nil {
		panic(err)
	}
	return string(b)
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
	return t.hash(nil)
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

// isInternal reports whether path has at least one child among paths.
func isInternal(path Path, paths []Path) bool {
	for _, p := range paths {
		if len(p) == len(path)+1 && isPrefix(path, p) {
			return true
		}
	}
	return false
}

// directChildIndex returns the child index of child under parent, or -1.
func directChildIndex(parent, child Path) int {
	if len(child) != len(parent)+1 || !isPrefix(parent, child) {
		return -1
	}
	return child[len(parent)]
}

// prefixPaths returns path and every ancestor path down to the root.
func prefixPaths(path Path) []Path {
	prefixes := make([]Path, len(path)+1)
	for i := 0; i <= len(path); i++ {
		prefixes[i] = append(Path(nil), path[:i]...)
	}
	return prefixes
}

// collectPaths gathers every explicit and implicit ancestor path from nodes.
func collectPaths(nodes map[string]Node) []Path {
	seen := make(map[string]Path)
	for _, n := range nodes {
		for _, p := range prefixPaths(n.Path) {
			seen[pathKey(p)] = p
		}
	}
	paths := make([]Path, 0, len(seen))
	for _, p := range seen {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return comparePaths(paths[i], paths[j]) < 0
	})
	return paths
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
func gatherChildren(parent Path, nodeMap map[string]*Node, paths []Path) []*Node {
	maxIdx := -1
	for _, p := range paths {
		if idx := directChildIndex(parent, p); idx >= 0 && idx > maxIdx {
			maxIdx = idx
		}
	}
	if maxIdx < 0 {
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
		nodeMap[key] = &Node{
			Digest: append(coz.B64(nil), n.Digest...),
			Path:   append(Path(nil), n.Path...),
		}
	}
	for _, p := range paths {
		key := pathKey(p)
		if _, ok := nodeMap[key]; !ok {
			nodeMap[key] = &Node{Path: append(Path(nil), p...)}
		}
	}
	return nodeMap
}

// Rebuild computes internal digests bottom-up from flat Nodes and refreshes
// derived leaf metadata. The root lives at path [] in Nodes.
func (t *Tree) Rebuild() error {
	if len(t.Nodes) == 0 {
		t.leafPaths = nil
		t.leafDigests = nil
		return nil
	}

	paths := collectPaths(t.Nodes)
	nodeMap := linkedNodeMap(t.Nodes, paths)

	for _, p := range pathsByDepthDesc(paths) {
		if !isInternal(p, paths) {
			continue
		}
		key := pathKey(p)
		n := nodeMap[key]
		children := gatherChildren(p, nodeMap, paths)
		n.Children = children

		digest, err := t.digestChildren(children)
		if err != nil {
			return err
		}
		n.Digest = digest
	}

	// Sync Nodes map from nodeMap (includes implicit ancestors).
	t.Nodes = make(map[string]Node, len(paths))
	for _, p := range paths {
		n := nodeMap[pathKey(p)]
		key := pathKey(p)
		t.Nodes[key] = Node{
			Digest: append(coz.B64(nil), n.Digest...),
			Path:   append(Path(nil), n.Path...),
		}
	}

	// Leaves: paths that are not prefixes of any deeper path.
	var leafPaths []Path
	for _, p := range paths {
		if isInternal(p, paths) {
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

	return nil
}