package narymerkletree

import (
	"crypto"
	"encoding/json"
	"sort"

	"github.com/cyphrme/coz"
)

// treeWire is the on-the-wire JSON shape for Tree. Nodes marshal as a
// deterministic sorted array of {path, digest} objects rather than the
// in-memory map keyed by pathKey.
type treeWire struct {
	Hash       crypto.Hash `json:"hash"`
	Nodes      []Node      `json:"nodes,omitempty"`
	Arity      int         `json:"arity,omitempty"`
	AppendOnly bool        `json:"append_only,omitempty"`
}

// sortedNodeSlice returns nodes sorted by path for deterministic JSON output.
func (t *Tree) sortedNodeSlice() []Node {
	if len(t.Nodes) == 0 {
		return nil
	}
	nodes := make([]Node, 0, len(t.Nodes))
	for _, n := range t.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return comparePaths(nodes[i].Path, nodes[j].Path) < 0
	})
	return nodes
}

// MarshalJSON returns a deterministic JSON representation with nodes as a
// sorted array of {path, digest} objects.
func (t *Tree) MarshalJSON() ([]byte, error) {
	return json.Marshal(treeWire{
		Hash:       t.Hash,
		Nodes:      t.sortedNodeSlice(),
		Arity:      t.Arity,
		AppendOnly: t.AppendOnly,
	})
}

// UnmarshalJSON loads a tree from JSON and rebuilds derived state.
func (t *Tree) UnmarshalJSON(data []byte) error {
	var w treeWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	t.Hash = w.Hash
	t.Arity = w.Arity
	t.AppendOnly = w.AppendOnly
	t.Nodes = make(map[string]Node, len(w.Nodes))
	for _, n := range w.Nodes {
		key := pathKey(n.Path)
		if _, ok := t.Nodes[key]; ok {
			return ErrDuplicatePath
		}
		t.Nodes[key] = Node{
			Path:   append(Path(nil), n.Path...),
			Digest: append(coz.B64(nil), n.Digest...),
		}
	}
	return t.Rebuild()
}