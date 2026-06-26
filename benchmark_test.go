package narymerkletree

import (
	"crypto"
	"fmt"
	"testing"
)

var benchSizes = []int{16, 64, 256, 1024}

func benchLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return leaves
}

func benchTreeFlat(n int) *Tree {
	tree, err := New(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	if err := tree.BuildFromLeaves(benchLeaves(n)); err != nil {
		panic(err)
	}
	return tree
}

func benchTreeBinary(n int) *Tree {
	tree, err := New(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	tree.Arity = 2
	if err := tree.BuildFromLeaves(benchLeaves(n)); err != nil {
		panic(err)
	}
	return tree
}

func BenchmarkBuildFromLeavesFlat(b *testing.B) {
	for _, n := range benchSizes {
		leaves := benchLeaves(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree, err := New(crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				if err := tree.BuildFromLeaves(leaves); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBuildFromLeavesBinary(b *testing.B) {
	for _, n := range benchSizes {
		leaves := benchLeaves(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree, err := New(crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				tree.Arity = 2
				if err := tree.BuildFromLeaves(leaves); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAppend(b *testing.B) {
	leaf := []byte("new-leaf")
	for _, n := range benchSizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				tree := benchTreeFlat(n)
				b.StartTimer()
				if err := tree.Append(leaf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRebuild(b *testing.B) {
	for _, n := range benchSizes {
		tree := benchTreeFlat(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := tree.Rebuild(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkGenerateInclusionProof(b *testing.B) {
	for _, n := range benchSizes {
		tree := benchTreeFlat(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := tree.GenerateInclusionProof(n / 2); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyInclusion(b *testing.B) {
	for _, n := range benchSizes {
		tree := benchTreeFlat(n)
		proof, err := tree.GenerateInclusionProof(n / 2)
		if err != nil {
			b.Fatal(err)
		}
		root := tree.Root()
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ok, err := VerifyInclusion(proof, root)
				if err != nil {
					b.Fatal(err)
				}
				if !ok {
					b.Fatal("proof did not verify")
				}
			}
		})
	}
}

func BenchmarkGenerateConsistencyProof(b *testing.B) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = false
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	for _, n := range benchSizes {
		tree := benchTreeFlat(n)
		oldSize := n / 2
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := tree.GenerateConsistencyProof(oldSize); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyConsistency(b *testing.B) {
	oldPromote := Promote
	oldCollapse := Collapse
	Promote = false
	Collapse = false
	defer func() {
		Promote = oldPromote
		Collapse = oldCollapse
	}()

	for _, n := range benchSizes {
		tree := benchTreeFlat(n)
		oldSize := n / 2
		proof, err := tree.GenerateConsistencyProof(oldSize)
		if err != nil {
			b.Fatal(err)
		}
		rootA, err := tree.mthRange(0, oldSize)
		if err != nil {
			b.Fatal(err)
		}
		rootB, err := tree.mthRange(0, n)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ok, err := VerifyConsistency(rootA, rootB, oldSize, n, proof, crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				if !ok {
					b.Fatal("consistency proof did not verify")
				}
			}
		})
	}
}

func BenchmarkMarshalJSON(b *testing.B) {
	for _, n := range benchSizes {
		tree := benchTreeBinary(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := tree.MarshalJSON(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	for _, n := range benchSizes {
		tree := benchTreeBinary(n)
		data, err := tree.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var decoded Tree
				if err := decoded.UnmarshalJSON(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}