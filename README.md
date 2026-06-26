# N-ary Merkle Tree

A Go library for an n-ary Merkle tree with inclusion/consistency proofs, plus
Cyphr-specific optimizations (singleton promotion, collapse, null nodes).

This library supports arbitrary inserts, meaning a path describing node insert
may be used.

## How an N-ary Merkle Tree Works

A **leaf** is any node whose path is not a prefix of another node's path.
Internal digests are computed bottom-up from children in index order. 

Nodes are stored flat by `path` and linked on `Rebuild()`. 

`Promote` and `Collapse` are package-level toggles (both default to `true`).

A **null** node has `Digest == nil`. When combined with non-null siblings, null
children contribute the **null digest**, which is calculated as `hash("")`, also
termed the null identity.

| Condition                           | Parent digest                          |
|-------------------------------------|--------------------------------------  |
| All children null                   | null                                   |
| `Promote` (one child)               | child's effective digest (no rehash)   |
| `Collapse` (all children equal)     | repeat digest (no rehash)              |
| Default                             | `hash(concat(digests in index order))` |


**Arity** is a tree-level setting for append-only leaf placement (`Tree.Arity`).
`0` or `1` is n-ary (leaves are root children `[0..n-1]`). `>= 2` is k-ary
for `BuildFromLeaves` / `Append`. Actual fanout at each internal node follows
the paths present in the tree.

**Proofs:** inclusion proofs replay `digestChildren` per level. Consistency
proofs use a binary-composed MTH over leaf order (RFC 6962 §2.1.3) and require
flat append layout (`Arity <= 1`).

## Nomenclature
**N-ary** - This library is n-ary meaning dynamic arity.  Also support k-ary (static arity).

**Singleton Promotion** - If a node has only one child, the parent assumes the
child's value without addition hashing. (May be turned off)

**Collapse** If all children have the same value, the parent assumes the child's
value without addition hashing. (Option may be turned off)

**Null** a node with no value.  A null node's must be a "null digest" when
rooted with a non-null value.  The null digest value is calculated as digest =
hash(). 

**Append only** is a tree-level option (`Tree.AppendOnly`) that restricts inserts
to the next leaf position.  More broadly, there are a few ways to design forward
immutability

0. **Right insert anywhere** - A new leaf may be inserted in the tree as a new
   node to the right.  The value of the target node (parent/root) itself is
   mutable but the value of existing leaves is immutable. As new leaves are
   added inner nodes are mutated.
1. **Children Immutable** - Once a child node is inserted, the child node is
   immutable. The target (parent) node itself is mutable as additions are added.
   This design forces atomic children inserts.  Inner nodes also remain
   immutable.
3. **Leaves immutable, the Append Only Log** The target node's value is mutated
  with every insert, but leaves values are immutable (denoted by the term
  "log"). Leaves must be inserted in order.  If the tree is k-ary, the
  "unbalanced" portion is mutable, but once a part of the tree becomes balanced,
  it inherits immutability from the leaves. This means inner nodes are immutable
  on the balanced portion and immutable on the unbalance portion.  This design
  works best with k-arity.

This implementation uses the **append only log** model  where inserted leaves
and leaf order are immutable. (For the use of Cyphr, a commit is considered a
leaf and its content is considered a subtree.)

**Balanced vs Unary** - Because n-ary supports unary cases, the tree may be
balanced and have a unary case.  This is unlike a binary tree which cannot be
balanced if there is a unary case.  Whereas "balanced" and "symmetrical" and
"not-have-a-unary-case" can be ambiguated for binary Merkle trees, it must be
disambiguated for n-ary Merkle trees. Even though a balanced tree is symmetrical and a
symmetrical tree is balanced, balances carries more of the connotation that a subtree or branch may be balanced while the whole tree may not be symmetrical. A balanced/symmetrical tree may have unary cases.


### Notes
This library has no support for "prefixes", which we consider to be an
anti-pattern, and instead uses pure hashing. If you need prefixes, you need to
manually add them to the preimage yourself.

This library may be used with the Merkle Mountain Range wrapper, which then may
be wrapped by the multi-hash Epoch Merkle Log.

## See also
 - [N-ary Merkle Tree (this repo)](https://github.com/Cyphrme/NaryMerkleTree) - The n-ary Merkle tree.
 - [Tree](https://github.com/Cyphrme/Tree) - Digest tree, aka the **reverse Merkle tree**
 - [Cyphr](https://github.com/Cyphrme/Cyphr) - The n-ary Merkle tree is a foundational primitive for Cyphr.
 - **Merkle Mountain Ranges**
   - [Merkle Mountain Ranges for Performant Data Authentication](https://commonware.xyz/blogs/mmr)
   - [2025 Merkle Mountain Ranges are Optimal: On Witness Update Frequency for Cryptographic Accumulators](https://eprint.iacr.org/2025/234.pdf)


Project sponsored by Cyphr.me


Key Words: Reverse Merkle Tree, Merkle Tree, Digest Tree, Hash Tree, Append only log tree, Epoch tree