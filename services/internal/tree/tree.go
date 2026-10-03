// Package tree keeps the incremental Merkle tree of commitments the same way the vault does:
// depth 32, leaves inserted in pairs, one root per pair.
package tree

import (
	"encoding/binary"
	"errors"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/poseidon2"
)

// Depth must match the circuit's Transaction(levels, 2, 2).
const Depth = 32

// Capacity is the number of leaves a full tree holds.
const Capacity = uint64(1) << Depth

// StateSize is the length of a marshalled tree: the leaf count, the root and the frontier of
// levels 1 to Depth-1.
const StateSize = 8 + 32 + (Depth-1)*32

var zeros [Depth + 1]fr.Element

func init() {
	for i := 1; i <= Depth; i++ {
		zeros[i] = poseidon2.Compress(zeros[i-1], zeros[i-1])
	}
}

var (
	// ErrFull reports an insertion into a tree with no room for another pair.
	ErrFull = errors.New("tree: full")
	// ErrBadState reports a marshalled tree that cannot be loaded.
	ErrBadState = errors.New("tree: bad state")
)

// Zero returns the root of an empty subtree of the given height.
func Zero(height int) fr.Element {
	return zeros[height]
}

// Tree is the frontier of an append-only tree. The zero value is the empty tree.
type Tree struct {
	next uint64
	root fr.Element
	// frontier[level] is the latest left child at that level, which a later right sibling hashes
	// with. Level 0 is never needed because leaves arrive in pairs.
	frontier [Depth]fr.Element
}

// Len returns the number of leaves inserted.
func (t *Tree) Len() uint64 {
	return t.next
}

// Root returns the current root.
func (t *Tree) Root() fr.Element {
	if t.next == 0 {
		return zeros[Depth]
	}
	return t.root
}

// AppendPair inserts left and right at the next two leaf indices and returns the index of left.
func (t *Tree) AppendPair(left, right fr.Element) (uint64, error) {
	index := t.next
	if index+2 > Capacity {
		return 0, ErrFull
	}
	node := poseidon2.Compress(left, right)
	position := index >> 1
	for level := 1; level < Depth; level++ {
		if position&1 == 0 {
			t.frontier[level] = node
			node = poseidon2.Compress(node, zeros[level])
		} else {
			node = poseidon2.Compress(t.frontier[level], node)
		}
		position >>= 1
	}
	t.root = node
	t.next = index + 2
	return index, nil
}

// MarshalBinary encodes the tree for storage.
func (t *Tree) MarshalBinary() ([]byte, error) {
	out := binary.BigEndian.AppendUint64(make([]byte, 0, StateSize), t.next)
	root := t.Root().Bytes()
	out = append(out, root[:]...)
	for _, node := range t.frontier[1:] {
		b := node.Bytes()
		out = append(out, b[:]...)
	}
	return out, nil
}

// UnmarshalBinary restores a tree saved by MarshalBinary.
func (t *Tree) UnmarshalBinary(data []byte) error {
	if len(data) != StateSize {
		return ErrBadState
	}
	var restored Tree
	restored.next = binary.BigEndian.Uint64(data)
	if restored.next%2 != 0 || restored.next > Capacity {
		return ErrBadState
	}
	nodes := make([]fr.Element, Depth)
	for i := range nodes {
		node, err := fr.SetBytes([32]byte(data[8+32*i : 8+32*(i+1)]))
		if err != nil {
			return ErrBadState
		}
		nodes[i] = node
	}
	restored.root = nodes[0]
	copy(restored.frontier[1:], nodes[1:])
	if restored.next == 0 && restored.root != zeros[Depth] {
		return ErrBadState
	}
	*t = restored
	return nil
}
