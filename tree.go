package acltree

import (
	"strings"
)

type groupPerm struct {
	group string
	perm  Perm
}

type node struct {
	name     string
	parent   *node
	children map[string]*node
	isFile   bool
	entries  map[groupPerm]uint8 // bitmask: 1=allow, 2=deny
	inherit  bool
}

func newNode(name string, isFile bool) *node {
	return &node{
		name:    name,
		isFile:  isFile,
		inherit: true,
	}
}

func (n *node) path() string {
	if n.parent == nil {
		return "/"
	}
	var parts []string
	for cur := n; cur.parent != nil; cur = cur.parent {
		parts = append(parts, cur.name)
	}
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteByte('/')
		b.WriteString(parts[i])
	}
	return b.String()
}

// splitPath validates and splits an absolute path into components.
func splitPath(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, ErrInvalidInput
	}
	var out []string
	for _, p := range strings.Split(path, "/") {
		if p == "" {
			continue
		}
		if p == "." || p == ".." {
			return nil, ErrInvalidInput
		}
		out = append(out, p)
	}
	return out, nil
}

// lookup finds the node at path, or nil.
func (e *Engine) lookup(path string) *node {
	comps, err := splitPath(path)
	if err != nil {
		return nil
	}
	cur := e.root
	for _, c := range comps {
		if cur.children == nil {
			return nil
		}
		cur = cur.children[c]
		if cur == nil {
			return nil
		}
	}
	return cur
}

// AddFile creates the file at path, creating missing intermediate
// directories. It is a no-op if the file already exists.
func (e *Engine) AddFile(path string) error {
	comps, err := splitPath(path)
	if err != nil || len(comps) == 0 {
		return ErrInvalidInput
	}
	cur := e.root
	for _, c := range comps[:len(comps)-1] {
		next := cur.children[c]
		if next == nil {
			next = newNode(c, false)
			next.parent = cur
			if cur.children == nil {
				cur.children = map[string]*node{}
			}
			cur.children[c] = next
		} else if next.isFile {
			return ErrInvalidInput
		}
		cur = next
	}
	last := comps[len(comps)-1]
	if existing := cur.children[last]; existing != nil {
		if existing.isFile {
			return nil // no-op
		}
		return ErrExists
	}
	f := newNode(last, true)
	f.parent = cur
	if cur.children == nil {
		cur.children = map[string]*node{}
	}
	cur.children[last] = f

	e.seq++
	e.pol.recomputeFile(f, e.seq)
	return nil
}

// Remove deletes the node at path and its whole subtree.
func (e *Engine) Remove(path string) error {
	n := e.lookup(path)
	if n == nil {
		return ErrNotFound
	}
	if n.parent == nil {
		return ErrInvalidInput
	}
	e.seq++
	e.pol.subtreeRemoved(n, e.seq)
	delete(n.parent.children, n.name)
	n.parent = nil
	return nil
}

// Move relocates the subtree rooted at src under dstDir. File identity
// is preserved across moves.
func (e *Engine) Move(src, dstDir string) error {
	s := e.lookup(src)
	if s == nil {
		return ErrNotFound
	}
	if s.parent == nil {
		return ErrInvalidInput
	}
	d := e.lookup(dstDir)
	if d == nil {
		return ErrNotFound
	}
	if d.isFile {
		return ErrInvalidInput
	}
	// Reject moving into own subtree (including src == dstDir).
	for cur := d; cur != nil; cur = cur.parent {
		if cur == s {
			return ErrInvalidInput
		}
	}
	if d.children[s.name] != nil {
		return ErrExists
	}
	e.seq++
	delete(s.parent.children, s.name)
	s.parent = d
	if d.children == nil {
		d.children = map[string]*node{}
	}
	d.children[s.name] = s
	e.pol.subtreeMoved(s, e.seq)
	return nil
}

// eachFile calls fn for every file in the subtree rooted at n.
func eachFile(n *node, fn func(f *node)) {
	if n.isFile {
		fn(n)
		return
	}
	for _, c := range n.children {
		eachFile(c, fn)
	}
}
