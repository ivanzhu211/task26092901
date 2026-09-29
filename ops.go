package acltree

import "errors"

var (
	errNotFound    = errors.New("acltree: path not found")
	errNotDir      = errors.New("acltree: not a directory")
	errExists      = errors.New("acltree: path already exists")
	errIntoSelf    = errors.New("acltree: cannot move into own subtree")
	errNameClash   = errors.New("acltree: name already exists in destination")
	errBadPolicy   = errors.New("acltree: duplicate policy for (group, root)")
	errBatchTooBig = errors.New("acltree: policy batch exceeds 500 entries")
)

// walkFiles 以先序遍历子树中的所有文件节点。
func walkFiles(n *node, fn func(f *node)) {
	if n.isFile {
		fn(n)
		return
	}
	for _, c := range n.children {
		walkFiles(c, fn)
	}
}

// AddFile 添加文件，自动创建缺失的中间目录。
func (t *Tree) AddFile(path string) error {
	segs := splitPath(path)
	if len(segs) == 0 {
		return errNotDir
	}
	n := t.root
	for _, s := range segs[:len(segs)-1] {
		n = n.childDir(s)
		if n.isFile {
			return errNotDir
		}
	}
	name := segs[len(segs)-1]
	if n.children[name] != nil {
		return errExists
	}
	f := &node{name: name, parent: n, isFile: true, inherit: true}
	f.path = joinPath(append(splitPath(n.path), name))
	if n.children == nil {
		n.children = make(map[string]*node)
	}
	n.children[name] = f
	t.files[f] = struct{}{}

	t.seq++
	t.recomputeFile(f, nil)
	return nil
}

// Remove 删除整棵子树。
func (t *Tree) Remove(path string) error {
	n := t.lookup(path)
	if n == nil || n == t.root {
		return errNotFound
	}
	t.seq++
	walkFiles(n, func(f *node) {
		t.resolveAll(f)
		delete(t.files, f)
	})
	delete(n.parent.children, n.name)
	n.parent = nil
	return nil
}

// Move 把 src 移动到 dstDir 下，文件身份不变。
func (t *Tree) Move(src, dstDir string) error {
	s := t.lookup(src)
	if s == nil || s == t.root {
		return errNotFound
	}
	d := t.lookup(dstDir)
	if d == nil {
		return errNotFound
	}
	if d.isFile {
		return errNotDir
	}
	for n := d; n != nil; n = n.parent {
		if n == s {
			return errIntoSelf
		}
	}
	if d.children[s.name] != nil {
		return errNameClash
	}

	t.seq++
	delete(s.parent.children, s.name)
	if d.children == nil {
		d.children = make(map[string]*node)
	}
	d.children[s.name] = s
	s.parent = d
	t.fixPaths(s)
	walkFiles(s, func(f *node) { t.recomputeFile(f, nil) })
	return nil
}

// fixPaths 在移动后自顶向下修正子树路径。
func (t *Tree) fixPaths(n *node) {
	n.path = joinPath(append(splitPath(n.parent.path), n.name))
	for _, c := range n.children {
		t.fixPaths(c)
	}
}

// SetACL 整体替换该节点的显式 ACL 与 inherit 标志。
func (t *Tree) SetACL(path string, entries []ACLEntry, inherit bool) error {
	n := t.lookup(path)
	if n == nil {
		return errNotFound
	}
	acl := make(map[string]map[Perm]Effect, len(entries))
	for _, e := range entries {
		m := acl[e.Group]
		if m == nil {
			m = make(map[Perm]Effect)
			acl[e.Group] = m
		}
		// 同一节点上 deny 优先。
		if old, ok := m[e.Perm]; !ok || e.Effect == Deny {
			m[e.Perm] = e.Effect
		} else {
			m[e.Perm] = old
		}
	}

	t.seq++
	n.acl = acl
	n.inherit = inherit
	walkFiles(n, func(f *node) { t.recomputeFile(f, nil) })
	return nil
}
