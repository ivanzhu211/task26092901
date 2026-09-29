package acltree

import "strings"

// node 是文件树中的一个目录或文件节点。节点指针即文件身份（跨 Move 不变）。
type node struct {
	name     string
	path     string
	parent   *node
	children map[string]*node
	isFile   bool
	inherit  bool
	acl      map[string]map[Perm]Effect
	viol     map[vinKey]*Violation
}

// Tree 维护文件树上的 ACL 继承与最小权限违规记录。纯内存、单线程。
type Tree struct {
	root           *node
	seq            uint64
	policiesByID   map[string]*Policy
	policiesByPath map[string]map[string]*Policy // 规范路径 -> 组 -> 策略
	files          map[*node]struct{}
	resolved       []*Violation
}

// New 创建一棵空树。
func New() *Tree {
	root := &node{name: "", path: "/", inherit: true}
	return &Tree{
		root:           root,
		policiesByID:   make(map[string]*Policy),
		policiesByPath: make(map[string]map[string]*Policy),
		files:          make(map[*node]struct{}),
	}
}

// splitPath 把路径规范化为段序列（忽略空段）。
func splitPath(p string) []string {
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// joinPath 把段序列拼回规范路径。
func joinPath(segs []string) string {
	return "/" + strings.Join(segs, "/")
}

// lookup 按路径查找节点，不存在返回 nil。
func (t *Tree) lookup(path string) *node {
	n := t.root
	for _, s := range splitPath(path) {
		if n.children == nil {
			return nil
		}
		n = n.children[s]
		if n == nil {
			return nil
		}
	}
	return n
}

// child 获取或创建目录子节点。
func (n *node) childDir(name string) *node {
	if n.children == nil {
		n.children = make(map[string]*node)
	}
	c := n.children[name]
	if c == nil {
		c = &node{name: name, parent: n, inherit: true}
		c.path = joinPath(append(splitPath(n.path), name))
		n.children[name] = c
	}
	return c
}
