package acltree

import "strings"

// 朴素模型：纯路径字符串实现，每步从零全量计算违规，与库共享除类型外的任何代码。
type naiveACL struct {
	eff     map[[2]interface{}]Effect // (group, perm) -> 归并后效果（同节点 deny 优先）
	inherit bool
}

type naivePolicy struct {
	group   string
	root    string
	allowed map[Perm]bool
}

type naive struct {
	files    map[string]int // 路径 -> 稳定文件身份（跨移动不变）
	nextID   int
	dirs     map[string]bool
	acl      map[string]*naiveACL
	policies map[string]naivePolicy // id -> policy
}

func newNaive() *naive {
	return &naive{
		files:    make(map[string]int),
		nextID:   1,
		dirs:     map[string]bool{"/": true},
		acl:      make(map[string]*naiveACL),
		policies: make(map[string]naivePolicy),
	}
}

func parentPath(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func baseName(p string) string {
	return p[strings.LastIndex(p, "/")+1:]
}

func normPath(p string) string {
	return joinPath(splitPath(p))
}

// isAncestorOrSelf 判断 root 是否为 p 的祖先或自身。
func isAncestorOrSelf(root, p string) bool {
	return root == "/" || p == root || strings.HasPrefix(p, root+"/")
}

func (n *naive) addFile(path string) {
	path = normPath(path)
	for p := parentPath(path); p != "/"; p = parentPath(p) {
		n.dirs[p] = true
	}
	n.files[path] = n.nextID
	n.nextID++
}

func (n *naive) remove(path string) {
	path = normPath(path)
	for p := range n.files {
		if p == path || strings.HasPrefix(p, path+"/") {
			delete(n.files, p)
		}
	}
	for p := range n.dirs {
		if p != "/" && (p == path || strings.HasPrefix(p, path+"/")) {
			delete(n.dirs, p)
		}
	}
	for p := range n.acl {
		if p == path || strings.HasPrefix(p, path+"/") {
			delete(n.acl, p)
		}
	}
}

func (n *naive) move(src, dstDir string) {
	src, dstDir = normPath(src), normPath(dstDir)
	dst := joinPath(append(splitPath(dstDir), baseName(src)))
	rewrite := func(p string) (string, bool) {
		if p == src {
			return dst, true
		}
		if strings.HasPrefix(p, src+"/") {
			return dst + p[len(src):], true
		}
		return p, false
	}
	moveMap := func(m map[string]bool) {
		for p := range m {
			if p == "/" {
				continue
			}
			if np, ok := rewrite(p); ok {
				delete(m, p)
				m[np] = true
			}
		}
	}
	moveMap(n.dirs)
	for p, id := range n.files {
		if np, ok := rewrite(p); ok {
			delete(n.files, p)
			n.files[np] = id
		}
	}
	for p, a := range n.acl {
		if np, ok := rewrite(p); ok {
			delete(n.acl, p)
			n.acl[np] = a
		}
	}
}

func (n *naive) setACL(path string, entries []ACLEntry, inherit bool) {
	a := &naiveACL{eff: make(map[[2]interface{}]Effect), inherit: inherit}
	for _, e := range entries {
		k := [2]interface{}{e.Group, e.Perm}
		if old, ok := a.eff[k]; !ok || e.Effect == Deny {
			a.eff[k] = e.Effect
		} else {
			a.eff[k] = old
		}
	}
	n.acl[normPath(path)] = a
}

func (n *naive) applyPolicies(upserts []Policy, deleteIDs []string) {
	for _, id := range deleteIDs {
		delete(n.policies, id)
	}
	for _, p := range upserts {
		n.policies[p.ID] = naivePolicy{group: p.Group, root: normPath(p.Root), allowed: p.Allowed}
	}
}

// effectivePerm 朴素计算：从文件逐级向上找最近显式条目，inherit 为假即止（含）。
func (n *naive) effectivePerm(f, group string, perm Perm) (Effect, bool) {
	for p := f; ; p = parentPath(p) {
		if a := n.acl[p]; a != nil {
			if eff, ok := a.eff[[2]interface{}{group, perm}]; ok {
				return eff, true
			}
		}
		inh := true
		if a := n.acl[p]; a != nil {
			inh = a.inherit
		}
		if !inh || p == "/" {
			break
		}
	}
	return Allow, false
}

// violations 从零全量计算当前未解决违规集合。
// 键为（文件身份，策略id，组，权限）。
func (n *naive) violations() map[[4]interface{}]struct{} {
	out := make(map[[4]interface{}]struct{})
	for f, fid := range n.files {
		// 每组适用策略：根目录离 f 最近者。
		best := make(map[string]string) // group -> policy id
		bestLen := make(map[string]int)
		for id, p := range n.policies {
			if !isAncestorOrSelf(p.root, f) {
				continue
			}
			d := len(splitPath(p.root))
			if _, ok := best[p.group]; !ok || d > bestLen[p.group] {
				best[p.group] = id
				bestLen[p.group] = d
			}
		}
		for g, id := range best {
			pol := n.policies[id]
			for _, perm := range []Perm{Read, Write} {
				if pol.allowed[perm] {
					continue
				}
				if eff, ok := n.effectivePerm(f, g, perm); ok && eff == Allow {
					out[[4]interface{}{fid, id, g, perm}] = struct{}{}
				}
			}
		}
	}
	return out
}
