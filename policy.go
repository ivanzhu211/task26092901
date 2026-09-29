package acltree

// ApplyPolicies 原子地应用一批策略 upsert 与删除（合计最多 500 条）。
// 批内中间状态不产生或结束任何违规；非法输入整体拒绝且状态不变。
func (t *Tree) ApplyPolicies(upserts []Policy, deleteIDs []string) error {
	if len(upserts)+len(deleteIDs) > 500 {
		return errBatchTooBig
	}
	del := make(map[string]bool, len(deleteIDs))
	for _, id := range deleteIDs {
		del[id] = true
	}
	// 规范化 upsert 并复制，避免调用方后续修改。
	norm := make([]Policy, len(upserts))
	for i, p := range upserts {
		allowed := make(map[Perm]bool, len(p.Allowed))
		for k, v := range p.Allowed {
			allowed[k] = v
		}
		norm[i] = Policy{ID: p.ID, Group: p.Group, Root: joinPath(splitPath(p.Root)), Allowed: allowed}
	}
	// 校验：结果集中不得有同（组，根目录）的两条策略。
	seen := make(map[[2]string]string, len(norm)) // (group,root) -> id
	for _, p := range norm {
		key := [2]string{p.Group, p.Root}
		if other, ok := seen[key]; ok && other != p.ID {
			return errBadPolicy
		}
		seen[key] = p.ID
		if cur := t.policiesByPath[p.Root][p.Group]; cur != nil && cur.ID != p.ID && !del[cur.ID] {
			return errBadPolicy
		}
	}

	t.seq++

	// 先整体修改索引，再统一重算，保证批内中间状态不可见。
	type affected struct {
		group string
		root  string
	}
	aff := make(map[affected]bool)
	for _, id := range deleteIDs {
		if old, ok := t.policiesByID[id]; ok {
			t.removePolicy(old)
			aff[affected{old.Group, old.Root}] = true
		}
	}
	for _, p := range norm {
		if old, ok := t.policiesByID[p.ID]; ok {
			t.removePolicy(old)
			aff[affected{old.Group, old.Root}] = true
		}
		pc := p
		t.policiesByID[pc.ID] = &pc
		m := t.policiesByPath[pc.Root]
		if m == nil {
			m = make(map[string]*Policy)
			t.policiesByPath[pc.Root] = m
		}
		m[pc.Group] = &pc
		aff[affected{pc.Group, pc.Root}] = true
	}

	// 按组收敛受影响根目录：被同组另一变更根包含的根无需重复遍历。
	byGroup := make(map[string][]string)
	for a := range aff {
		byGroup[a.group] = append(byGroup[a.group], a.root)
	}
	for g, roots := range byGroup {
		groups := map[string]bool{g: true}
		for _, r := range roots {
			if coveredBySiblingRoot(r, roots) {
				continue
			}
			if n := t.lookup(r); n != nil {
				walkFiles(n, func(f *node) { t.recomputeFile(f, groups) })
			}
		}
	}
	return nil
}

// coveredBySiblingRoot 判断 r 是否被 roots 中另一个根真包含。
func coveredBySiblingRoot(r string, roots []string) bool {
	rs := splitPath(r)
	for _, o := range roots {
		os := splitPath(o)
		if len(os) >= len(rs) {
			continue
		}
		prefix := true
		for i := range os {
			if os[i] != rs[i] {
				prefix = false
				break
			}
		}
		if prefix {
			return true
		}
	}
	return false
}

func (t *Tree) removePolicy(p *Policy) {
	delete(t.policiesByID, p.ID)
	if m := t.policiesByPath[p.Root]; m != nil {
		delete(m, p.Group)
		if len(m) == 0 {
			delete(t.policiesByPath, p.Root)
		}
	}
}

// applicablePolicy 返回组 group 对文件 f 适用的策略（根目录离 f 最近者）。
func (t *Tree) applicablePolicy(f *node, group string) *Policy {
	for n := f; n != nil; n = n.parent {
		if p := t.policiesByPath[n.path][group]; p != nil {
			return p
		}
	}
	return nil
}

// applicablePolicies 返回文件 f 的所有适用策略（按组，每组取最近根）。
func (t *Tree) applicablePolicies(f *node) map[string]*Policy {
	out := make(map[string]*Policy)
	for n := f; n != nil; n = n.parent {
		for g, p := range t.policiesByPath[n.path] {
			if _, ok := out[g]; !ok {
				out[g] = p
			}
		}
	}
	return out
}
