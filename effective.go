package acltree

var perms = [2]Perm{Read, Write}

// effective 计算某组在某文件上对某权限的有效结果：从文件自身向上，
// 取最近一个对该（组，权限）有显式条目的节点；查到 inherit 为假的节点为止（含）。
// 第二个返回值表示是否找到任何条目（找不到即无权限）。
func effective(f *node, group string, p Perm) (Effect, bool) {
	for n := f; n != nil; n = n.parent {
		if m := n.acl[group]; m != nil {
			if eff, ok := m[p]; ok {
				return eff, true
			}
		}
		if !n.inherit {
			break
		}
	}
	return Allow, false
}

// recomputeFile 针对给定组集合重算文件 f 的违规并做增量差异。
// groups 为 nil 表示重算所有有适用策略的组。
// 持续存在的违规保持同一条记录；消失的写入 resolved；新出现的开新记录。
func (t *Tree) recomputeFile(f *node, groups map[string]bool) {
	desired := make(map[vinKey]struct{})
	if groups == nil {
		for g, pol := range t.applicablePolicies(f) {
			t.collectDesired(f, g, pol, desired)
		}
	} else {
		for g := range groups {
			if pol := t.applicablePolicy(f, g); pol != nil {
				t.collectDesired(f, g, pol, desired)
			}
		}
	}

	for k, rec := range f.viol {
		if groups != nil && !groups[k.group] {
			continue
		}
		if _, ok := desired[k]; !ok {
			rec.Resolved = t.seq
			delete(f.viol, k)
			t.resolved = append(t.resolved, rec)
		}
	}
	for k := range desired {
		if _, ok := f.viol[k]; !ok {
			if f.viol == nil {
				f.viol = make(map[vinKey]*Violation)
			}
			f.viol[k] = &Violation{
				File:     f.path,
				PolicyID: k.policyID,
				Group:    k.group,
				Perm:     k.perm,
				Opened:   t.seq,
				file:     f,
			}
		}
	}
}

// collectDesired 把组 g 在文件 f 上超出策略 pol 允许的权限记入 desired。
func (t *Tree) collectDesired(f *node, g string, pol *Policy, desired map[vinKey]struct{}) {
	for _, p := range perms {
		if pol.Allowed[p] {
			continue
		}
		if eff, ok := effective(f, g, p); ok && eff == Allow {
			desired[vinKey{policyID: pol.ID, group: g, perm: p}] = struct{}{}
		}
	}
}

// resolveAll 解决文件 f 的全部未解决违规（用于 Remove）。
func (t *Tree) resolveAll(f *node) {
	for k, rec := range f.viol {
		rec.Resolved = t.seq
		t.resolved = append(t.resolved, rec)
		delete(f.viol, k)
	}
}
