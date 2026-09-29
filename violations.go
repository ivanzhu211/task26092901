package acltree

import "sort"

// Violations 返回违规记录。includeResolved 为真时包含已解决记录。
// 持续存在的违规跨调用始终是同一条记录（同一指针）。
func (t *Tree) Violations(includeResolved bool) []*Violation {
	out := make([]*Violation, 0)
	for f := range t.files {
		for _, rec := range f.viol {
			rec.File = f.path
			out = append(out, rec)
		}
	}
	if includeResolved {
		out = append(out, t.resolved...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		if a.Perm != b.Perm {
			return a.Perm < b.Perm
		}
		return a.Opened < b.Opened
	})
	return out
}
