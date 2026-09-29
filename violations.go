package acltree

import "sort"

type vioKey struct {
	file     *node
	policyID string
	group    string
	perm     Perm
}

type violationTracker struct {
	e          *Engine
	open       map[vioKey]*Violation
	openByFile map[*node]map[vioKey]*Violation
	all        []*Violation
}

func newViolationTracker(e *Engine) *violationTracker {
	return &violationTracker{
		e:          e,
		open:       map[vioKey]*Violation{},
		openByFile: map[*node]map[vioKey]*Violation{},
	}
}

var allPerms = [2]Perm{Read, Write}

// applicablePolicies returns, per group, the policy whose root is the
// nearest ancestor (or self) of f. Groups without any covering policy
// are absent.
func (t *violationTracker) applicablePolicies(f *node) map[string]*Policy {
	out := map[string]*Policy{}
	for cur := f; cur != nil; cur = cur.parent {
		byGroup := t.e.policies.byRoot[cur.path()]
		for group, id := range byGroup {
			if _, seen := out[group]; !seen {
				out[group] = t.e.policies.byID[id]
			}
		}
	}
	return out
}

// violationsFor computes the full violation key set for file f from
// scratch (cost: depth x applicable groups).
func (t *violationTracker) violationsFor(f *node) map[vioKey]bool {
	want := map[vioKey]bool{}
	for group, p := range t.applicablePolicies(f) {
		for _, perm := range allPerms {
			if p.Allowed[perm] {
				continue
			}
			if eff, ok := effective(f, group, perm); ok && eff == Allow {
				want[vioKey{file: f, policyID: p.ID, group: group, perm: perm}] = true
			}
		}
	}
	return want
}

// recomputeFile diffs the freshly computed violation set of f against
// its open records, opening and resolving records as needed.
func (t *violationTracker) recomputeFile(f *node, seq uint64) {
	want := t.violationsFor(f)
	cur := t.openByFile[f]
	for key, rec := range cur {
		if !want[key] {
			rec.Resolved = seq
			rec.File = f.path()
			delete(t.open, key)
			delete(cur, key)
		}
	}
	for key := range want {
		if _, ok := cur[key]; ok {
			continue
		}
		rec := &Violation{
			File:     f.path(),
			PolicyID: key.policyID,
			Group:    key.group,
			Perm:     key.perm,
			Opened:   seq,
		}
		if cur == nil {
			cur = map[vioKey]*Violation{}
			t.openByFile[f] = cur
		}
		cur[key] = rec
		t.open[key] = rec
		t.all = append(t.all, rec)
	}
	if len(cur) == 0 {
		delete(t.openByFile, f)
	}
}

func (t *violationTracker) subtreeRemoved(n *node, seq uint64) {
	eachFile(n, func(f *node) {
		cur := t.openByFile[f]
		for key, rec := range cur {
			rec.Resolved = seq
			rec.File = f.path()
			delete(t.open, key)
		}
		delete(t.openByFile, f)
	})
}

func (t *violationTracker) subtreeMoved(n *node, seq uint64) {
	eachFile(n, func(f *node) {
		t.recomputeFile(f, seq)
		for _, rec := range t.openByFile[f] {
			rec.File = f.path()
		}
	})
}

// Violations returns currently open violations, plus resolved ones when
// includeResolved is true. The result is sorted deterministically.
func (e *Engine) Violations(includeResolved bool) []*Violation {
	var out []*Violation
	if includeResolved {
		out = append(out, e.pol.all...)
	} else {
		for _, rec := range e.pol.open {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Opened != b.Opened {
			return a.Opened < b.Opened
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.Perm < b.Perm
	})
	return out
}
