package acltree

import "strings"

const maxBatch = 500

// policySet stores policies by ID and indexes them by (root path, group).
type policySet struct {
	byID   map[string]*Policy
	byRoot map[string]map[string]string // root path -> group -> policy ID
}

func newPolicySet() *policySet {
	return &policySet{
		byID:   map[string]*Policy{},
		byRoot: map[string]map[string]string{},
	}
}

func normalizeRoot(path string) (string, error) {
	comps, err := splitPath(path)
	if err != nil {
		return "", err
	}
	if len(comps) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(comps, "/"), nil
}

func (ps *policySet) clone() *policySet {
	out := &policySet{
		byID:   make(map[string]*Policy, len(ps.byID)),
		byRoot: make(map[string]map[string]string, len(ps.byRoot)),
	}
	for id, p := range ps.byID {
		out.byID[id] = p
	}
	for root, m := range ps.byRoot {
		cp := make(map[string]string, len(m))
		for g, id := range m {
			cp[g] = id
		}
		out.byRoot[root] = cp
	}
	return out
}

func (ps *policySet) removeLocked(id string) {
	p := ps.byID[id]
	if p == nil {
		return
	}
	delete(ps.byID, id)
	if m := ps.byRoot[p.Root]; m != nil {
		delete(m, p.Group)
		if len(m) == 0 {
			delete(ps.byRoot, p.Root)
		}
	}
}

// insertLocked adds p; caller must ensure the (Root, Group) slot is free.
func (ps *policySet) insertLocked(p *Policy) {
	m := ps.byRoot[p.Root]
	if m == nil {
		m = map[string]string{}
		ps.byRoot[p.Root] = m
	}
	m[p.Group] = p.ID
	ps.byID[p.ID] = p
}

// ApplyPolicies atomically applies a batch of policy upserts and deletes.
// The batch may contain at most 500 entries in total. On any invalid
// input the whole batch is rejected and state is left unchanged.
func (e *Engine) ApplyPolicies(upserts []Policy, deleteIDs []string) error {
	if len(upserts)+len(deleteIDs) > maxBatch {
		return ErrInvalidInput
	}
	next := e.policies.clone()
	affectedRoots := map[string]bool{}

	// Deletes first: unknown IDs reject the batch.
	for _, id := range deleteIDs {
		p := next.byID[id]
		if p == nil {
			return ErrNotFound
		}
		affectedRoots[p.Root] = true
		next.removeLocked(id)
	}

	// Upserts: validate, then replace by ID.
	normalized := make([]*Policy, 0, len(upserts))
	for _, u := range upserts {
		if u.ID == "" || u.Group == "" {
			return ErrInvalidInput
		}
		root, err := normalizeRoot(u.Root)
		if err != nil {
			return ErrInvalidInput
		}
		allowed := make(map[Perm]bool, len(u.Allowed))
		for perm, ok := range u.Allowed {
			allowed[perm] = ok
		}
		normalized = append(normalized, &Policy{
			ID:      u.ID,
			Group:   u.Group,
			Root:    root,
			Allowed: allowed,
		})
	}
	for _, p := range normalized {
		if old := next.byID[p.ID]; old != nil {
			affectedRoots[old.Root] = true
			next.removeLocked(p.ID)
		}
		if holder := next.byRoot[p.Root][p.Group]; holder != "" {
			// Another policy already occupies (group, root).
			return ErrInvalidInput
		}
		affectedRoots[p.Root] = true
		next.insertLocked(p)
	}

	// Commit, then recompute only files under affected roots, exactly
	// once, against the post-batch state.
	e.seq++
	e.policies = next
	affected := map[*node]bool{}
	for root := range affectedRoots {
		if n := e.lookup(root); n != nil {
			eachFile(n, func(f *node) { affected[f] = true })
		}
	}
	for f := range affected {
		e.pol.recomputeFile(f, e.seq)
	}
	return nil
}
