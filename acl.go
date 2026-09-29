package acltree

// SetACL replaces the explicit ACL of the node at path and sets its
// inherit flag. Work is proportional to the subtree below path.
func (e *Engine) SetACL(path string, entries []ACLEntry, inherit bool) error {
	n := e.lookup(path)
	if n == nil {
		return ErrNotFound
	}
	m := make(map[groupPerm]uint8, len(entries))
	for _, en := range entries {
		if en.Group == "" {
			return ErrInvalidInput
		}
		key := groupPerm{en.Group, en.Perm}
		if en.Effect == Deny {
			m[key] |= bitDeny
		} else {
			m[key] |= bitAllow
		}
	}
	e.seq++
	n.entries = m
	n.inherit = inherit
	eachFile(n, func(f *node) {
		e.pol.recomputeFile(f, e.seq)
	})
	return nil
}
