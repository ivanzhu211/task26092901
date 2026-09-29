package acltree

import "errors"

var (
	ErrNotFound     = errors.New("acltree: path not found")
	ErrExists       = errors.New("acltree: path already exists")
	ErrInvalidInput = errors.New("acltree: invalid input")
)

const (
	bitAllow uint8 = 1
	bitDeny  uint8 = 2
)

// Engine maintains an in-memory file tree with inherited ACLs and
// tracks least-privilege policy violations incrementally.
type Engine struct {
	root *node
	seq  uint64

	policies *policySet
	pol      *violationTracker
}

func New() *Engine {
	e := &Engine{root: newNode("", false)}
	e.policies = newPolicySet()
	e.pol = newViolationTracker(e)
	return e
}

// effective computes the effective result for (group, perm) at node n:
// walk upward from n to the nearest node with an explicit entry; deny
// wins at that node. The search stops at the first node with
// inherit == false (inclusive). ok is false when no entry applies.
func effective(n *node, group string, perm Perm) (eff Effect, ok bool) {
	key := groupPerm{group, perm}
	for cur := n; cur != nil; cur = cur.parent {
		if bits, hit := cur.entries[key]; hit {
			if bits&bitDeny != 0 {
				return Deny, true
			}
			return Allow, true
		}
		if !cur.inherit {
			return 0, false
		}
	}
	return 0, false
}
