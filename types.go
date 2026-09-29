package acltree

// Perm is a permission kind subject to ACL checks.
type Perm int

const (
	Read Perm = iota
	Write
)

// Effect is the outcome of an ACL entry.
type Effect int

const (
	Allow Effect = iota
	Deny
)

// ACLEntry is a single explicit ACL item on a node.
type ACLEntry struct {
	Group  string
	Perm   Perm
	Effect Effect
}

// Policy bounds the permissions a group may effectively hold under Root.
type Policy struct {
	ID      string
	Group   string
	Root    string
	Allowed map[Perm]bool
}

// Violation records that a file effectively granted Perm to Group while the
// applicable Policy did not allow it. Resolved == 0 means still open.
type Violation struct {
	File     string
	PolicyID string
	Group    string
	Perm     Perm
	Opened   uint64
	Resolved uint64
}
