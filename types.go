package acltree

// Perm 表示权限种类。
type Perm int

const (
	Read Perm = iota
	Write
)

// Effect 表示 ACL 条目的允许/拒绝。
type Effect int

const (
	Allow Effect = iota
	Deny
)

// ACLEntry 是一条显式 ACL 条目：（组，权限，allow/deny）。
type ACLEntry struct {
	Group  string
	Perm   Perm
	Effect Effect
}

// Policy 是最小权限策略：（id，组，根目录，允许的权限集合）。
type Policy struct {
	ID      string
	Group   string
	Root    string
	Allowed map[Perm]bool
}

// Violation 是一条违规记录，身份为（文件，策略id，组，权限）。
// Resolved 为 0 表示仍未解决。
type Violation struct {
	File     string
	PolicyID string
	Group    string
	Perm     Perm
	Opened   uint64
	Resolved uint64

	file *node
}

// vinKey 是违规记录的内部身份键。
type vinKey struct {
	policyID string
	group    string
	perm     Perm
}
