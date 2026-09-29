package acltree

import "testing"

// 在外层策略范围内新增一条更深的同组策略（两者都不允许 write）：
// 同一文件外层名下的违规被 resolved，内层名下以新记录出现。
func TestInnerPolicySupersedesOuter(t *testing.T) {
	tr := New()
	if err := tr.AddFile("/a/b/f"); err != nil {
		t.Fatal(err)
	}
	// 组 g 在 /a 上拥有 write。
	if err := tr.SetACL("/a", []ACLEntry{{Group: "g", Perm: Write, Effect: Allow}}, true); err != nil {
		t.Fatal(err)
	}
	// 外层策略：/a 下 g 只允许 read。
	mustApply(t, tr, []Policy{{ID: "outer", Group: "g", Root: "/a",
		Allowed: map[Perm]bool{Read: true}}}, nil)

	open := tr.Violations(false)
	if len(open) != 1 {
		t.Fatalf("want 1 open violation, got %d", len(open))
	}
	outer := open[0]
	if outer.PolicyID != "outer" || outer.Perm != Write || outer.Group != "g" || outer.File != "/a/b/f" {
		t.Fatalf("unexpected violation: %+v", outer)
	}
	if outer.Opened == 0 || outer.Resolved != 0 {
		t.Fatalf("bad seq: opened=%d resolved=%d", outer.Opened, outer.Resolved)
	}

	// 内层策略：/a/b 下 g 同样只允许 read。
	mustApply(t, tr, []Policy{{ID: "inner", Group: "g", Root: "/a/b",
		Allowed: map[Perm]bool{Read: true}}}, nil)

	open = tr.Violations(false)
	if len(open) != 1 {
		t.Fatalf("want 1 open violation, got %d", len(open))
	}
	inner := open[0]
	if inner.PolicyID != "inner" || inner.Perm != Write {
		t.Fatalf("unexpected violation: %+v", inner)
	}
	if inner == outer {
		t.Fatal("inner violation must be a new record")
	}
	if inner.Opened != outer.Resolved || inner.Opened == 0 {
		t.Fatalf("inner.Opened=%d should equal outer.Resolved=%d", inner.Opened, outer.Resolved)
	}
	all := tr.Violations(true)
	if len(all) != 2 {
		t.Fatalf("want 2 total records, got %d", len(all))
	}
	if outer.Resolved == 0 {
		t.Fatal("outer violation should be resolved")
	}
}

// 同一批内删除内层策略并在同根目录新增同组替代策略：
// 批内中间状态不得让外层策略名下冒出违规。
func TestBatchAtomicityNoTransientViolation(t *testing.T) {
	tr := New()
	if err := tr.AddFile("/a/b/f"); err != nil {
		t.Fatal(err)
	}
	if err := tr.SetACL("/a", []ACLEntry{{Group: "g", Perm: Write, Effect: Allow}}, true); err != nil {
		t.Fatal(err)
	}
	// 外层不允许 write；内层允许 write，因此稳态下无违规。
	mustApply(t, tr, []Policy{
		{ID: "outer", Group: "g", Root: "/a", Allowed: map[Perm]bool{Read: true}},
		{ID: "inner", Group: "g", Root: "/a/b", Allowed: map[Perm]bool{Read: true, Write: true}},
	}, nil)
	if n := len(tr.Violations(false)); n != 0 {
		t.Fatalf("want 0 open violations, got %d", n)
	}

	// 一批：删 inner，新增 inner2（同组同根，同样允许 write）。
	mustApply(t, tr,
		[]Policy{{ID: "inner2", Group: "g", Root: "/a/b", Allowed: map[Perm]bool{Read: true, Write: true}}},
		[]string{"inner"})

	for _, v := range tr.Violations(true) {
		if v.PolicyID == "outer" {
			t.Fatalf("transient violation under outer leaked: %+v", v)
		}
	}
	if n := len(tr.Violations(false)); n != 0 {
		t.Fatalf("want 0 open violations, got %d", n)
	}
}

func mustApply(t *testing.T, tr *Tree, upserts []Policy, del []string) {
	t.Helper()
	if err := tr.ApplyPolicies(upserts, del); err != nil {
		t.Fatal(err)
	}
}

// 非法输入整体拒绝且状态不变。
func TestInvalidInputsRejected(t *testing.T) {
	tr := New()
	for _, p := range []string{"/a/b/f1", "/a/c/f2"} {
		if err := tr.AddFile(p); err != nil {
			t.Fatal(err)
		}
	}
	mustApply(t, tr, []Policy{{ID: "p1", Group: "g", Root: "/a",
		Allowed: map[Perm]bool{Read: true}}}, nil)
	before := len(tr.Violations(true))

	// 同组同根目录的两条策略。
	if err := tr.ApplyPolicies([]Policy{{ID: "p2", Group: "g", Root: "/a",
		Allowed: map[Perm]bool{Read: true, Write: true}}}, nil); err == nil {
		t.Fatal("duplicate (group, root) policy should be rejected")
	}
	// 一批超过 500 条。
	big := make([]Policy, 501)
	for i := range big {
		big[i] = Policy{ID: string(rune(i)), Group: "g", Root: "/x", Allowed: map[Perm]bool{}}
	}
	if err := tr.ApplyPolicies(big, nil); err == nil {
		t.Fatal("batch over 500 should be rejected")
	}
	// Move 到自身子树下。
	if err := tr.Move("/a", "/a/b"); err == nil {
		t.Fatal("move into own subtree should be rejected")
	}
	// 目标目录不存在。
	if err := tr.Move("/a/b/f1", "/nope"); err == nil {
		t.Fatal("move to missing dir should be rejected")
	}
	// 目标目录下重名。
	if err := tr.Move("/a/b", "/a"); err == nil {
		t.Fatal("move with name clash should be rejected")
	}
	// 全部拒绝后状态不变。
	if got := len(tr.Violations(true)); got != before {
		t.Fatalf("state changed after rejected ops: %d -> %d", before, got)
	}
	if err := tr.ApplyPolicies([]Policy{{ID: "p2", Group: "g", Root: "/a/b",
		Allowed: map[Perm]bool{Read: true}}}, nil); err != nil {
		t.Fatalf("valid upsert after rejections should succeed: %v", err)
	}
}
