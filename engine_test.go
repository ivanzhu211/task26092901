package acltree

import "testing"

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func findOpen(t *testing.T, e *Engine, policyID string, perm Perm) *Violation {
	t.Helper()
	for _, v := range e.Violations(false) {
		if v.PolicyID == policyID && v.Perm == perm {
			return v
		}
	}
	return nil
}

// A deeper same-group policy takes over: the outer policy's violation is
// resolved and a fresh record appears under the inner policy.
func TestNestedPolicyResolution(t *testing.T) {
	e := New()
	mustOK(t, e.AddFile("/a/b/f"))
	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "outer", Group: "g", Root: "/a", Allowed: map[Perm]bool{Read: true}},
	}, nil))
	mustOK(t, e.SetACL("/a/b", []ACLEntry{
		{Group: "g", Perm: Write, Effect: Allow},
	}, true))

	outer := findOpen(t, e, "outer", Write)
	if outer == nil {
		t.Fatal("expected open violation under outer policy")
	}
	if outer.File != "/a/b/f" || outer.Group != "g" || outer.Resolved != 0 {
		t.Fatalf("bad outer record: %+v", outer)
	}

	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "inner", Group: "g", Root: "/a/b", Allowed: map[Perm]bool{Read: true}},
	}, nil))

	if v := findOpen(t, e, "outer", Write); v != nil {
		t.Fatalf("outer violation still open: %+v", v)
	}
	inner := findOpen(t, e, "inner", Write)
	if inner == nil {
		t.Fatal("expected open violation under inner policy")
	}
	if inner.Opened <= outer.Opened {
		t.Fatalf("inner record should be new: inner.Opened=%d outer.Opened=%d", inner.Opened, outer.Opened)
	}
	if outer.Resolved != inner.Opened {
		t.Fatalf("outer.Resolved=%d want %d", outer.Resolved, inner.Opened)
	}
	all := e.Violations(true)
	if len(all) != 2 {
		t.Fatalf("expected 2 total records, got %d", len(all))
	}
}

// Deleting an inner policy and adding a replacement in the same batch
// must not produce transient violations under the outer policy.
func TestBatchAtomicity(t *testing.T) {
	e := New()
	mustOK(t, e.AddFile("/a/b/f"))
	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "outer", Group: "g", Root: "/a", Allowed: map[Perm]bool{Read: true}},
		{ID: "inner", Group: "g", Root: "/a/b", Allowed: map[Perm]bool{Read: true, Write: true}},
	}, nil))
	mustOK(t, e.SetACL("/a/b", []ACLEntry{
		{Group: "g", Perm: Write, Effect: Allow},
	}, true))
	if n := len(e.Violations(false)); n != 0 {
		t.Fatalf("expected no violations, got %d", n)
	}

	// One batch: drop "inner", add "inner2" that still allows write.
	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "inner2", Group: "g", Root: "/a/b", Allowed: map[Perm]bool{Read: true, Write: true}},
	}, []string{"inner"}))

	if n := len(e.Violations(false)); n != 0 {
		t.Fatalf("expected no violations after batch, got %d", n)
	}
	for _, v := range e.Violations(true) {
		if v.PolicyID == "outer" {
			t.Fatalf("transient outer violation recorded: %+v", v)
		}
	}
}

func TestDenyWinsAndInheritStops(t *testing.T) {
	e := New()
	mustOK(t, e.AddFile("/a/b/f"))
	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "p", Group: "g", Root: "/", Allowed: map[Perm]bool{}},
	}, nil))

	// allow and deny for the same (group, perm) on one node: deny wins.
	mustOK(t, e.SetACL("/a", []ACLEntry{
		{Group: "g", Perm: Read, Effect: Allow},
		{Group: "g", Perm: Read, Effect: Deny},
	}, true))
	if n := len(e.Violations(false)); n != 0 {
		t.Fatalf("deny should win, expected no violations, got %d", n)
	}

	// inherit=false on /a/b blocks the allow from /a.
	mustOK(t, e.SetACL("/a", []ACLEntry{
		{Group: "g", Perm: Read, Effect: Allow},
	}, true))
	if findOpen(t, e, "p", Read) == nil {
		t.Fatal("expected read violation from inherited allow")
	}
	mustOK(t, e.SetACL("/a/b", nil, false))
	if n := len(e.Violations(false)); n != 0 {
		t.Fatalf("inherit=false should block ancestor entries, got %d", n)
	}
}

func TestInvalidInputsRejected(t *testing.T) {
	e := New()
	mustOK(t, e.AddFile("/a/b/f"))
	mustOK(t, e.AddFile("/a/c/g"))
	before := e.Violations(true)

	if err := e.Move("/a/b", "/a/b"); err == nil {
		t.Fatal("move into self should fail")
	}
	if err := e.Move("/a", "/a/b"); err == nil {
		t.Fatal("move into own subtree should fail")
	}
	if err := e.Move("/a/b", "/nonexistent"); err == nil {
		t.Fatal("move to missing dir should fail")
	}
	if err := e.Move("/a/b", "/a"); err == nil {
		t.Fatal("move to occupied name should fail")
	}
	if err := e.SetACL("/nope", nil, true); err == nil {
		t.Fatal("SetACL on missing path should fail")
	}
	if err := e.Remove("/nope"); err == nil {
		t.Fatal("Remove on missing path should fail")
	}
	if err := e.ApplyPolicies(nil, []string{"ghost"}); err == nil {
		t.Fatal("delete of unknown policy should fail")
	}
	if err := e.ApplyPolicies([]Policy{
		{ID: "p1", Group: "g", Root: "/a", Allowed: map[Perm]bool{}},
		{ID: "p2", Group: "g", Root: "/a", Allowed: map[Perm]bool{}},
	}, nil); err == nil {
		t.Fatal("duplicate (group, root) should fail")
	}
	big := make([]Policy, 501)
	for i := range big {
		big[i] = Policy{ID: string(rune('A' + i)), Group: "g", Root: "/a", Allowed: map[Perm]bool{}}
	}
	if err := e.ApplyPolicies(big, nil); err == nil {
		t.Fatal("batch over 500 should fail")
	}
	after := e.Violations(true)
	if len(before) != len(after) {
		t.Fatalf("rejected ops changed state: %d -> %d records", len(before), len(after))
	}
}

func TestMovePreservesIdentity(t *testing.T) {
	e := New()
	mustOK(t, e.AddFile("/x/f"))
	mustOK(t, e.AddFile("/y/dummy"))
	mustOK(t, e.ApplyPolicies([]Policy{
		{ID: "p", Group: "g", Root: "/", Allowed: map[Perm]bool{}},
	}, nil))
	mustOK(t, e.SetACL("/x", []ACLEntry{
		{Group: "g", Perm: Read, Effect: Allow},
	}, true))
	rec := findOpen(t, e, "p", Read)
	if rec == nil {
		t.Fatal("expected violation")
	}
	mustOK(t, e.Move("/x", "/y"))
	rec2 := findOpen(t, e, "p", Read)
	if rec2 != rec {
		t.Fatalf("expected same record after move, got %+v", rec2)
	}
	if rec2.File != "/y/x/f" {
		t.Fatalf("path not updated after move: %s", rec2.File)
	}
	if rec2.Resolved != 0 {
		t.Fatal("record should still be open")
	}
}
