package acltree

import (
	"fmt"
	"testing"
)

// 规模 sanity：10 万文件下各操作的增量成本。
func TestScaleSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	tr := New()
	for i := 0; i < 100000; i++ {
		p := fmt.Sprintf("/d%d/sub%d/f%d", i%10, (i/10)%100, i)
		if err := tr.AddFile(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.SetACL("/d1", []ACLEntry{{Group: "g", Perm: Write, Effect: Allow}}, true); err != nil {
		t.Fatal(err)
	}
	mustApply(t, tr, []Policy{
		{ID: "p1", Group: "g", Root: "/d1", Allowed: map[Perm]bool{Read: true}},
		{ID: "p2", Group: "g", Root: "/d1/sub5", Allowed: map[Perm]bool{Read: true, Write: true}},
	}, nil)
	if err := tr.AddFile("/dest/x"); err != nil {
		t.Fatal(err)
	}
	if err := tr.Move("/d1/sub5", "/dest"); err != nil {
		t.Fatal(err)
	}
	if err := tr.Remove("/dest/sub5"); err != nil {
		t.Fatal(err)
	}
	if n := len(tr.files); n != 99901 {
		t.Fatalf("files=%d want 99901", n)
	}
	t.Logf("open=%d resolved=%d", len(tr.Violations(false)), len(tr.Violations(true)))
}
