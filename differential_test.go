package acltree

import (
	"fmt"
	"math/rand"
	"testing"
)

// 固定种子生成数千步随机操作，每步之后：
// 1. 未解决违规集合与朴素全量计算器完全一致；
// 2. 前后两步都存在的违规仍是同一条记录；
// 3. 新开/新解决的记录序号等于当前操作序号。
func TestDifferential(t *testing.T) {
	for _, seed := range []int64{26092901, 42, 777} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runDifferential(t, seed)
		})
	}
}

func runDifferential(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	tr := New()
	nv := newNaive()

	names := []string{"a", "b", "c", "d", "e", "f"}
	groups := []string{"g1", "g2", "g3"}
	randPath := func() string {
		depth := 1 + rng.Intn(5)
		segs := make([]string, depth)
		for i := range segs {
			segs[i] = names[rng.Intn(len(names))]
		}
		return joinPath(segs)
	}
	existingPath := func() string {
		var all []string
		for p := range nv.dirs {
			if p != "/" {
				all = append(all, p)
			}
		}
		for p := range nv.files {
			all = append(all, p)
		}
		if len(all) == 0 {
			return ""
		}
		return all[rng.Intn(len(all))]
	}
	existingDir := func() string {
		var all []string
		for p := range nv.dirs {
			all = append(all, p)
		}
		return all[rng.Intn(len(all))]
	}

	var seq uint64
	prev := make(map[[4]interface{}]*Violation)

	check := func(step int) {
		t.Helper()
		want := nv.violations()
		open := tr.Violations(false)
		got := make(map[[4]interface{}]*Violation, len(open))
		for _, v := range open {
			if v.Resolved != 0 {
				t.Fatalf("step %d: open violation has Resolved=%d", step, v.Resolved)
			}
			fid, ok := nv.files[v.File]
			if !ok {
				t.Fatalf("step %d: violation on unknown file %s", step, v.File)
			}
			got[[4]interface{}{fid, v.PolicyID, v.Group, v.Perm}] = v
		}
		if len(got) != len(want) {
			t.Fatalf("step %d: open count got %d want %d", step, len(got), len(want))
		}
		for k := range want {
			if _, ok := got[k]; !ok {
				t.Fatalf("step %d: missing violation %v", step, k)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Fatalf("step %d: unexpected violation %v", step, k)
			}
		}
		for k, v := range got {
			if old, ok := prev[k]; ok {
				if old != v {
					t.Fatalf("step %d: persistent violation %v changed record", step, k)
				}
			} else if v.Opened != seq {
				t.Fatalf("step %d: new violation %v Opened=%d want seq=%d", step, k, v.Opened, seq)
			}
		}
		for k, old := range prev {
			if _, ok := got[k]; !ok && old.Resolved != seq {
				t.Fatalf("step %d: vanished violation %v Resolved=%d want seq=%d", step, k, old.Resolved, seq)
			}
		}
		prev = got
	}

	const steps = 4000
	for step := 0; step < steps; step++ {
		var err error
		mutated := false
		switch op := rng.Intn(100); {
		case op < 42: // AddFile
			p := randPath()
			if err = tr.AddFile(p); err == nil {
				nv.addFile(p)
				mutated = true
			}
		case op < 48: // Remove
			if p := existingPath(); p != "" {
				if err = tr.Remove(p); err == nil {
					nv.remove(p)
					mutated = true
				}
			}
		case op < 58: // Move
			if src := existingPath(); src != "" {
				dst := existingDir()
				if err = tr.Move(src, dst); err == nil {
					nv.move(src, dst)
					mutated = true
				}
			}
		case op < 80: // SetACL
			if p := existingPath(); p != "" {
				n := rng.Intn(4)
				entries := make([]ACLEntry, 0, n)
				for i := 0; i < n; i++ {
					entries = append(entries, ACLEntry{
						Group:  groups[rng.Intn(len(groups))],
						Perm:   Perm(rng.Intn(2)),
						Effect: Effect(rng.Intn(2)),
					})
				}
				inherit := rng.Intn(10) >= 3
				if err = tr.SetACL(p, entries, inherit); err == nil {
					nv.setACL(p, entries, inherit)
					mutated = true
				}
			}
		default: // ApplyPolicies
			var ups []Policy
			for i, nu := 0, rng.Intn(4); i < nu; i++ {
				allowed := map[Perm]bool{Read: rng.Intn(2) == 0, Write: rng.Intn(2) == 0}
				ups = append(ups, Policy{
					ID:      fmt.Sprintf("p%d", rng.Intn(8)),
					Group:   groups[rng.Intn(len(groups))],
					Root:    randPath(),
					Allowed: allowed,
				})
			}
			var del []string
			seenDel := map[string]bool{}
			for i, nd := 0, rng.Intn(3); i < nd; i++ {
				id := fmt.Sprintf("p%d", rng.Intn(8))
				if !seenDel[id] {
					seenDel[id] = true
					del = append(del, id)
				}
			}
			if err = tr.ApplyPolicies(ups, del); err == nil {
				nv.applyPolicies(ups, del)
				mutated = true
			}
		}
		if mutated {
			seq++
		}
		check(step)
	}
	t.Logf("completed %d steps, final seq=%d, files=%d, policies=%d",
		steps, seq, len(nv.files), len(nv.policies))
}
