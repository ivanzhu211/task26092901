package acltree

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// ---- Independent naive model: recomputes everything from scratch. ----

type mKey struct {
	group string
	perm  Perm
}

type mACL struct {
	bits    map[mKey]uint8
	inherit bool
}

type model struct {
	files map[string]bool
	dirs  map[string]bool
	acls  map[string]*mACL
	pols  map[string]Policy
}

func newModel() *model {
	return &model{
		files: map[string]bool{},
		dirs:  map[string]bool{"/": true},
		acls:  map[string]*mACL{},
		pols:  map[string]Policy{},
	}
}

func parentOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (m *model) addFile(path string) {
	m.files[path] = true
	for p := parentOf(path); ; p = parentOf(p) {
		m.dirs[p] = true
		if p == "/" {
			break
		}
	}
}

func (m *model) remove(path string) {
	prefix := path + "/"
	delete(m.files, path)
	delete(m.dirs, path)
	delete(m.acls, path)
	for p := range m.files {
		if strings.HasPrefix(p, prefix) {
			delete(m.files, p)
		}
	}
	for p := range m.dirs {
		if strings.HasPrefix(p, prefix) {
			delete(m.dirs, p)
		}
	}
	for p := range m.acls {
		if strings.HasPrefix(p, prefix) {
			delete(m.acls, p)
		}
	}
}

func (m *model) move(src, dstDir string) {
	prefix := src + "/"
	join := func(dir, name string) string {
		if dir == "/" {
			return "/" + name
		}
		return dir + "/" + name
	}
	reloc := func(p string) (string, bool) {
		if p == src {
			return join(dstDir, p[strings.LastIndex(p, "/")+1:]), true
		}
		if strings.HasPrefix(p, prefix) {
			return join(dstDir, src[strings.LastIndex(src, "/")+1:]) + p[len(src):], true
		}
		return "", false
	}
	for _, set := range []map[string]bool{m.files, m.dirs} {
		var moves [][2]string
		for p := range set {
			if np, ok := reloc(p); ok {
				moves = append(moves, [2]string{p, np})
			}
		}
		for _, mv := range moves {
			delete(set, mv[0])
			set[mv[1]] = true
		}
	}
	next := map[string]*mACL{}
	for p, a := range m.acls {
		if np, ok := reloc(p); ok {
			next[np] = a
		} else {
			next[p] = a
		}
	}
	m.acls = next
}

func (m *model) setACL(path string, entries []ACLEntry, inherit bool) {
	bits := map[mKey]uint8{}
	for _, en := range entries {
		k := mKey{en.Group, en.Perm}
		if en.Effect == Deny {
			bits[k] |= 2
		} else {
			bits[k] |= 1
		}
	}
	m.acls[path] = &mACL{bits: bits, inherit: inherit}
}

func (m *model) applyPolicies(upserts []Policy, deleteIDs []string) {
	for _, id := range deleteIDs {
		delete(m.pols, id)
	}
	for _, u := range upserts {
		root, err := normalizeRoot(u.Root)
		if err != nil {
			panic(err)
		}
		u.Root = root
		m.pols[u.ID] = u
	}
}

// naiveEffective walks up the path chain; deny wins at the nearest node
// with an entry; the search stops at the first inherit=false node.
func (m *model) naiveEffective(f, group string, perm Perm) (Effect, bool) {
	for cur := f; ; cur = parentOf(cur) {
		if a := m.acls[cur]; a != nil {
			if bits, ok := a.bits[mKey{group, perm}]; ok {
				if bits&2 != 0 {
					return Deny, true
				}
				return Allow, true
			}
			if !a.inherit {
				return 0, false
			}
		}
		if cur == "/" {
			return 0, false
		}
	}
}

func covers(root, f string) bool {
	return root == "/" || root == f || strings.HasPrefix(f, root+"/")
}

type tuple struct {
	file, policyID, group string
	perm                  Perm
}

func (m *model) naiveViolations() map[tuple]bool {
	out := map[tuple]bool{}
	for f := range m.files {
		// Nearest covering policy per group.
		byGroup := map[string]Policy{}
		depth := map[string]int{}
		for _, p := range m.pols {
			if !covers(p.Root, f) {
				continue
			}
			d := 0
			if p.Root != "/" {
				d = strings.Count(strings.TrimPrefix(p.Root, "/"), "/") + 1
			}
			if cur, seen := byGroup[p.Group]; !seen || d > depth[p.Group] {
				byGroup[p.Group] = p
				depth[p.Group] = d
				_ = cur
			}
		}
		for g, p := range byGroup {
			for _, perm := range []Perm{Read, Write} {
				if p.Allowed[perm] {
					continue
				}
				if eff, ok := m.naiveEffective(f, g, perm); ok && eff == Allow {
					out[tuple{f, p.ID, g, perm}] = true
				}
			}
		}
	}
	return out
}

// ---- Randomized differential test. ----

func engineOpen(e *Engine) (map[tuple]*Violation, []*Violation) {
	open := map[tuple]*Violation{}
	for _, v := range e.Violations(false) {
		open[tuple{v.File, v.PolicyID, v.Group, v.Perm}] = v
	}
	return open, e.Violations(true)
}

func TestDifferentialRandom(t *testing.T) {
	for _, seed := range []int64{26092901, 42, 7} {
		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			runDifferential(t, seed)
		})
	}
}

func runDifferential(t *testing.T, seed int64) {
	rnd := rand.New(rand.NewSource(seed))
	e := New()
	m := newModel()

	groups := []string{"g0", "g1", "g2", "g3", "g4"}
	pickGroup := func() string { return groups[rnd.Intn(len(groups))] }

	randPath := func(maxDepth int) string {
		d := 1 + rnd.Intn(maxDepth)
		var b strings.Builder
		for i := 0; i < d; i++ {
			b.WriteString("/d")
			b.WriteByte(byte('0' + rnd.Intn(7)))
		}
		return b.String()
	}
	sortedKeys := func(set map[string]bool) []string {
		var out []string
		for k := range set {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	randDir := func() string {
		dirs := sortedKeys(m.dirs)
		return dirs[rnd.Intn(len(dirs))]
	}
	joinPath := func(dir, name string) string {
		if dir == "/" {
			return "/" + name
		}
		return dir + "/" + name
	}
	randNode := func() string {
		var nodes []string
		for d := range m.dirs {
			if d != "/" {
				nodes = append(nodes, d)
			}
		}
		for f := range m.files {
			nodes = append(nodes, f)
		}
		if len(nodes) == 0 {
			return ""
		}
		sort.Strings(nodes)
		return nodes[rnd.Intn(len(nodes))]
	}
	randEntries := func() []ACLEntry {
		n := rnd.Intn(5)
		var out []ACLEntry
		for i := 0; i < n; i++ {
			perm := Perm(rnd.Intn(2))
			eff := Effect(rnd.Intn(2))
			g := pickGroup()
			out = append(out, ACLEntry{Group: g, Perm: perm, Effect: eff})
			if rnd.Intn(10) < 3 { // same node, opposite effect: deny must win
				out = append(out, ACLEntry{Group: g, Perm: perm, Effect: 1 - eff})
			}
		}
		return out
	}

	var prevOpen map[tuple]*Violation
	steps := 6000
	var log []string
	fail := func(format string, args ...interface{}) {
		for _, l := range log {
			t.Log(l)
		}
		t.Fatalf(format, args...)
	}
	for step := 0; step < steps; step++ {
		op := rnd.Intn(100)
		var err error
		var desc string
		switch {
		case op < 32: // AddFile
			if len(m.files) < 300 {
				path := joinPath(randDir(), "f"+string(byte('0'+rnd.Intn(40))))
				if rnd.Intn(10) < 3 { // nest under new intermediate dirs
					path = joinPath(path, "d"+string(byte('0'+rnd.Intn(7))))
					path = joinPath(path, "f"+string(byte('0'+rnd.Intn(40))))
				}
				desc = fmt.Sprintf("AddFile(%s)", path)
				err = e.AddFile(path)
				if err == nil {
					m.addFile(path)
				}
			}
		case op < 38: // Remove
			if n := randNode(); n != "" {
				desc = fmt.Sprintf("Remove(%s)", n)
				err = e.Remove(n)
				if err == nil {
					m.remove(n)
				}
			}
		case op < 50: // Move
			if src := randNode(); src != "" {
				dst := randDir()
				desc = fmt.Sprintf("Move(%s, %s)", src, dst)
				err = e.Move(src, dst)
				if err == nil {
					m.move(src, dst)
				}
			}
		case op < 76: // SetACL
			if n := randNode(); n != "" {
				entries := randEntries()
				inherit := rnd.Intn(10) > 2
				desc = fmt.Sprintf("SetACL(%s, %v, %v)", n, entries, inherit)
				err = e.SetACL(n, entries, inherit)
				if err == nil {
					m.setACL(n, entries, inherit)
				}
			}
		case op < 94: // ApplyPolicies
			var ups []Policy
			var dels []string
			nUp := rnd.Intn(4)
			for i := 0; i < nUp; i++ {
				root := randDir()
				if rnd.Intn(10) < 2 {
					root = randPath(4) // possibly nonexistent root
				}
				allowed := map[Perm]bool{}
				if rnd.Intn(2) == 0 {
					allowed[Read] = true
				}
				if rnd.Intn(2) == 0 {
					allowed[Write] = true
				}
				ups = append(ups, Policy{
					ID:      "p" + string(byte('0'+rnd.Intn(12))),
					Group:   pickGroup(),
					Root:    root,
					Allowed: allowed,
				})
			}
			var ids []string
			for id := range m.pols {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			if len(ids) > 0 && rnd.Intn(2) == 0 {
				dels = append(dels, ids[rnd.Intn(len(ids))])
			}
			err = e.ApplyPolicies(ups, dels)
			if err == nil {
				m.applyPolicies(ups, dels)
			}
			desc = fmt.Sprintf("ApplyPolicies(%v, %v) err=%v", ups, dels, err)
		default: // deliberately invalid operations
			switch rnd.Intn(4) {
			case 0: // move into own subtree
				if n := randNode(); n != "" && n != "/" {
					if e.Move(n, n) == nil {
						t.Fatalf("step %d: move into self accepted", step)
					}
				}
			case 1: // duplicate (group, root) in one batch
				g := pickGroup()
				r := randDir()
				if e.ApplyPolicies([]Policy{
					{ID: "dupA", Group: g, Root: r, Allowed: map[Perm]bool{}},
					{ID: "dupB", Group: g, Root: r, Allowed: map[Perm]bool{}},
				}, nil) == nil {
					t.Fatalf("step %d: duplicate (group, root) accepted", step)
				}
			case 2: // delete unknown policy
				if e.ApplyPolicies(nil, []string{"no-such-policy"}) == nil {
					t.Fatalf("step %d: unknown delete accepted", step)
				}
			case 3: // batch too large
				big := make([]Policy, 501)
				for i := range big {
					big[i] = Policy{ID: "x" + strings.Repeat("y", i%5) + strings.TrimSpace(strings.Repeat("z", i%3)) + string(rune(i)), Group: "g9", Root: "/nowhere", Allowed: map[Perm]bool{}}
				}
				if e.ApplyPolicies(big, nil) == nil {
					t.Fatalf("step %d: oversized batch accepted", step)
				}
			}
		}
		_ = err
		log = append(log, fmt.Sprintf("step %d: %s err=%v", step, desc, err))
		if len(log) > 30 {
			log = log[1:]
		}

		// Compare open violations with the naive full recomputation.
		want := m.naiveViolations()
		got, all := engineOpen(e)
		if len(got) != len(want) {
			for tp := range got {
				if !want[tp] {
					n := e.lookup(tp.file)
					for cur := n; cur != nil; cur = cur.parent {
						t.Logf("engine chain %s entries=%v inherit=%v", cur.path(), cur.entries, cur.inherit)
					}
					for p := tp.file; ; p = parentOf(p) {
						if a := m.acls[p]; a != nil {
							t.Logf("model chain %s bits=%v inherit=%v", p, a.bits, a.inherit)
						}
						if p == "/" {
							break
						}
					}
				}
			}
			fail("step %d: open count mismatch: engine=%d naive=%d\nengine: %v\nnaive: %v", step, len(got), len(want), keysOf(got), keysOfW(want))
		}
		for tp := range want {
			if _, ok := got[tp]; !ok {
				t.Fatalf("step %d: missing violation %+v", step, tp)
			}
		}
		for tp := range got {
			if _, ok := want[tp]; !ok {
				t.Fatalf("step %d: unexpected violation %+v", step, tp)
			}
		}
		// Violations persisting across steps must be the same record.
		for tp, rec := range got {
			if prev, ok := prevOpen[tp]; ok && prev != rec {
				t.Fatalf("step %d: violation %+v changed identity", step, tp)
			}
		}
		// Resolved records must stay resolved and never reappear open.
		openCount := 0
		for _, v := range all {
			if v.Resolved == 0 {
				openCount++
			}
		}
		if openCount != len(got) {
			t.Fatalf("step %d: open/all inconsistent: %d vs %d", step, openCount, len(got))
		}
		prevOpen = got
	}
	t.Logf("completed %d steps, %d files, %d policies, %d total records",
		steps, len(m.files), len(m.pols), len(e.Violations(true)))
}

func keysOf(m map[tuple]*Violation) []tuple {
	var out []tuple
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfW(m map[tuple]bool) []tuple {
	var out []tuple
	for k := range m {
		out = append(out, k)
	}
	return out
}
