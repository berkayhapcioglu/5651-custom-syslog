package ingest

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// UnknownSource is an address that sent logs but belongs to no tenant.
type UnknownSource struct {
	Addr  netip.Addr
	Proto string
	Count int64
	First time.Time
	Last  time.Time
}

// Unknown remembers recent unknown sources so the panel can offer to add
// them to a tenant. It is bounded; the least recently seen entry is evicted.
type Unknown struct {
	mu  sync.Mutex
	m   map[netip.Addr]*UnknownSource
	max int
}

// NewUnknown keeps at most max addresses.
func NewUnknown(max int) *Unknown { return &Unknown{m: map[netip.Addr]*UnknownSource{}, max: max} }

func (u *Unknown) note(a netip.Addr, proto string, now time.Time) {
	if u == nil {
		return
	}
	a = a.Unmap()
	u.mu.Lock()
	defer u.mu.Unlock()
	e := u.m[a]
	if e == nil {
		if len(u.m) >= u.max {
			var oldest netip.Addr
			var ot time.Time
			for k, v := range u.m {
				if ot.IsZero() || v.Last.Before(ot) {
					oldest, ot = k, v.Last
				}
			}
			delete(u.m, oldest)
		}
		e = &UnknownSource{Addr: a, First: now}
		u.m[a] = e
	}
	e.Count++
	e.Last = now
	e.Proto = proto
}

// List returns the unknown sources, most recently seen first.
func (u *Unknown) List() []UnknownSource {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]UnknownSource, 0, len(u.m))
	for _, v := range u.m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

// Forget removes an address, e.g. after it was added to a tenant.
func (u *Unknown) Forget(a netip.Addr) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.m, a.Unmap())
}
