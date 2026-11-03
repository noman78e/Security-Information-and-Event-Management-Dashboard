package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"homesiem/capture"
	"homesiem/rules"
	"homesiem/store"
)

type destKey struct {
	dev, remote string
	port        int
}

// DestTracker remembers which outside addresses each device talks to.
// After a learning period, a brand-new destination raises an alert.
// Ordinary web/DNS/time ports are ignored because websites change addresses all the time.
type DestTracker struct {
	st *store.Store
	am *Alerts

	mu         sync.Mutex
	seen       map[destKey]struct{}
	learnStart map[string]int64
	maxSeen    int
}

func NewDestTracker(st *store.Store, am *Alerts) *DestTracker {
	d := &DestTracker{st: st, am: am, seen: map[destKey]struct{}{}, learnStart: map[string]int64{}, maxSeen: 100000}
	if rows, err := st.LoadDestSeen(d.maxSeen); err == nil {
		for _, r := range rows {
			d.seen[destKey{r.Dev, r.Remote, r.Port}] = struct{}{}
		}
	} else {
		log.Printf("load destinations: %v", err)
	}
	if m, err := st.DestLearnStarts(); err == nil {
		d.learnStart = m
	}
	return d
}

func matchStrict(list []string, dv store.Device) bool {
	for _, s := range list {
		s = strings.ToLower(strings.TrimSpace(s))
		switch {
		case s == "":
		case s == "*":
			return true
		case strings.EqualFold(s, dv.MAC) || s == dv.IP:
			return true
		case strings.Contains(strings.ToLower(dv.Hostname), s) || strings.Contains(strings.ToLower(dv.Vendor), s):
			return true
		}
	}
	return false
}

// OnFlows looks at one batch of flows (called whenever flows are saved).
func (d *DestTracker) OnFlows(rows []capture.FlowRow) {
	r := d.am.Config().Rules.NewDestination
	if !r.Enabled {
		return
	}
	byIP := map[string]store.Device{}
	if devs, err := d.st.ListDevices(); err == nil {
		for _, dv := range devs {
			byIP[dv.IP] = dv
		}
	}
	ignore := map[int]bool{}
	for _, p := range r.IgnorePorts {
		ignore[p] = true
	}
	now := time.Now().Unix()
	learnFor := int64(r.LearningHours) * 3600

	var add []store.DestRow
	d.mu.Lock()
	for _, f := range rows {
		if f.Dir != capture.DirUp || (f.Proto != "tcp" && f.Proto != "udp") || f.Port == 0 {
			continue
		}
		dv, known := byIP[f.Src]
		dev, label := f.Src, f.Src
		if known {
			dev, label = dv.MAC, describe(dv.IP, dv.Hostname, dv.Vendor)
		}
		if !(known && matchStrict(r.StrictDevices, dv)) && ignore[f.Port] {
			continue
		}
		k := destKey{dev, f.Dst, f.Port}
		if _, ok := d.seen[k]; ok || len(d.seen) >= d.maxSeen {
			continue
		}
		d.seen[k] = struct{}{}
		add = append(add, store.DestRow{Dev: dev, Remote: f.Dst, Port: f.Port, FirstSeen: now})

		start, ok := d.learnStart[dev]
		if !ok {
			d.learnStart[dev] = now // first sighting: start learning silently
			continue
		}
		if now < start+learnFor {
			continue
		}
		mac := ""
		if known {
			mac = dv.MAC
		}
		msg := fmt.Sprintf("New destination: %s connected to %s port %d/%s for the first time", label, f.Dst, f.Port, f.Proto)
		go d.am.Fire(rules.Alert{Rule: "new_destination", Key: dev, IP: f.Src, MAC: mac, Message: msg})
	}
	d.mu.Unlock()

	if err := d.st.AddDestSeen(add); err != nil {
		log.Printf("store destinations: %v", err)
	}
}
