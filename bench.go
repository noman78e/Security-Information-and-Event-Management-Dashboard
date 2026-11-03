package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"homesiem/auth"
	"homesiem/capture"
	"homesiem/store"
)

// runBench is "homesiem bench": it measures how much work this computer can
// do, so you can tell whether it is fast enough for your network.
func runBench() {
	fmt.Printf("HomeSIEM benchmark: %s/%s, %d CPU core(s), %s\n\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())

	// 1. reading packet headers and counting them into flows, on one core
	local := &net.IPNet{IP: net.IPv4(192, 168, 1, 0).To4(), Mask: net.CIDRMask(24, 32)}
	agg := capture.NewAggregator(local, 20000)
	frame := make([]byte, 14+20+20)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0], ip[9] = 0x45, capture.ProtoTCP
	copy(ip[12:16], []byte{192, 168, 1, 20})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	ip[20], ip[21], ip[22], ip[23] = 0xc3, 0x50, 0x01, 0xbb
	n := 0
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		for i := 0; i < 1000; i++ {
			ip[18], ip[19] = byte(n>>8), byte(n) // many different destinations, so the flow table is used for real
			agg.Add(capture.Parse(frame), 1200)
			n++
		}
	}
	pps := float64(n) / time.Since(start).Seconds()
	fmt.Printf("Packet analysis:   %9.0f packets per second (one core)\n", pps)

	// 2. database writes and a search, in a temporary folder
	dir, err := os.MkdirTemp("", "homesiem-bench")
	if err == nil {
		defer os.RemoveAll(dir)
		if st, err := store.Open(filepath.Join(dir, "bench.db")); err == nil {
			rows := make([]store.LogRow, 200)
			start = time.Now()
			for b := 0; b < 50; b++ {
				for i := range rows {
					rows[i] = store.LogRow{TS: time.Now().Unix(), SrcIP: "10.0.0.1", Host: "bench", Program: "bench",
						Facility: 1, Severity: 6, Message: fmt.Sprintf("benchmark message number %d with some typical text", b*200+i)}
				}
				st.AddLogs(rows)
			}
			fmt.Printf("Log storage:       %9.0f messages per second written\n", 10000/time.Since(start).Seconds())
			start = time.Now()
			st.SearchLogs(store.LogQuery{Text: "number 9999", MaxSeverity: -1, Limit: 100})
			fmt.Printf("Log search:        %9.0f ms to search 10,000 messages\n", float64(time.Since(start).Microseconds())/1000)
			st.Close()
		} else {
			fmt.Printf("Database test skipped: %v\n", err)
		}
	}

	// 3. how long one sign-in takes
	start = time.Now()
	auth.HashPassword("benchmark password")
	fmt.Printf("Sign-in:           %9.0f ms to check a password\n", float64(time.Since(start).Microseconds())/1000)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("Memory:            %9.1f MB used by this test\n\n", float64(ms.Sys)/1024/1024)

	fmt.Println("How to read this:")
	fmt.Println("  A busy home network is roughly 500 to 5,000 packets per second. If packet")
	fmt.Println("  analysis is well above that (at least 3 times), live capture will keep up.")
	fmt.Println("  Log storage should be well above 200 messages per second, the default")
	fmt.Println("  limit for one sender. A sign-in under about 2,000 ms is fine.")
}
