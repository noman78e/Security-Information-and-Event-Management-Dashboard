package fw

import (
	"strings"
	"testing"
)

func has(t *testing.T, script, want string) {
	t.Helper()
	if !strings.Contains(script, want) {
		t.Fatalf("script is missing %q:\n%s", want, script)
	}
}

func lacks(t *testing.T, script, bad string) {
	t.Helper()
	if strings.Contains(script, bad) {
		t.Fatalf("script must not contain %q:\n%s", bad, script)
	}
}

func TestBlockByMAC(t *testing.T) {
	s := Script([]Entry{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.20", Block: true}}, true)
	has(t, s, "table inet homesiem\ndelete table inet homesiem\n")
	has(t, s, "type filter hook forward priority -10; policy accept;")
	has(t, s, "ether saddr AA:BB:CC:DD:EE:01 drop")
	has(t, s, "ip daddr 192.168.1.20 drop")
	has(t, s, "type filter hook input priority -10; policy accept;")
}

func TestBlockByIPWhenMACMatchingIsUnavailable(t *testing.T) {
	s := Script([]Entry{{MAC: "AA:BB:CC:DD:EE:01", IP: "192.168.1.20", Block: true}}, false)
	has(t, s, "ip saddr 192.168.1.20 drop")
	has(t, s, "ip daddr 192.168.1.20 drop")
	lacks(t, s, "ether saddr")
	// without MAC matching and without an IP a device cannot be blocked
	s = Script([]Entry{{MAC: "AA:BB:CC:DD:EE:02", Block: true}}, false)
	has(t, s, "cannot block AA:BB:CC:DD:EE:02")
}

func TestSpeedLimit(t *testing.T) {
	s := Script([]Entry{{MAC: "AA:BB:CC:DD:EE:03", IP: "192.168.1.30", LimitKBytes: 125}}, true)
	has(t, s, "ether saddr AA:BB:CC:DD:EE:03 limit rate over 125 kbytes/second burst 31")
	has(t, s, "ip daddr 192.168.1.30 limit rate over 125 kbytes/second")
	lacks(t, s, "ether saddr AA:BB:CC:DD:EE:03 drop") // limited, not blocked
}

func TestBlockWinsOverLimit(t *testing.T) {
	s := Script([]Entry{{MAC: "AA:BB:CC:DD:EE:04", IP: "192.168.1.40", Block: true, LimitKBytes: 125}}, true)
	has(t, s, "ether saddr AA:BB:CC:DD:EE:04 drop")
	lacks(t, s, "limit rate")
}

func TestNothingBadReachesTheScript(t *testing.T) {
	s := Script([]Entry{
		{MAC: "AA:BB:CC:DD:EE:05; flush ruleset", IP: "1.2.3.4", Block: true},
		{MAC: "AA:BB:CC:DD:EE:06", IP: "1.2.3.4; flush ruleset", Block: true},
		{MAC: "AA:BB:CC:DD:EE:07", IP: "fe80::1", Block: true},
	}, true)
	lacks(t, s, "flush ruleset")
	lacks(t, s, "fe80")
	lacks(t, s, "EE:05")
	has(t, s, "ether saddr AA:BB:CC:DD:EE:06 drop") // the valid MAC is still blocked
	lacks(t, s, "ip daddr 1.2.3.4;")
}

func TestEmptyScriptIsHarmless(t *testing.T) {
	s := Script(nil, true)
	has(t, s, "policy accept")
	lacks(t, s, "drop\n")
}

func TestParseGateway(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if g := ParseGateway(route); g != "192.168.1.1" {
		t.Fatalf("gateway = %q", g)
	}
	if g := ParseGateway("Iface\tDestination\n"); g != "" {
		t.Fatalf("expected no gateway, got %q", g)
	}
}

func TestParseCapEff(t *testing.T) {
	root := "Name:\thomesiem\nCapEff:\t000001ffffffffff\n"
	service := "Name:\thomesiem\nCapEff:\t0000000000003000\n" // CAP_NET_ADMIN (12) and CAP_NET_RAW (13)
	plain := "Name:\thomesiem\nCapEff:\t0000000000000000\n"
	if !parseCapEff(root) || !parseCapEff(service) || parseCapEff(plain) || parseCapEff("nothing here") {
		t.Fatal("capability parsing is wrong")
	}
}
