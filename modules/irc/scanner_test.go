package irc

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Message
	}{
		{
			name: "numeric with prefix and trailing",
			line: ":irc.example.net 001 zgrab2 :Welcome to the Net zgrab2!u@h\r\n",
			want: Message{Prefix: "irc.example.net", Command: "001", Params: []string{"zgrab2"}, Trailing: "Welcome to the Net zgrab2!u@h"},
		},
		{
			name: "ping with colon token",
			line: "PING :ABC123\r\n",
			want: Message{Command: "PING", Trailing: "ABC123"},
		},
		{
			name: "ping without colon token",
			line: "PING ABC123\r\n",
			want: Message{Command: "PING", Params: []string{"ABC123"}},
		},
		{
			name: "isupport tokens",
			line: ":s 005 zgrab2 CHANTYPES=# PREFIX=(ov)@+ SAFELIST :are supported by this server\r\n",
			want: Message{Prefix: "s", Command: "005", Params: []string{"zgrab2", "CHANTYPES=#", "PREFIX=(ov)@+", "SAFELIST"}, Trailing: "are supported by this server"},
		},
		{
			name: "tags prefix command",
			line: "@time=2020-01-01 :nick!u@h PRIVMSG #c :hi there\r\n",
			want: Message{Tags: "time=2020-01-01", Prefix: "nick!u@h", Command: "PRIVMSG", Params: []string{"#c"}, Trailing: "hi there"},
		},
		{
			name: "lowercase command uppercased",
			line: "notice * :hello\r\n",
			want: Message{Command: "NOTICE", Params: []string{"*"}, Trailing: "hello"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMessage(tc.line)
			if got.Tags != tc.want.Tags || got.Prefix != tc.want.Prefix || got.Command != tc.want.Command || got.Trailing != tc.want.Trailing {
				t.Errorf("parseMessage(%q) = %+v, want %+v", tc.line, got, tc.want)
			}
			if strings.Join(got.Params, "|") != strings.Join(tc.want.Params, "|") {
				t.Errorf("parseMessage(%q) params = %v, want %v", tc.line, got.Params, tc.want.Params)
			}
		})
	}
}

func TestParseISupport(t *testing.T) {
	dst := map[string]string{}
	parseISupport([]string{"CHANTYPES=#", "PREFIX=(ov)@+", "SAFELIST", "", "MAXLIST=beI:60"}, dst)
	want := map[string]string{"CHANTYPES": "#", "PREFIX": "(ov)@+", "SAFELIST": "", "MAXLIST": "beI:60"}
	if len(dst) != len(want) {
		t.Fatalf("got %d tokens, want %d: %v", len(dst), len(want), dst)
	}
	for k, v := range want {
		if dst[k] != v {
			t.Errorf("token %q = %q, want %q", k, dst[k], v)
		}
	}
}

func TestParseServerInfo(t *testing.T) {
	mi := parseServerInfo([]string{"zgrab2", "irc.example.net", "InspIRCd-3", "iow", "ovh"})
	if mi == nil {
		t.Fatal("parseServerInfo returned nil")
	}
	if mi.ServerName != "irc.example.net" || mi.Version != "InspIRCd-3" || mi.UserModes != "iow" || mi.ChannelModes != "ovh" {
		t.Errorf("parseServerInfo = %+v", mi)
	}
	if parseServerInfo([]string{"zgrab2", "too", "few"}) != nil {
		t.Error("parseServerInfo with too few params should return nil")
	}
}

func TestGuessImplementation(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"running version InspIRCd-3", "InspIRCd"},
		{"UnrealIRCd-6.1.0", "UnrealIRCd"},
		{"solanum-1.0", "Solanum"},
		{"u2.10.12.19", "ircu"},                  // Undernet
		{"u2.10.12.18(gs2)", "ircu"},             // GameSurge
		{"u2.10.12.10+snircd(1.3.4a)", "snircd"}, // snircd must win over the u2.10 ircu match
		{"plexus-4(hybrid-8.1.20)", "Plexus"},    // Plexus must win over its hybrid base
		{"hybrid-7.2.2+oftc1.7.3", "ircd-hybrid"},
		{"DangerousIRCd-6.6.6", "DangerousIRCd"},
		{"some unknown ircd", ""},
	}
	for _, tc := range tests {
		if got := guessImplementation(tc.in); got != tc.want {
			t.Errorf("guessImplementation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// scriptedServer accepts one connection, drains client commands into a
// recorded slice, and writes the supplied transcript lines. It returns the
// listener address and a function that returns the recorded client lines.
func scriptedServer(t *testing.T, transcript []string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var received []string
	readerDone := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(readerDone)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Drain whatever the client sends until it closes (or the deadline).
		go func() {
			defer close(readerDone)
			r := bufio.NewReader(conn)
			for {
				line, err := r.ReadString('\n')
				if line != "" {
					mu.Lock()
					received = append(received, strings.TrimRight(line, "\r\n"))
					mu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}()

		for _, line := range transcript {
			if _, err := conn.Write([]byte(line)); err != nil {
				return
			}
		}
		// Keep the server side open until the client closes the connection so
		// trailing client writes (CAP END, PONG, QUIT) are read.
		<-readerDone
	}()

	// recorded blocks until the client has closed the connection and all of its
	// writes have been drained, then returns a snapshot of the recorded lines.
	return ln.Addr().String(), func() []string {
		<-readerDone
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(received))
		copy(out, received)
		return out
	}
}

func TestRegisterSuccess(t *testing.T) {
	transcript := []string{
		":irc.test NOTICE * :*** Looking up your hostname...\r\n",
		"CAP * LS :multi-prefix sasl message-tags\r\n",
		"PING :TOKEN123\r\n",
		":irc.test 001 zgrab2 :Welcome to the TestNet IRC Network zgrab2!zgrab2@host\r\n",
		":irc.test 002 zgrab2 :Your host is irc.test, running version InspIRCd-3\r\n",
		":irc.test 003 zgrab2 :This server was created Jan 1 2020\r\n",
		":irc.test 004 zgrab2 irc.test InspIRCd-3 iow ovh\r\n",
		":irc.test 005 zgrab2 CHANTYPES=# PREFIX=(ov)@+ NETWORK=TestNet SAFELIST :are supported by this server\r\n",
		":irc.test 251 zgrab2 :There are 100 users and 5 invisible on 2 servers\r\n",
		":irc.test 252 zgrab2 7 :IRC Operators online\r\n",
		":irc.test 254 zgrab2 42 :channels formed\r\n",
		":irc.test 375 zgrab2 :- irc.test Message of the Day -\r\n",
		":irc.test 372 zgrab2 :- Hello world\r\n",
		":irc.test 376 zgrab2 :End of /MOTD command.\r\n",
	}
	addr, recorded := scriptedServer(t, transcript)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := &Scanner{config: &Flags{Nick: "zgrab2", User: "zgrab2", RealName: "zgrab2 scanner"}}
	result := &ScanResults{ISupport: map[string]string{}}
	status, scanErr := scanner.register(NewConnection(c), result, false)

	if scanErr != nil {
		t.Fatalf("register error: %v", scanErr)
	}
	if status != "success" {
		t.Errorf("status = %q, want success", status)
	}
	if result.ServerName != "irc.test" {
		t.Errorf("ServerName = %q", result.ServerName)
	}
	if !strings.Contains(result.Welcome, "Welcome to the TestNet") {
		t.Errorf("Welcome = %q", result.Welcome)
	}
	if result.ServerInfo == nil || result.ServerInfo.Version != "InspIRCd-3" {
		t.Errorf("ServerInfo = %+v", result.ServerInfo)
	}
	if result.Implementation != "InspIRCd" {
		t.Errorf("Implementation = %q, want InspIRCd", result.Implementation)
	}
	if result.ISupport["NETWORK"] != "TestNet" || result.ISupport["CHANTYPES"] != "#" {
		t.Errorf("ISupport = %v", result.ISupport)
	}
	if _, ok := result.ISupport["SAFELIST"]; !ok {
		t.Errorf("ISupport missing valueless SAFELIST token: %v", result.ISupport)
	}
	if len(result.Capabilities) != 3 || result.Capabilities[0] != "multi-prefix" {
		t.Errorf("Capabilities = %v", result.Capabilities)
	}
	if !strings.Contains(result.MOTD, "Hello world") {
		t.Errorf("MOTD = %q", result.MOTD)
	}
	if result.Banner == "" || !strings.Contains(result.Banner, "Looking up your hostname") {
		t.Errorf("Banner = %q", result.Banner)
	}
	if len(result.LUsers) != 3 {
		t.Errorf("LUsers = %v", result.LUsers)
	}
	// 252/254 carry the count as a separate parameter; it must be preserved.
	if !containsStr(result.LUsers, "7 IRC Operators online") || !containsStr(result.LUsers, "42 channels formed") {
		t.Errorf("LUsers lost the count param: %v", result.LUsers)
	}

	// Close the client so the server drains the client's writes, then verify
	// the client honored the protocol: registered, ended CAP, answered PING.
	_ = c.Close()
	got := strings.Join(recorded(), "\n")
	for _, want := range []string{"CAP LS 302", "NICK zgrab2", "USER zgrab2 0 * :zgrab2 scanner", "CAP END", "PONG :TOKEN123"} {
		if !strings.Contains(got, want) {
			t.Errorf("client did not send %q; sent:\n%s", want, got)
		}
	}
}

func TestRegisterPasswordRequired(t *testing.T) {
	transcript := []string{
		":irc.test NOTICE * :*** Looking up your hostname...\r\n",
		"CAP * LS :sasl\r\n",
		":irc.test 464 zgrab2 :Password required\r\n",
	}
	addr, _ := scriptedServer(t, transcript)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := &Scanner{config: &Flags{Nick: "zgrab2", User: "zgrab2", RealName: "zgrab2 scanner"}}
	result := &ScanResults{ISupport: map[string]string{}}
	status, scanErr := scanner.register(NewConnection(c), result, false)

	if status != "application-error" {
		t.Errorf("status = %q, want application-error", status)
	}
	if scanErr == nil {
		t.Error("expected an error for password-required rejection")
	}
	if result.ErrorCode != "464" || !strings.Contains(result.Error, "Password required") {
		t.Errorf("ErrorCode=%q Error=%q", result.ErrorCode, result.Error)
	}
}

func TestValidate(t *testing.T) {
	if err := (Flags{Nick: "zgrab2", User: "zgrab2"}).Validate(nil); err != nil {
		t.Errorf("valid flags rejected: %v", err)
	}
	if err := (Flags{Nick: "", User: "zgrab2"}).Validate(nil); err == nil {
		t.Error("empty nick should be rejected")
	}
	if err := (Flags{Nick: "bad nick", User: "zgrab2"}).Validate(nil); err == nil {
		t.Error("nick with space should be rejected")
	}
	if err := (Flags{Nick: "zgrab2", User: ""}).Validate(nil); err == nil {
		t.Error("empty user should be rejected")
	}
	if err := (Flags{Nick: "zgrab2", User: "zgrab2", IRCS: true, StartTLS: true}).Validate(nil); err == nil {
		t.Error("--ircs and --starttls together should be rejected")
	}
}

// startRawServer listens on a loopback TCP port, accepts one connection, runs
// handler against it in a goroutine, and returns the address plus a channel
// that closes when handler returns.
func startRawServer(t *testing.T, handler func(net.Conn)) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	return ln.Addr().String(), done
}

// startTLSScanner builds a Scanner and DialerGroup wired to a pre-dialed
// connection, with an insecure TLS wrapper for the STARTTLS upgrade.
func startTLSScanner(t *testing.T, addr string) (*Scanner, *zgrab2.DialerGroup, *zgrab2.ScanTarget) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	scanner := &Scanner{config: &Flags{Nick: "zgrab2", User: "zgrab2", RealName: "zgrab2 scanner", StartTLS: true}}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(c),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}
	return scanner, dialGroup, target
}

func TestStartTLSSuccess(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)

	addr, done := startRawServer(t, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		// Plaintext STARTTLS negotiation.
		_, _ = r.ReadString('\n') // CAP LS 302
		_, _ = conn.Write([]byte("CAP * LS :tls multi-prefix sasl\r\n"))
		_, _ = r.ReadString('\n') // CAP REQ :tls
		_, _ = conn.Write([]byte("CAP * ACK :tls\r\n"))
		_, _ = r.ReadString('\n') // STARTTLS
		_, _ = conn.Write([]byte(":irc.test 670 zgrab2 :STARTTLS successful, proceed with TLS\r\n"))

		// Upgrade to TLS and continue registration over the encrypted link.
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			return
		}
		tr := bufio.NewReader(srv)
		for i := 0; i < 3; i++ { // NICK, USER, CAP END
			if _, err := tr.ReadString('\n'); err != nil {
				return
			}
		}
		_, _ = srv.Write([]byte(":irc.test 001 zgrab2 :Welcome to TestNet\r\n"))
		_, _ = srv.Write([]byte(":irc.test 004 zgrab2 irc.test InspIRCd-4 iow ovh\r\n"))
		_, _ = srv.Write([]byte(":irc.test 005 zgrab2 NETWORK=TestNet :are supported by this server\r\n"))
		_, _ = srv.Write([]byte(":irc.test 376 zgrab2 :End of /MOTD command.\r\n"))
		_, _ = tr.ReadString('\n') // QUIT
	})

	scanner, dialGroup, target := startTLSScanner(t, addr)
	status, resAny, scanErr := scanner.Scan(context.Background(), dialGroup, target)
	<-done

	if scanErr != nil {
		t.Fatalf("Scan error: %v", scanErr)
	}
	if status != "success" {
		t.Errorf("status = %q, want success", status)
	}
	res, ok := resAny.(*ScanResults)
	if !ok {
		t.Fatalf("result type = %T", resAny)
	}
	if res.StartTLS != "success" {
		t.Errorf("StartTLS = %q, want success", res.StartTLS)
	}
	if res.TLSLog == nil {
		t.Error("expected a TLS log")
	}
	if res.ServerName != "irc.test" {
		t.Errorf("ServerName = %q", res.ServerName)
	}
	if res.ServerInfo == nil || res.ServerInfo.Version != "InspIRCd-4" || res.Implementation != "InspIRCd" {
		t.Errorf("ServerInfo=%+v Implementation=%q", res.ServerInfo, res.Implementation)
	}
	if res.ISupport["NETWORK"] != "TestNet" {
		t.Errorf("ISupport = %v", res.ISupport)
	}
	if !containsStr(res.Capabilities, "tls") || !containsStr(res.Capabilities, "multi-prefix") {
		t.Errorf("Capabilities = %v, want tls and multi-prefix", res.Capabilities)
	}
}

func TestStartTLSUnsupported(t *testing.T) {
	var mu sync.Mutex
	var got []string

	addr, done := startRawServer(t, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				mu.Lock()
				got = append(got, strings.TrimRight(line, "\r\n"))
				mu.Unlock()
			}
			if err != nil {
				return
			}
			// Respond to the CAP LS without advertising tls.
			if strings.HasPrefix(line, "CAP LS") {
				_, _ = conn.Write([]byte("CAP * LS :multi-prefix sasl\r\n"))
			}
		}
	})

	scanner, dialGroup, target := startTLSScanner(t, addr)
	status, resAny, scanErr := scanner.Scan(context.Background(), dialGroup, target)
	<-done

	if status != "application-error" {
		t.Errorf("status = %q, want application-error", status)
	}
	if scanErr == nil {
		t.Error("expected an error when STARTTLS is unsupported")
	}
	res, ok := resAny.(*ScanResults)
	if !ok {
		t.Fatalf("result type = %T", resAny)
	}
	if res.StartTLS != "unsupported" {
		t.Errorf("StartTLS = %q, want unsupported", res.StartTLS)
	}
	if !containsStr(res.Capabilities, "multi-prefix") {
		t.Errorf("Capabilities = %v, want the advertised caps captured", res.Capabilities)
	}
	// Critically: the client must NOT have registered in plaintext.
	mu.Lock()
	defer mu.Unlock()
	for _, line := range got {
		if strings.HasPrefix(line, "NICK") || strings.HasPrefix(line, "USER") {
			t.Errorf("client leaked plaintext registration: %q (all: %v)", line, got)
		}
	}
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
