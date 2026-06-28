package irc

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// FuzzParseMessage fuzzes the line parser directly. The parser handles raw,
// untrusted bytes from the server, so it must never panic regardless of input.
func FuzzParseMessage(f *testing.F) {
	seeds := []string{
		":irc.example.net 001 zgrab2 :Welcome to the Net zgrab2!u@h\r\n",
		"PING :ABC123\r\n",
		"PING ABC123\r\n",
		":s 005 zgrab2 CHANTYPES=# PREFIX=(ov)@+ SAFELIST :are supported by this server\r\n",
		"@time=2020-01-01 :nick!u@h PRIVMSG #c :hi there\r\n",
		"ERROR :Closing Link\r\n",
		"", "@", ":", " :", "@ :", "::::", "   ", "\r\n",
		"CAP * LS * :multi-prefix sasl\r\n",
		":x 004 a b c d e f g\r\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		msg := parseMessage(line)
		// Invariants the rest of the module relies on:
		//  - a parsed command never contains whitespace (callers switch on it)
		//  - LastParam is safe to call and returns one of the parsed fields
		if strings.ContainsAny(msg.Command, " \t\r\n") {
			t.Fatalf("command contains whitespace: %q (line %q)", msg.Command, line)
		}
		_ = msg.LastParam()
	})
}

// FuzzParseISupport fuzzes the RPL_ISUPPORT token parser with arbitrary
// space-separated tokens.
func FuzzParseISupport(f *testing.F) {
	f.Add("CHANTYPES=# PREFIX=(ov)@+ SAFELIST")
	f.Add("=")
	f.Add("-NICKLEN A=B=C MAXLIST=beI:60")
	f.Add("")

	f.Fuzz(func(t *testing.T, tokens string) {
		dst := map[string]string{}
		parseISupport(strings.Fields(tokens), dst)
	})
}

// FuzzRegister fuzzes the full registration read loop against an arbitrary
// server response stream. This exercises ReadMessage, handleMessage, and every
// numeric/CAP parsing path on untrusted bytes, mirroring how omronfins fuzzes
// its query paths.
func FuzzRegister(f *testing.F) {
	seeds := []string{
		// A well-formed, successful registration burst.
		":irc.test NOTICE * :*** Looking up your hostname...\r\n" +
			"CAP * LS :multi-prefix sasl\r\n" +
			"PING :TOKEN123\r\n" +
			":irc.test 001 zgrab2 :Welcome\r\n" +
			":irc.test 004 zgrab2 irc.test ngircd-27 abc def\r\n" +
			":irc.test 005 zgrab2 CHANTYPES=# NETWORK=Test :are supported\r\n" +
			":irc.test 375 zgrab2 :- MOTD -\r\n" +
			":irc.test 372 zgrab2 :- hello\r\n" +
			":irc.test 376 zgrab2 :End of /MOTD command.\r\n",
		// Nick collision then rejection.
		":irc.test 433 zgrab2 :Nickname already in use\r\n",
		// Immediate fatal error.
		"ERROR :Closing Link: too many connections\r\n",
		// Garbage / truncated input.
		"not an irc line at all",
		"",
		"\r\n\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		clientConn, serverConn := net.Pipe()
		deadline := time.Now().Add(5 * time.Second)
		_ = clientConn.SetDeadline(deadline)
		_ = serverConn.SetDeadline(deadline)
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer serverConn.Close()
			// Drain whatever the client writes so its sends (CAP LS, NICK,
			// USER, PONG, CAP END, nick retries) never block on the synchronous
			// pipe.
			go func() {
				buf := make([]byte, 1024)
				for {
					if _, err := serverConn.Read(buf); err != nil {
						return
					}
				}
			}()
			// Feed the fuzzed server response, then close to signal EOF.
			_, _ = serverConn.Write(data)
		}()

		scanner := &Scanner{config: &Flags{Nick: "zgrab2", User: "zgrab2", RealName: "zgrab2 scanner"}}
		result := &ScanResults{ISupport: map[string]string{}}
		_, _ = scanner.register(NewConnection(clientConn), result, false)
		_ = clientConn.Close()
		<-done
	})
}

// FuzzDoStartTLS fuzzes the STARTTLS negotiation parsing (CAP LS / CAP ACK /
// STARTTLS / 670 / 691) against arbitrary server bytes. The TLS wrapper is
// stubbed to always fail, so the handshake path returns cleanly without real
// crypto while every plaintext parsing branch is exercised.
func FuzzDoStartTLS(f *testing.F) {
	seeds := []string{
		"CAP * LS :tls multi-prefix\r\n",                 // tls offered -> proceeds to REQ
		"CAP * LS :multi-prefix sasl\r\n",                // no tls -> unsupported
		"CAP * LS :tls\r\nCAP * ACK :tls\r\n670 :ok\r\n", // full happy path (until stubbed handshake)
		"CAP * LS :tls\r\nCAP * NAK :tls\r\n",            // NAK
		"CAP * LS :tls\r\nCAP * ACK :tls\r\n691 :no\r\n", // ERR_STARTTLS
		"PING :x\r\n",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	failingWrapper := testhelpers.MakeFailingTLSWrapper()
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 6667}

	f.Fuzz(func(t *testing.T, data []byte) {
		clientConn, serverConn := net.Pipe()
		deadline := time.Now().Add(5 * time.Second)
		_ = clientConn.SetDeadline(deadline)
		_ = serverConn.SetDeadline(deadline)
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer serverConn.Close()
			go func() {
				buf := make([]byte, 1024)
				for {
					if _, err := serverConn.Read(buf); err != nil {
						return
					}
				}
			}()
			_, _ = serverConn.Write(data)
		}()

		scanner := &Scanner{config: &Flags{Nick: "zgrab2", User: "zgrab2", RealName: "zgrab2 scanner", StartTLS: true}}
		result := &ScanResults{ISupport: map[string]string{}}
		_, _, _ = scanner.doStartTLS(context.Background(), NewConnection(clientConn), failingWrapper, target, result)
		_ = clientConn.Close()
		<-done
	})
}
