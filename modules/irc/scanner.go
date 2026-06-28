package irc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

// maxLines bounds the number of protocol lines read during registration so a
// chatty or hostile server cannot make a single scan run unbounded. The
// per-read and per-target timeouts are the primary safeguards; this is a
// backstop.
const maxLines = 2000

// Flags holds the command-line configuration for the IRC scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// IRCS indicates that the client should perform a TLS handshake
	// immediately after connecting, before registering.
	IRCS bool `long:"ircs" description:"Immediately negotiate a TLS connection before registering (IRC over TLS, e.g. port 6697)"`

	// StartTLS indicates that the client should negotiate the IRCv3 STARTTLS
	// extension (CAP REQ :tls; STARTTLS) and upgrade the connection to TLS
	// before registering. Note: IRCv3 STARTTLS is deprecated in favor of
	// implicit TLS (--ircs); this is provided for completeness.
	StartTLS bool `long:"starttls" description:"Upgrade to TLS via the IRCv3 STARTTLS extension before registering"`

	// Nick is the nickname used during registration.
	Nick string `long:"nick" description:"Nickname to register with" default:"zgrab2"`

	// User is the username (ident) used during registration.
	User string `long:"user" description:"Username (ident) to register with" default:"zgrab2"`

	// RealName is the real name (gecos) used during registration.
	RealName string `long:"real-name" description:"Real name to register with" default:"zgrab2 scanner"`

	// SkipCAP disables IRCv3 capability negotiation (CAP LS 302).
	SkipCAP bool `long:"skip-cap" description:"Skip IRCv3 capability negotiation (CAP LS)"`
}

// Scanner implements the zgrab2.Scanner interface for IRC.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a new IRC module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"irc",
		"Internet Relay Chat (IRC)",
		"Register an unauthenticated IRC client and collect the server's welcome numerics, ISUPPORT tokens, capabilities, and MOTD, optionally over TLS.",
		6667,
	)
}

// Validate checks that the flags are internally consistent.
func (flags Flags) Validate(_ []string) error {
	if flags.IRCS && flags.StartTLS {
		return fmt.Errorf("%w: --ircs and --starttls are mutually exclusive", zgrab2.ErrInvalidArguments)
	}
	if strings.TrimSpace(flags.Nick) == "" || strings.ContainsAny(flags.Nick, " \r\n") {
		return fmt.Errorf("%w: --nick must be a non-empty single token", zgrab2.ErrInvalidArguments)
	}
	if strings.TrimSpace(flags.User) == "" || strings.ContainsAny(flags.User, " \r\n") {
		return fmt.Errorf("%w: --user must be a non-empty single token", zgrab2.ErrInvalidArguments)
	}
	if strings.ContainsAny(flags.RealName, "\r\n") {
		return fmt.Errorf("%w: --real-name must not contain newlines", zgrab2.ErrInvalidArguments)
	}
	return nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// Scan performs the IRC scan:
//  1. Open a TCP connection to the target port (default 6667).
//  2. If --ircs is set, perform a TLS handshake using the command-line flags.
//  3. Optionally send CAP LS 302 to enumerate IRCv3 capabilities.
//  4. Send NICK and USER (no credentials) and read the registration burst,
//     answering any PING, until the welcome/MOTD completes or the server
//     rejects the registration.
//  5. Send QUIT and close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("l4 dialer is required for irc")
	}
	tlsWrapper := dialGroup.TLSWrapper
	if tlsWrapper == nil && (scanner.config.IRCS || scanner.config.StartTLS) {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("TLS wrapper is required for irc with --ircs or --starttls")
	}

	c, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error connecting to target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(c)

	result := &ScanResults{ISupport: map[string]string{}}

	if scanner.config.IRCS {
		tlsConn, tlsErr := tlsWrapper(ctx, target, c)
		if tlsConn != nil {
			result.TLSLog = tlsConn.GetLog()
		}
		if tlsErr != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, result, fmt.Errorf("error wrapping connection in TLS for target %s: %w", target.String(), tlsErr)
		}
		c = tlsConn
	}

	conn := NewConnection(c)
	capPreNegotiated := false

	if scanner.config.StartTLS {
		upgraded, stStatus, stErr := scanner.doStartTLS(ctx, conn, tlsWrapper, target, result)
		if stErr != nil {
			// Report the failure; do not fall back to plaintext registration.
			_ = conn.Send("QUIT :zgrab2")
			if len(result.ISupport) == 0 {
				result.ISupport = nil
			}
			return stStatus, result, stErr
		}
		conn = upgraded
		capPreNegotiated = true
	}

	status, scanErr := scanner.register(conn, result, capPreNegotiated)

	// Be a polite client: try to QUIT before disconnecting. Ignore errors --
	// the connection may already be gone, and the result is already gathered.
	_ = conn.Send("QUIT :zgrab2")

	if len(result.ISupport) == 0 {
		result.ISupport = nil
	}
	return status, result, scanErr
}

// register drives the client registration handshake and populates result with
// everything the server reports. capPreNegotiated indicates that CAP LS was
// already sent and consumed (by the STARTTLS step) and the CAP session is still
// open -- in that case register skips CAP LS and closes negotiation with CAP
// END once registration is sent.
func (scanner *Scanner) register(conn *Connection, result *ScanResults, capPreNegotiated bool) (zgrab2.ScanStatus, error) {
	sendCap := !scanner.config.SkipCAP && !capPreNegotiated
	capEnded := !sendCap

	if sendCap {
		if err := conn.Send("CAP LS 302"); err != nil {
			return zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send CAP LS: %w", err)
		}
	}
	nick := scanner.config.Nick
	if err := conn.Send("NICK " + nick); err != nil {
		return zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send NICK: %w", err)
	}
	if err := conn.Send(fmt.Sprintf("USER %s 0 * :%s", scanner.config.User, scanner.config.RealName)); err != nil {
		return zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send USER: %w", err)
	}
	if capPreNegotiated {
		// CAP LS was already exchanged during STARTTLS; close the still-open
		// negotiation so the server proceeds with registration.
		if err := conn.Send("CAP END"); err != nil {
			return zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send CAP END: %w", err)
		}
	}

	var banner, motd strings.Builder
	nickRetries := 0
	gotWelcome := false

	for lines := 0; lines < maxLines; lines++ {
		msg, raw, err := conn.ReadMessage()
		if msg != nil && msg.Command != "" {
			if scanner.config.Verbose {
				result.Raw = append(result.Raw, raw)
			}
			done := scanner.handleMessage(conn, msg, result, &banner, &motd, &nick, &nickRetries, &gotWelcome, &capEnded)
			if done {
				break
			}
		}
		if err != nil {
			break
		}
	}

	if s := strings.TrimRight(banner.String(), "\n"); s != "" {
		// Preserve any banner captured earlier (e.g. during STARTTLS).
		result.Banner = joinNonEmpty(result.Banner, s)
	}
	if s := strings.TrimRight(motd.String(), "\n"); s != "" {
		result.MOTD = s
	}
	result.Implementation = guessImplementation(result.YourHost, serverInfoVersion(result.ServerInfo))

	switch {
	case gotWelcome:
		return zgrab2.SCAN_SUCCESS, nil
	case result.Error != "":
		return zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("server rejected registration: %s", result.Error)
	case result.Banner != "":
		// The server spoke IRC (greeting notices / ERROR) but never completed
		// registration. Report what we saw rather than discarding it.
		return zgrab2.SCAN_APPLICATION_ERROR, errors.New("connection closed before registration completed")
	default:
		return zgrab2.SCAN_PROTOCOL_ERROR, errors.New("no IRC response received")
	}
}

// handleMessage processes a single parsed server message, updating result and
// the in-progress banner/MOTD builders. It returns true when registration has
// reached a terminal state (success or fatal rejection) and the read loop
// should stop.
func (scanner *Scanner) handleMessage(conn *Connection, msg *Message, result *ScanResults, banner, motd *strings.Builder, nick *string, nickRetries *int, gotWelcome, capEnded *bool) (done bool) {
	switch msg.Command {
	case "PING":
		// Must answer or the server will not complete registration.
		_ = conn.Send("PONG :" + msg.LastParam())

	case "NOTICE":
		// Pre/peri-registration server notices form the connection banner.
		appendLine(banner, msg.Trailing)

	case "CAP":
		scanner.handleCAP(conn, msg, result, capEnded)

	case "ERROR":
		result.Error = firstNonEmpty(msg.Trailing, strings.Join(msg.Params, " "))
		return true

	case "001": // RPL_WELCOME
		*gotWelcome = true
		result.ServerName = msg.Prefix
		result.Welcome = msg.Trailing
	case "002": // RPL_YOURHOST
		result.YourHost = msg.Trailing
	case "003": // RPL_CREATED
		result.Created = msg.Trailing
	case "004": // RPL_MYINFO
		result.ServerInfo = parseServerInfo(msg.Params)
	case "005": // RPL_ISUPPORT
		if len(msg.Params) > 1 {
			parseISupport(msg.Params[1:], result.ISupport)
		}

	case "251", "255", "265", "266": // LUSERS family: count is in the trailing text
		if line := firstNonEmpty(msg.Trailing, strings.Join(msg.Params[min(1, len(msg.Params)):], " ")); line != "" {
			result.LUsers = append(result.LUsers, line)
		}
	case "252", "253", "254": // LUSERS family: count is a separate param, trailing is its label
		count := strings.Join(msg.Params[min(1, len(msg.Params)):], " ")
		if line := strings.TrimSpace(count + " " + msg.Trailing); line != "" {
			result.LUsers = append(result.LUsers, line)
		}

	case "372": // RPL_MOTD
		appendLine(motd, msg.Trailing)
	case "375": // RPL_MOTDSTART
		appendLine(motd, msg.Trailing)
	case "376", "422": // RPL_ENDOFMOTD / ERR_NOMOTD -- registration is complete
		return true

	case "432": // ERR_ERRONEUSNICKNAME
		result.ErrorCode = msg.Command
		result.Error = firstNonEmpty(msg.Trailing, "erroneous nickname")
		return true
	case "433": // ERR_NICKNAMEINUSE -- pick a fresh nick and retry a couple times
		if *nickRetries < 2 {
			*nickRetries++
			*nick = scanner.config.Nick + strings.Repeat("_", *nickRetries)
			_ = conn.Send("NICK " + *nick)
			return false
		}
		result.ErrorCode = msg.Command
		result.Error = firstNonEmpty(msg.Trailing, "nickname in use")
		return true
	case "464": // ERR_PASSWDMISMATCH
		result.ErrorCode = msg.Command
		result.Error = firstNonEmpty(msg.Trailing, "password required")
		return true
	case "465": // ERR_YOUREBANNEDCREEP
		result.ErrorCode = msg.Command
		result.Error = firstNonEmpty(msg.Trailing, "banned from server")
		return true
	}
	return false
}

// handleCAP processes a CAP reply. It accumulates the capabilities advertised
// by CAP LS and, once the final (non-continuation) LS line is received, ends
// negotiation with CAP END so the server proceeds with registration.
func (scanner *Scanner) handleCAP(conn *Connection, msg *Message, result *ScanResults, capEnded *bool) {
	// CAP <target> <subcommand> [*] :<space-separated caps>
	// params[0] is the target (nick or "*"); params[1] is the subcommand; an
	// optional "*" before the trailing list marks a multi-line continuation.
	if len(msg.Params) < 2 || !strings.EqualFold(msg.Params[1], "LS") {
		return
	}
	result.Capabilities = append(result.Capabilities, strings.Fields(msg.Trailing)...)
	continuation := len(msg.Params) >= 3 && msg.Params[2] == "*"
	if !continuation && !*capEnded {
		*capEnded = true
		_ = conn.Send("CAP END")
	}
}

// tlsWrapperFunc upgrades an existing net.Conn to a TLS connection. It matches
// the signature of DialerGroup.TLSWrapper.
type tlsWrapperFunc func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error)

// doStartTLS negotiates the IRCv3 STARTTLS extension and upgrades the
// connection to TLS before registration. It runs CAP LS (capturing the
// advertised capabilities), verifies the server offers the "tls" capability,
// requests it with CAP REQ :tls, sends STARTTLS, waits for RPL_STARTTLS (670),
// and then performs the TLS handshake. On success it returns a new Connection
// wrapping the TLS connection. On failure it records result.StartTLS and
// returns a status and error -- it never falls back to plaintext registration.
func (scanner *Scanner) doStartTLS(ctx context.Context, conn *Connection, tlsWrapper tlsWrapperFunc, target *zgrab2.ScanTarget, result *ScanResults) (*Connection, zgrab2.ScanStatus, error) {
	var banner strings.Builder
	defer func() {
		if s := strings.TrimRight(banner.String(), "\n"); s != "" {
			result.Banner = joinNonEmpty(result.Banner, s)
		}
	}()

	if err := conn.Send("CAP LS 302"); err != nil {
		return nil, zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send CAP LS: %w", err)
	}

	// Phase 1: read CAP LS (possibly multi-line) and learn whether tls is offered.
	tlsOffered := false
	for lines := 0; lines < maxLines; lines++ {
		msg, raw, err := conn.ReadMessage()
		capDone := false
		if msg != nil && msg.Command != "" {
			if scanner.config.Verbose {
				result.Raw = append(result.Raw, raw)
			}
			switch msg.Command {
			case "PING":
				_ = conn.Send("PONG :" + msg.LastParam())
			case "NOTICE":
				appendLine(&banner, msg.Trailing)
			case "CAP":
				if len(msg.Params) >= 2 && strings.EqualFold(msg.Params[1], "LS") {
					for _, c := range strings.Fields(msg.Trailing) {
						result.Capabilities = append(result.Capabilities, c)
						if capName(c) == "tls" {
							tlsOffered = true
						}
					}
					// A "*" parameter before the trailing list marks a
					// continuation line; otherwise this is the final LS line.
					continuation := len(msg.Params) >= 3 && msg.Params[2] == "*"
					if !continuation {
						capDone = true
					}
				}
			}
		}
		if capDone {
			break
		}
		if err != nil {
			result.StartTLS = "failed"
			return nil, zgrab2.TryGetScanStatus(err), fmt.Errorf("error during CAP negotiation: %w", err)
		}
	}
	if !tlsOffered {
		result.StartTLS = "unsupported"
		return nil, zgrab2.SCAN_APPLICATION_ERROR, errors.New("server does not advertise the tls capability")
	}

	// Phase 2: request the tls capability and wait for the ACK.
	if err := conn.Send("CAP REQ :tls"); err != nil {
		return nil, zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send CAP REQ :tls: %w", err)
	}
	if status, err := scanner.awaitCapTLSAck(conn, result); err != nil {
		return nil, status, err
	}

	// Phase 3: send STARTTLS and wait for RPL_STARTTLS (670).
	if err := conn.Send("STARTTLS"); err != nil {
		return nil, zgrab2.TryGetScanStatus(err), fmt.Errorf("failed to send STARTTLS: %w", err)
	}
	for lines := 0; lines < maxLines; lines++ {
		msg, raw, err := conn.ReadMessage()
		if msg != nil && msg.Command != "" {
			if scanner.config.Verbose {
				result.Raw = append(result.Raw, raw)
			}
			switch msg.Command {
			case "PING":
				_ = conn.Send("PONG :" + msg.LastParam())
			case "670": // RPL_STARTTLS -- proceed with the handshake
				return scanner.upgradeTLS(ctx, conn, tlsWrapper, target, result)
			case "691": // ERR_STARTTLS
				result.StartTLS = "failed"
				return nil, zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("server returned ERR_STARTTLS: %s", firstNonEmpty(msg.Trailing, "STARTTLS failed"))
			}
		}
		if err != nil {
			result.StartTLS = "failed"
			return nil, zgrab2.TryGetScanStatus(err), fmt.Errorf("error waiting for STARTTLS response: %w", err)
		}
	}
	result.StartTLS = "failed"
	return nil, zgrab2.SCAN_APPLICATION_ERROR, errors.New("no STARTTLS response received")
}

// awaitCapTLSAck waits for the server to ACK (or NAK) the tls capability.
func (scanner *Scanner) awaitCapTLSAck(conn *Connection, result *ScanResults) (zgrab2.ScanStatus, error) {
	for lines := 0; lines < maxLines; lines++ {
		msg, raw, err := conn.ReadMessage()
		if msg != nil && msg.Command != "" {
			if scanner.config.Verbose {
				result.Raw = append(result.Raw, raw)
			}
			switch msg.Command {
			case "PING":
				_ = conn.Send("PONG :" + msg.LastParam())
			case "CAP":
				if len(msg.Params) >= 2 {
					switch strings.ToUpper(msg.Params[1]) {
					case "ACK":
						if capListContains(msg.Trailing, "tls") {
							return zgrab2.SCAN_SUCCESS, nil
						}
					case "NAK":
						result.StartTLS = "failed"
						return zgrab2.SCAN_APPLICATION_ERROR, errors.New("server NAK'd the tls capability")
					}
				}
			}
		}
		if err != nil {
			result.StartTLS = "failed"
			return zgrab2.TryGetScanStatus(err), fmt.Errorf("error waiting for CAP ACK: %w", err)
		}
	}
	result.StartTLS = "failed"
	return zgrab2.SCAN_APPLICATION_ERROR, errors.New("no CAP ACK for tls received")
}

// upgradeTLS performs the TLS handshake on the existing connection after the
// server has accepted STARTTLS.
func (scanner *Scanner) upgradeTLS(ctx context.Context, conn *Connection, tlsWrapper tlsWrapperFunc, target *zgrab2.ScanTarget, result *ScanResults) (*Connection, zgrab2.ScanStatus, error) {
	tlsConn, err := tlsWrapper(ctx, target, conn.Conn)
	if tlsConn != nil {
		result.TLSLog = tlsConn.GetLog()
	}
	if err != nil {
		result.StartTLS = "failed"
		return nil, zgrab2.SCAN_HANDSHAKE_ERROR, fmt.Errorf("STARTTLS handshake failed for %s: %w", target.String(), err)
	}
	result.StartTLS = "success"
	return NewConnection(tlsConn), zgrab2.SCAN_SUCCESS, nil
}

// serverInfoVersion returns the version string from a ServerInfo, or "" if nil.
func serverInfoVersion(mi *ServerInfo) string {
	if mi == nil {
		return ""
	}
	return mi.Version
}

// appendLine appends s plus a newline to b when s is non-empty.
func appendLine(b *strings.Builder, s string) {
	if s == "" {
		return
	}
	b.WriteString(s)
	b.WriteByte('\n')
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// capName returns the name portion of a capability token (the part before an
// '=' value separator, if any).
func capName(token string) string {
	if i := strings.IndexByte(token, '='); i >= 0 {
		return token[:i]
	}
	return token
}

// capListContains reports whether a space-separated capability list contains
// the named capability, ignoring any "=value" suffix.
func capListContains(list, name string) bool {
	for _, c := range strings.Fields(list) {
		if capName(c) == name {
			return true
		}
	}
	return false
}

// joinNonEmpty joins two strings with a newline, skipping empty operands.
func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "\n" + b
	}
}
