// Package irc provides a zgrab2 module that scans for IRC (Internet Relay
// Chat) servers.
// Default Port: 6667 (TCP), 6697 (TCP/TLS)
//
// The scanner performs the standard, unauthenticated client registration
// handshake (CAP/NICK/USER) that any IRC client sends on connect, then
// records the information the server volunteers in response: the welcome
// numerics (001-004), the RPL_ISUPPORT (005) feature tokens, the LUSERS
// network statistics, the MOTD, and any advertised IRCv3 capabilities.
//
// No credentials are ever sent: the module never sends PASS and aborts the
// session (QUIT) before anything resembling authentication. If a server
// requires a password or bans the client, the rejection is recorded as-is.
//
// The --ircs flag tells the scanner to perform a TLS handshake immediately
// after connecting, before registering (IRC over TLS, conventionally port
// 6697). The standard zgrab2 TLS flags configure the handshake.
//
// The --starttls flag tells the scanner to negotiate the IRCv3 STARTTLS
// extension (CAP REQ :tls; STARTTLS) and upgrade the connection to TLS before
// registering. IRCv3 STARTTLS is deprecated in favor of implicit TLS, but is
// supported for completeness. If the server does not offer it, the scan
// reports it as unsupported and does not fall back to plaintext registration.
// --ircs and --starttls are mutually exclusive.
//
// The --skip-cap flag disables IRCv3 capability negotiation (CAP LS 302).
package irc

import (
	"bufio"
	"net"
	"strings"

	"github.com/zmap/zgrab2"
)

// ScanResults is the result of an IRC scan, returned by the module's Scan
// function.
type ScanResults struct {
	// Banner collects any pre-registration NOTICE lines the server sends on
	// connect (e.g. "*** Looking up your hostname...").
	Banner string `json:"banner,omitempty"`

	// ServerName is the server's own name, taken from the prefix of the
	// RPL_WELCOME (001) reply.
	ServerName string `json:"server_name,omitempty"`

	// Welcome is the trailing text of RPL_WELCOME (001).
	Welcome string `json:"welcome,omitempty"`

	// YourHost is the trailing text of RPL_YOURHOST (002), which usually
	// names the server software and version.
	YourHost string `json:"your_host,omitempty"`

	// Created is the trailing text of RPL_CREATED (003).
	Created string `json:"created,omitempty"`

	// ServerInfo holds the parsed fields of RPL_MYINFO (004).
	ServerInfo *ServerInfo `json:"server_info,omitempty"`

	// ISupport maps RPL_ISUPPORT (005) feature tokens to their values. A
	// token with no value (a boolean feature) maps to the empty string.
	ISupport map[string]string `json:"isupport,omitempty"`

	// LUsers collects the human-readable network statistics lines
	// (RPL_LUSER* / RPL_LOCALUSERS / RPL_GLOBALUSERS).
	LUsers []string `json:"lusers,omitempty"`

	// MOTD is the server's message of the day, joined with newlines.
	MOTD string `json:"motd,omitempty"`

	// Capabilities lists the IRCv3 capabilities advertised in response to
	// CAP LS, if --skip-cap was not set.
	Capabilities []string `json:"capabilities,omitempty"`

	// Implementation is a best-effort guess of the server software (e.g.
	// "InspIRCd", "UnrealIRCd", "Solanum"), derived from the version strings.
	Implementation string `json:"implementation,omitempty"`

	// StartTLS records the outcome of IRCv3 STARTTLS negotiation when
	// --starttls is set: "success", "unsupported" (server did not advertise
	// the tls capability), or "failed" (the server rejected STARTTLS or the
	// TLS handshake failed).
	StartTLS string `json:"starttls,omitempty"`

	// ErrorCode is the numeric of a fatal registration reply, if any (e.g.
	// "433" nick in use, "464" password mismatch, "465" banned).
	ErrorCode string `json:"error_code,omitempty"`

	// Error is the human-readable text accompanying a fatal reply or an
	// ERROR line sent by the server.
	Error string `json:"error,omitempty"`

	// Raw contains every raw line received during the session. Only populated
	// when --verbose is set.
	Raw []string `json:"raw,omitempty"`

	// TLSLog is the standard TLS log, populated when --ircs is set.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// ServerInfo holds the parsed parameters of an RPL_MYINFO (004) reply.
type ServerInfo struct {
	ServerName   string `json:"server_name,omitempty"`
	Version      string `json:"version,omitempty"`
	UserModes    string `json:"user_modes,omitempty"`
	ChannelModes string `json:"channel_modes,omitempty"`
}

// Message is a parsed IRC protocol message of the form
//
//	[@tags] [:prefix] COMMAND [param ...] [:trailing]
type Message struct {
	// Tags is the IRCv3 message-tags blob (without the leading '@'), if present.
	Tags string
	// Prefix is the message source (without the leading ':'), if present.
	Prefix string
	// Command is the command name or three-digit numeric reply code.
	Command string
	// Params are the middle parameters (everything before the trailing arg).
	Params []string
	// Trailing is the final parameter (the part after " :"), if present.
	Trailing string
}

// LastParam returns the trailing parameter if present, otherwise the final
// middle parameter, otherwise the empty string. It is used to echo the token
// of a PING regardless of whether the server colon-prefixed it.
func (m *Message) LastParam() string {
	if m.Trailing != "" {
		return m.Trailing
	}
	if len(m.Params) > 0 {
		return m.Params[len(m.Params)-1]
	}
	return ""
}

// parseMessage parses a single line of IRC protocol into a Message. The line
// may include a trailing CR and/or LF, which are stripped.
func parseMessage(line string) *Message {
	msg := &Message{}
	rest := strings.TrimRight(line, "\r\n")

	if strings.HasPrefix(rest, "@") {
		part, remainder := splitToken(rest)
		msg.Tags = part[1:]
		rest = remainder
	}
	if strings.HasPrefix(rest, ":") {
		part, remainder := splitToken(rest)
		msg.Prefix = part[1:]
		rest = remainder
	}
	// Split off the trailing parameter, introduced by " :". The rest of the
	// line up to that point holds the command and any middle parameters.
	if idx := strings.Index(rest, " :"); idx >= 0 {
		msg.Trailing = rest[idx+2:]
		rest = rest[:idx]
	}
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		msg.Command = strings.ToUpper(fields[0])
		msg.Params = fields[1:]
	}
	return msg
}

// splitToken splits s on the first run of spaces, returning the first token
// and the remainder (with leading spaces trimmed).
func splitToken(s string) (string, string) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], strings.TrimLeft(s[i:], " ")
	}
	return s, ""
}

// parseISupport adds the KEY=VALUE feature tokens of an RPL_ISUPPORT (005)
// reply to dst. params[0] is the recipient nick and is skipped; the trailing
// "are supported by this server" text is not part of params. A token without
// a value maps to the empty string.
func parseISupport(params []string, dst map[string]string) {
	for _, tok := range params {
		if tok == "" {
			continue
		}
		if i := strings.IndexByte(tok, '='); i >= 0 {
			dst[tok[:i]] = tok[i+1:]
		} else {
			dst[tok] = ""
		}
	}
}

// parseServerInfo parses the parameters of an RPL_MYINFO (004) reply. The expected
// layout is [nick, servername, version, usermodes, channelmodes, ...].
func parseServerInfo(params []string) *ServerInfo {
	if len(params) < 5 {
		return nil
	}
	return &ServerInfo{
		ServerName:   params[1],
		Version:      params[2],
		UserModes:    params[3],
		ChannelModes: params[4],
	}
}

// implementationSignatures maps a lowercase substring found in a server
// version/host string to a canonical IRC server implementation name.
var implementationSignatures = []struct {
	needle string
	name   string
}{
	{"inspircd", "InspIRCd"},
	{"dangerousircd", "DangerousIRCd"},
	{"unreal", "UnrealIRCd"},
	{"solanum", "Solanum"},
	{"charybdis", "Charybdis"},
	{"ratbox", "ircd-ratbox"},
	{"ircd-seven", "ircd-seven"},
	// plexus must precede hybrid: Plexus advertises its hybrid base, e.g.
	// "plexus-4(hybrid-8.1.20)", and should be reported as Plexus.
	{"plexus", "Plexus"},
	{"hybrid", "ircd-hybrid"},
	{"bahamut", "Bahamut"},
	// snircd must precede the generic u2.10 ircu match: snircd advertises a
	// version like "u2.10.12.10+snircd(...)" and should be reported as snircd.
	{"snircd", "snircd"},
	{"ircu", "ircu"},
	{"u2.10", "ircu"}, // ircu's version scheme (e.g. Undernet u2.10.12.19, GameSurge u2.10.12.18(gs2))
	{"ngircd", "ngIRCd"},
	{"beware", "bewareircd"},
	{"nefarious", "Nefarious"},
	{"chatircd", "ChatIRCd"},
	{"elemental", "Elemental-IRCd"},
	{"ircd-2.", "ircd2 (classic)"},
}

// guessImplementation returns a best-effort server software name based on the
// version strings collected during registration, or "" if none match.
func guessImplementation(versions ...string) string {
	joined := strings.ToLower(strings.Join(versions, " "))
	for _, sig := range implementationSignatures {
		if strings.Contains(joined, sig.needle) {
			return sig.name
		}
	}
	return ""
}

// Connection wraps a net.Conn with a buffered, line-oriented reader for the
// IRC text protocol.
type Connection struct {
	Conn   net.Conn
	reader *bufio.Reader
}

// NewConnection returns a Connection that reads lines from conn.
func NewConnection(conn net.Conn) *Connection {
	return &Connection{Conn: conn, reader: bufio.NewReader(conn)}
}

// Send writes a single command to the server, appending the IRC CRLF
// terminator.
func (c *Connection) Send(command string) error {
	_, err := c.Conn.Write([]byte(command + "\r\n"))
	return err
}

// ReadMessage reads and parses a single line from the server. It returns the
// parsed Message, the raw line (CRLF trimmed), and any read error. If a
// partial final line is returned alongside an error (e.g. EOF), it is still
// parsed and returned.
func (c *Connection) ReadMessage() (*Message, string, error) {
	line, err := c.reader.ReadString('\n')
	if line == "" {
		return nil, "", err
	}
	raw := strings.TrimRight(line, "\r\n")
	return parseMessage(line), raw, err
}
