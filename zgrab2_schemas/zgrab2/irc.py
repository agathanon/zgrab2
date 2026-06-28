# zschema sub-schema for zgrab2's irc module
# Registers zgrab2-irc globally, and irc with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

irc_server_info = SubRecord(
    {
        "server_name": String(doc="The server name reported in RPL_MYINFO (004)."),
        "version": String(
            doc="The server software version reported in RPL_MYINFO (004)."
        ),
        "user_modes": String(doc="The user modes supported, from RPL_MYINFO (004)."),
        "channel_modes": String(
            doc="The channel modes supported, from RPL_MYINFO (004)."
        ),
    }
)

irc_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(
                    doc="Pre-registration NOTICE lines the server sent on connect."
                ),
                "server_name": String(
                    doc="The server's own name, from the RPL_WELCOME (001) prefix."
                ),
                "welcome": String(doc="The RPL_WELCOME (001) message."),
                "your_host": String(doc="The RPL_YOURHOST (002) message."),
                "created": String(doc="The RPL_CREATED (003) message."),
                "server_info": irc_server_info,
                "isupport": SubRecord(
                    {},
                    allow_unknown=True,
                    doc="The RPL_ISUPPORT (005) feature tokens, as key/value pairs. "
                    "Keys are server-defined token names; values are strings "
                    "(empty for valueless boolean flags).",
                ),
                "lusers": ListOf(
                    String(),
                    doc="The network statistics lines (RPL_LUSER* / LOCALUSERS / GLOBALUSERS).",
                ),
                "motd": String(doc="The server's message of the day."),
                "capabilities": ListOf(
                    String(),
                    doc="The IRCv3 capabilities advertised in response to CAP LS.",
                ),
                "implementation": String(
                    doc="Best-effort guess of the server software (e.g. InspIRCd, UnrealIRCd)."
                ),
                "starttls": String(
                    doc="Outcome of IRCv3 STARTTLS negotiation when --starttls is set: success, unsupported, or failed."
                ),
                "error_code": String(
                    doc="The numeric of a fatal registration reply (e.g. 433, 464, 465)."
                ),
                "error": String(
                    doc="The text of a fatal reply or an ERROR line from the server."
                ),
                "raw": ListOf(
                    String(),
                    doc="Every raw protocol line received (only with --verbose).",
                ),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-irc", irc_scan_response)

zgrab2.register_scan_response_type("irc", irc_scan_response)
