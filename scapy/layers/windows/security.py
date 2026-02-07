# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter
# pylint: disable=invalid-name

"""
Python objects for Microsoft Windows security structures.
"""

from dataclasses import dataclass
import enum
import re
import struct
from typing import Optional

from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagValue,
    FlagsField,
    LEIntField,
    LELongField,
    LenField,
    LEShortEnumField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    ShortField,
    StrFieldUtf16,
    StrFixedLenField,
    StrLenField,
    StrLenFieldUtf16,
    UUIDField,
)

from scapy.layers.ntlm import (
    _NTLMPayloadField,
    _NTLMPayloadPacket,
    _NTLM_ENUM,
    _NTLM_post_build,
)

# [MS-DTYP] sect 2.4.1


class WINNT_SID_IDENTIFIER_AUTHORITY(Packet):
    """
    Security Identifier (SID) Identifier Authority
    Standard values are:
        - SECURITY_NULL_SID_AUTHORITY	        0	S-1-0
        - SECURITY_WORLD_SID_AUTHORITY  	    1	S-1-1
        - SECURITY_LOCAL_SID_AUTHORITY  	    2	S-1-2
        - SECURITY_CREATOR_SID_AUTHORITY        3	S-1-3
        - NON_UNIQUE_AUTHORITY        	        4	S-1-4
        - SECURITY_NT_AUTHORITY 	            5	S-1-5
        - SECURITY_APP_PACKAGE_AUTHORITY	    15	S-1-15
        - SECURITY_MANDATORY_LABEL_AUTHORITY    16	S-1-16
        - SECURITY_SCOPED_POLICY_ID_AUTHORITY   17	S-1-17
        - SECURITY_AUTHENTICATION_AUTHORITY     18	S-1-18
    """

    fields_desc: list[StrFixedLenField] = [
        StrFixedLenField("Value", b"\x00\x00\x00\x00\x00\x01", length=6),
    ]

    def default_payload_class(self, payload: bytes) -> Packet:
        return conf.padding_layer


# [MS-DTYP] sect 2.4.2


class WINNT_SID(Packet):
    """Complete Security Identifier (SID) structure"""

    fields_desc = [
        ByteField("Revision", 1),
        FieldLenField("SubAuthorityCount", None, count_of="SubAuthority", fmt="B"),
        PacketField(
            "IdentifierAuthority",
            WINNT_SID_IDENTIFIER_AUTHORITY(),
            WINNT_SID_IDENTIFIER_AUTHORITY,
        ),
        FieldListField(
            "SubAuthority",
            [0],
            LEIntField("", 0),
            count_from=lambda pkt: pkt.SubAuthorityCount,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Packet:
        return conf.padding_layer

    _SID_REG = re.compile(r"^S-(\d)-(\d+)((?:-\d+)*)$")

    @staticmethod
    def fromstr(x: str):
        """
        Helper to create a SID from its string representation.

        :param x: string representation of the SID like "S-1-5-18"
        :type x: str

        .. code-block:: python
            >>> from scapy.layers.win_security import WINNT_SID
            >>> WINNT_SID.fromstr("S-1-5-18")
            <WINNT_SID  Revision=1 IdentifierAuthority=<WINNT_SID_IDENTIFIER_AUTHORITY
            Value=b'\x00\x00\x00\x00\x00\x05' |> SubAuthority=[18] |>
            >>> _.summary()
            >>> 'S-1-5-18'
        """

        m = WINNT_SID._SID_REG.match(x)
        if not m:
            raise ValueError("Invalid SID format !")
        rev, authority, subauthority = m.groups()
        return WINNT_SID(
            Revision=int(rev),
            IdentifierAuthority=WINNT_SID_IDENTIFIER_AUTHORITY(
                Value=struct.pack(">Q", int(authority))[2:]
            ),
            SubAuthority=[int(x) for x in subauthority[1:].split("-")],
        )

    def summary(self) -> str:
        """
        Return the string representation of the SID.
        """
        return "S-%s-%s%s" % (
            self.Revision,
            struct.unpack(">Q", b"\x00\x00" + self.IdentifierAuthority.Value)[0],
            (
                ("-%s" % "-".join(str(x) for x in self.SubAuthority))
                if self.SubAuthority
                else ""
            ),
        )


# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

# pylint: disable-next=duplicate-key
WELL_KNOWN_SIDS = {
    # Universal well-known SID
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner ID",
    "S-1-3-1": "Creator Group ID",
    "S-1-3-2": "Owner Server",
    "S-1-3-3": "Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-80-0": "All Services",
    # NT well-known SIDs
    "S-1-5-1": "Dialup",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System (or LocalSystem)",
    "S-1-5-19": "NT Authority (LocalService)",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": r"Builtin\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": r"Builtin\Remote Desktop Users",
    "S-1-5-32-556": r"Builtin\Network Configuration Operators",
    "S-1-5-32-557": r"Builtin\Incoming Forest Trust Builders",
    "S-1-5-32-558": r"Builtin\Performance Monitor Users",
    "S-1-5-32-559": r"Builtin\Performance Log Users",
    "S-1-5-32-560": r"Builtin\Windows Authorization Access Group",
    "S-1-5-32-561": r"Builtin\Terminal Server License Servers",
    "S-1-5-32-562": r"Builtin\Distributed COM Users",
    "S-1-5-32-568": r"Builtin\IIS_IUSRS",
    "S-1-5-32-569": r"Builtin\Cryptographic Operators",
    "S-1-5-32-573": r"Builtin\Event Log Readers",
    "S-1-5-32-574": r"Builtin\Certificate Service DCOM Access",
    "S-1-5-32-575": r"Builtin\RDS Remote Access Servers",
    "S-1-5-32-576": r"Builtin\RDS Endpoint Servers",
    "S-1-5-32-577": r"Builtin\RDS Management Servers",
    "S-1-5-32-578": r"Builtin\Hyper-V Administrators",
    "S-1-5-32-579": r"Builtin\Access Control Assistance Operators",
    "S-1-5-32-580": r"Builtin\Remote Management Users",
    "S-1-5-32-581": r"Builtin\Default Account",
    "S-1-5-32-582": r"Builtin\Storage Replica Admins",
    "S-1-5-32-583": r"Builtin\Device Owners",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
    "S-1-5-80-0": "All Services",
    "S-1-5-83-0": r"NT VIRTUAL MACHINE\Virtual Machines",
}


# [MS-DTYP] sect 2.4.3

_WINNT_ACCESS_MASK = {
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",
    0x02000000: "MAXIMUM_ALLOWED",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x00100000: "SYNCHRONIZE",
    0x00080000: "WRITE_OWNER",
    0x00040000: "WRITE_DACL",
    0x00020000: "READ_CONTROL",
    0x00010000: "DELETE",
}


# [MS-DTYP] sect 2.4.4.1


WINNT_ACE_FLAGS = {
    0x01: "OBJECT_INHERIT",
    0x02: "CONTAINER_INHERIT",
    0x04: "NO_PROPAGATE_INHERIT",
    0x08: "INHERIT_ONLY",
    0x10: "INHERITED_ACE",
    0x40: "SUCCESSFUL_ACCESS",
    0x80: "FAILED_ACCESS",
}


class WINNT_ACE_HEADER(Packet):
    """
    Access Control Entry (ACE) Header
    It is composed of 3 fields, followed by ACE-specific data:
        - AceType (1 byte): see below for standard values
        - AceFlags (1 byte): see WINNT_ACE_FLAGS
        - AceSize (2 bytes): total size of the ACE, including the header
                             and the ACE-specific data.
    """

    fields_desc = [
        ByteEnumField(
            "AceType",
            0,
            {
                0x00: "ACCESS_ALLOWED",
                0x01: "ACCESS_DENIED",
                0x02: "SYSTEM_AUDIT",
                0x03: "SYSTEM_ALARM",
                0x04: "ACCESS_ALLOWED_COMPOUND",
                0x05: "ACCESS_ALLOWED_OBJECT",
                0x06: "ACCESS_DENIED_OBJECT",
                0x07: "SYSTEM_AUDIT_OBJECT",
                0x08: "SYSTEM_ALARM_OBJECT",
                0x09: "ACCESS_ALLOWED_CALLBACK",
                0x0A: "ACCESS_DENIED_CALLBACK",
                0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
                0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
                0x0D: "SYSTEM_AUDIT_CALLBACK",
                0x0E: "SYSTEM_ALARM_CALLBACK",
                0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
                0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
                0x11: "SYSTEM_MANDATORY_LABEL",
                0x12: "SYSTEM_RESOURCE_ATTRIBUTE",
                0x13: "SYSTEM_SCOPED_POLICY_ID",
            },
        ),
        FlagsField(
            "AceFlags",
            0,
            8,
            WINNT_ACE_FLAGS,
        ),
        LenField("AceSize", None, fmt="<H", adjust=lambda x: x + 4),
    ]

    def extract_padding(self, p):
        return p[: self.AceSize - 4], p[self.AceSize - 4 :]

    # fmt: off
    def extractData(self, accessMask=None):
        """
        Return the ACE data as usable data.

        :param accessMask: context-specific flags for the ACE Mask.
        """
        sid_string = self.payload.Sid.summary()
        mask = self.payload.Mask
        if accessMask is not None:
            mask = FlagValue(mask, FlagsField("", 0, 32, accessMask).names)
        ace_flag_string = str(
            FlagValue(self.AceFlags, ["OI", "CI", "NP", "IO", "ID", "SA", "FA"])
        )
        object_guid = getattr(self.payload, "ObjectType", "")
        inherit_object_guid = getattr(self.payload, "InheritedObjectType", "")
        # ApplicationData -> conditional expression
        cond_expr = None
        if hasattr(self.payload, "ApplicationData"):
            # Parse tokens
            res = []
            for ct in self.payload.ApplicationData.Tokens:
                if ct.TokenType in [
                    # binary operators
                    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x8e, 0x8f,
                    0xa0, 0xa1
                ]:
                    t1 = res.pop(-1)
                    t0 = res.pop(-1)
                    tt = ct.sprintf("%TokenType%")
                    if ct.TokenType in [0xa0, 0xa1]:  # && and ||
                        res.append(f"({t0}) {tt} ({t1})")
                    else:
                        res.append(f"{t0} {tt} {t1}")
                elif ct.TokenType in [
                    # unary operators
                    0x87, 0x8d, 0xa2, 0x89, 0x8a, 0x8b, 0x8c, 0x91, 0x92, 0x93
                ]:
                    t0 = res.pop(-1)
                    tt = ct.sprintf("%TokenType%")
                    res.append(f"{tt}{t0}")
                elif ct.TokenType in [
                    # values
                    0x01, 0x02, 0x03, 0x04, 0x10, 0x18, 0x50, 0x51, 0xf8, 0xf9,
                    0xfa, 0xfb
                ]:
                    def lit(ct):
                        if ct.TokenType in [0x10, 0x18]:  # literal strings
                            return '"%s"' % ct.value
                        elif ct.TokenType == 0x50:  # composite
                            return "({%s})" % ",".join(lit(x) for x in ct.value)
                        else:
                            return str(ct.value)
                    res.append(lit(ct))
                elif ct.TokenType == 0x00:  # padding
                    pass
                else:
                    raise ValueError("Unhandled token type %s" % ct.TokenType)
            if len(res) != 1:
                raise ValueError("Incomplete SDDL !")
            cond_expr = "(%s)" % res[0]
        return {
            "ace-flags-string": ace_flag_string,
            "sid-string": sid_string,
            "mask": mask,
            "object-guid": object_guid,
            "inherited-object-guid": inherit_object_guid,
            "cond-expr": cond_expr,
        }
    # fmt: on

    def toSDDL(self, accessMask=None):
        """
        Return SDDL
        """
        data = self.extractData(accessMask=accessMask)
        ace_rights = ""  # TODO
        if self.AceType in [0x9, 0xA, 0xB, 0xD]:  # Conditional ACE
            conditional_ace_type = {
                0x09: "XA",
                0x0A: "XD",
                0x0B: "XU",
                0x0D: "ZA",
            }[self.AceType]
            return "D:(%s)" % (
                ";".join(
                    x
                    for x in [
                        conditional_ace_type,
                        data["ace-flags-string"],
                        ace_rights,
                        str(data["object-guid"]),
                        str(data["inherited-object-guid"]),
                        data["sid-string"],
                        data["cond-expr"],
                    ]
                    if x is not None
                )
            )
        else:
            ace_type = {
                0x00: "A",
                0x01: "D",
                0x02: "AU",
                0x05: "OA",
                0x06: "OD",
                0x07: "OU",
                0x11: "ML",
                0x13: "SP",
            }[self.AceType]
            return "(%s)" % (
                ";".join(
                    x
                    for x in [
                        ace_type,
                        data["ace-flags-string"],
                        ace_rights,
                        str(data["object-guid"]),
                        str(data["inherited-object-guid"]),
                        data["sid-string"],
                        data["cond-expr"],
                    ]
                    if x is not None
                )
            )


# Field definition that takes context into account


class WINNT_ACCESS_MASK_SPECIFIC_TYPE(enum.IntEnum):
    """
    Enum class used to identify the specific access rights type
    for a given SECURITY_DESCRIPTOR. If you want to add a specific
    access mask type, you need to:
        - add a new enum value here
        - create a dict with the specific access rights
        - register it using register_winnt_access_mask_context_specific in your module
    """

    DEFAULT = 0
    REGISTRY = 1

    # to implement
    # https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
    # SAMR = 2
    # FILE_SYSTEM = 3
    # PROCESS = 4
    # THREAD = 5
    # TOKEN = 6
    # SERVICE = 7
    # SYNCHRONIZATION = 9
    # JOB_OBJECT = 10


_WINNT_ACCESS_MASK_CONTEXT_SPECIFIC: dict[
    WINNT_ACCESS_MASK_SPECIFIC_TYPE, dict[str, FlagsField | str]
] = {}


def register_winnt_access_mask_context_specific(
    mask_specific_type: WINNT_ACCESS_MASK_SPECIFIC_TYPE,
    specific_access_masks: dict,
    aliases_sddl: dict,
) -> None:
    """
    Function to register context-specific access masks for a given
    SECURITY_DESCRIPTOR type.

    :param mask_specific_type: type of the SECURITY_DESCRIPTOR
                               (as per WINNT_ACCESS_MASK_SPECIFIC_TYPE)
    :type mask_specific_type: WINNT_ACCESS_MASK_SPECIFIC_TYPE

    :param specific_access_masks: dict of specific access masks to add/override
    :type specific_access_masks: dict

    :param aliases_sddl: dict of SDDL aliases for the specific access masks
    :type aliases_sddl: dict
    """
    _WINNT_ACCESS_MASK_CONTEXT_SPECIFIC[mask_specific_type] = {
        "mask": _WINNT_ACCESS_MASK.copy(),
        "aliases_sddl": aliases_sddl,
    }
    _WINNT_ACCESS_MASK_CONTEXT_SPECIFIC[mask_specific_type]["mask"].update(
        specific_access_masks
    )
    print(
        f"[+] Registered context-specific access mask for type {mask_specific_type} with masks {specific_access_masks} and SDDL aliases {aliases_sddl}"
    )


register_winnt_access_mask_context_specific(
    WINNT_ACCESS_MASK_SPECIFIC_TYPE.DEFAULT,
    {},
    {},
)


class _WINNT_ACCESS_MASK_Field(MultipleTypeField):
    def __init__(self, name, default):
        # We create a MultipleTypeField that returns different FlagsField depending
        # on the type of the SECURITY_DESCRIPTOR
        self.flds = [
            (
                FlagsField(name, default, 32, context["mask"]),
                lambda pkt, m_type=mask_type: self._winnt_access_mask_specific_type(pkt)
                == m_type,
            )
            for mask_type, context in _WINNT_ACCESS_MASK_CONTEXT_SPECIFIC.items()
        ]
        super(_WINNT_ACCESS_MASK_Field, self).__init__(
            self.flds,
            FlagsField(name, default, 32, _WINNT_ACCESS_MASK),
        )

    def _winnt_access_mask_specific_type(self, pkt):
        print(
            f"[*] Got {pkt.__class__.__name__} with mask_specific_type={pkt.mask_specific_type}"
        )
        print(self.flds)
        return pkt.mask_specific_type


# [MS-DTYP] sect 2.4.4.2


class WINNT_ACCESS_ALLOWED_ACE(Packet):
    fields_desc = [
        _WINNT_ACCESS_MASK_Field("Mask", 0),
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]
    __slots__ = ["mask_specific_type"]

    def __init__(self, *args, **kwargs):
        # Identify which specific type of ACE we are parsing to be able to use the right access mask
        self.mask_specific_type = kwargs.pop(
            "mask_specific_type", WINNT_ACCESS_MASK_SPECIFIC_TYPE.DEFAULT
        )
        if self.mask_specific_type not in WINNT_ACCESS_MASK_SPECIFIC_TYPE:
            print(
                "[!] Warning: unknown WINNT_ACCESS_MASK_SPECIFIC_TYPE %s"
                % self.mask_specific_type
            )
            self.mask_specific_type = WINNT_ACCESS_MASK_SPECIFIC_TYPE.DEFAULT

        super(WINNT_ACCESS_ALLOWED_ACE, self).__init__(*args, **kwargs)
        self.fields_desc = [
            _WINNT_ACCESS_MASK_Field("Mask", 0),
            PacketField("Sid", WINNT_SID(), WINNT_SID),
        ]
        breakpoint()


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_ACE, AceType=0x00)


# [MS-DTYP] sect 2.4.4.3


class WINNT_ACCESS_ALLOWED_OBJECT_ACE(Packet):
    fields_desc = [
        FlagsField("Mask", 0, -32, _WINNT_ACCESS_MASK),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x00000001: "OBJECT_TYPE_PRESENT",
                0x00000002: "INHERITED_OBJECT_TYPE_PRESENT",
            },
        ),
        ConditionalField(
            UUIDField("ObjectType", None, uuid_fmt=UUIDField.FORMAT_LE),
            lambda pkt: pkt.Flags.OBJECT_TYPE_PRESENT,
        ),
        ConditionalField(
            UUIDField("InheritedObjectType", None, uuid_fmt=UUIDField.FORMAT_LE),
            lambda pkt: pkt.Flags.INHERITED_OBJECT_TYPE_PRESENT,
        ),
        PacketField("Sid", WINNT_SID(), WINNT_SID),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_OBJECT_ACE, AceType=0x05)


# [MS-DTYP] sect 2.4.4.4


class WINNT_ACCESS_DENIED_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_ACE, AceType=0x01)


# [MS-DTYP] sect 2.4.4.5


class WINNT_ACCESS_DENIED_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_OBJECT_ACE, AceType=0x06)


# [MS-DTYP] sect 2.4.4.17.4+


class WINNT_APPLICATION_DATA_LITERAL_TOKEN(Packet):
    def default_payload_class(self, payload):
        return conf.padding_layer


# fmt: off
WINNT_APPLICATION_DATA_LITERAL_TOKEN.fields_desc = [
    ByteEnumField(
        "TokenType",
        0,
        {
            # [MS-DTYP] sect 2.4.4.17.5
            0x00: "Padding token",
            0x01: "Signed int8",
            0x02: "Signed int16",
            0x03: "Signed int32",
            0x04: "Signed int64",
            0x10: "Unicode",
            0x18: "Octet String",
            0x50: "Composite",
            0x51: "SID",
            # [MS-DTYP] sect 2.4.4.17.6
            0x80: "==",
            0x81: "!=",
            0x82: "<",
            0x83: "<=",
            0x84: ">",
            0x85: ">=",
            0x86: "Contains",
            0x88: "Any_of",
            0x8e: "Not_Contains",
            0x8f: "Not_Any_of",
            0x89: "Member_of",
            0x8a: "Device_Member_of",
            0x8b: "Member_of_Any",
            0x8c: "Device_Member_of_Any",
            0x90: "Not_Member_of",
            0x91: "Not_Device_Member_of",
            0x92: "Not_Member_of_Any",
            0x93: "Not_Device_Member_of_Any",
            # [MS-DTYP] sect 2.4.4.17.7
            0x87: "Exists",
            0x8d: "Not_Exists",
            0xa0: "&&",
            0xa1: "||",
            0xa2: "!",
            # [MS-DTYP] sect 2.4.4.17.8
            0xf8: "Local attribute",
            0xf9: "User Attribute",
            0xfa: "Resource Attribute",
            0xfb: "Device Attribute",
        }
    ),
    ConditionalField(
        # Strings
        LEIntField("length", 0),
        lambda pkt: pkt.TokenType in [
            0x10,  # Unicode string
            0x18,  # Octet string
            0xf8, 0xf9, 0xfa, 0xfb,  # Attribute tokens
            0x50,  # Composite
        ]
    ),
    ConditionalField(
        MultipleTypeField(
            [
                (
                    LELongField("value", 0),
                    lambda pkt: pkt.TokenType in [
                        0x01,  # signed int8
                        0x02,  # signed int16
                        0x03,  # signed int32
                        0x04,  # signed int64
                    ]
                ),
                (
                    StrLenFieldUtf16("value", b"", length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType in [
                        0x10,  # Unicode string
                        0xf8, 0xf9, 0xfa, 0xfb,  # Attribute tokens
                    ]
                ),
                (
                    StrLenField("value", b"", length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType == 0x18,  # Octet string
                ),
                (
                    PacketListField("value", [], WINNT_APPLICATION_DATA_LITERAL_TOKEN,
                                    length_from=lambda pkt: pkt.length),
                    lambda pkt: pkt.TokenType == 0x50,  # Composite
                ),

            ],
            StrFixedLenField("value", b"", length=0),
        ),
        lambda pkt: pkt.TokenType in [
            0x01, 0x02, 0x03, 0x04, 0x10, 0x18, 0xf8, 0xf9, 0xfa, 0xfb, 0x50
        ]
    ),
    ConditionalField(
        # Literal
        ByteEnumField("sign", 0, {
            0x01: "+",
            0x02: "-",
            0x03: "None",
        }),
        lambda pkt: pkt.TokenType in [
            0x01,  # signed int8
            0x02,  # signed int16
            0x03,  # signed int32
            0x04,  # signed int64
        ]
    ),
    ConditionalField(
        # Literal
        ByteEnumField("base", 0, {
            0x01: "Octal",
            0x02: "Decimal",
            0x03: "Hexadecimal",
        }),
        lambda pkt: pkt.TokenType in [
            0x01,  # signed int8
            0x02,  # signed int16
            0x03,  # signed int32
            0x04,  # signed int64
        ]
    ),
]
# fmt: on


class WINNT_APPLICATION_DATA(Packet):
    fields_desc = [
        StrFixedLenField("Magic", b"\x61\x72\x74\x78", length=4),
        PacketListField(
            "Tokens",
            [],
            WINNT_APPLICATION_DATA_LITERAL_TOKEN,
        ),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# [MS-DTYP] sect 2.4.4.6


class WINNT_ACCESS_ALLOWED_CALLBACK_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_CALLBACK_ACE, AceType=0x09)


# [MS-DTYP] sect 2.4.4.7


class WINNT_ACCESS_DENIED_CALLBACK_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_CALLBACK_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_CALLBACK_ACE, AceType=0x0A)


# [MS-DTYP] sect 2.4.4.8


class WINNT_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, AceType=0x0B)


# [MS-DTYP] sect 2.4.4.9


class WINNT_ACCESS_DENIED_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_ACCESS_DENIED_OBJECT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_ACCESS_DENIED_CALLBACK_OBJECT_ACE, AceType=0x0C)


# [MS-DTYP] sect 2.4.4.10


class WINNT_SYSTEM_AUDIT_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_ACE, AceType=0x02)


# [MS-DTYP] sect 2.4.4.11


class WINNT_SYSTEM_AUDIT_OBJECT_ACE(Packet):
    # doc is wrong.
    fields_desc = WINNT_ACCESS_ALLOWED_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_OBJECT_ACE, AceType=0x07)


# [MS-DTYP] sect 2.4.4.12


class WINNT_SYSTEM_AUDIT_CALLBACK_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_ACE.fields_desc + [
        PacketField(
            "ApplicationData", WINNT_APPLICATION_DATA(), WINNT_APPLICATION_DATA
        ),
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_CALLBACK_ACE, AceType=0x0D)


# [MS-DTYP] sect 2.4.4.13


class WINNT_SYSTEM_MANDATORY_LABEL_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_MANDATORY_LABEL_ACE, AceType=0x11)


# [MS-DTYP] sect 2.4.4.14


class WINNT_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE(Packet):
    fields_desc = WINNT_SYSTEM_AUDIT_OBJECT_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, AceType=0x0F)

# [MS-DTYP] sect 2.4.10.1


class CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(_NTLMPayloadPacket):
    _NTLM_PAYLOAD_FIELD_NAME = "Data"
    fields_desc = [
        LEIntField("NameOffset", 0),
        LEShortEnumField(
            "ValueType",
            0,
            {
                0x0001: "CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64",
                0x0002: "CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64",
                0x0003: "CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING",
                0x0005: "CLAIM_SECURITY_ATTRIBUTE_TYPE_SID",
                0x0006: "CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN",
                0x0010: "CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING",
            },
        ),
        LEShortField("Reserved", 0),
        FlagsField(
            "Flags",
            0,
            -32,
            {
                0x0001: "CLAIM_SECURITY_ATTRIBUTE_NON_INHERITABLE",
                0x0002: "CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE",
                0x0004: "CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY",
                0x0008: "CLAIM_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT",
                0x0010: "CLAIM_SECURITY_ATTRIBUTE_DISABLED",
                0x0020: "CLAIM_SECURITY_ATTRIBUTE_MANDATORY",
            },
        ),
        LEIntField("ValueCount", 0),
        FieldListField(
            "ValueOffsets", [], LEIntField("", 0), count_from=lambda pkt: pkt.ValueCount
        ),
        _NTLMPayloadField(
            "Data",
            lambda pkt: 16 + pkt.ValueCount * 4,
            [
                ConditionalField(
                    StrFieldUtf16("Name", b""),
                    lambda pkt: pkt.NameOffset,
                ),
                # TODO: Values
            ],
            offset_name="Offset",
        ),
    ]


# [MS-DTYP] sect 2.4.4.15


class WINNT_SYSTEM_RESOURCE_ATTRIBUTE_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc + [
        PacketField(
            "AttributeData",
            CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(),
            CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1,
        )
    ]


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_RESOURCE_ATTRIBUTE_ACE, AceType=0x12)

# [MS-DTYP] sect 2.4.4.16


class WINNT_SYSTEM_SCOPED_POLICY_ID_ACE(Packet):
    fields_desc = WINNT_ACCESS_ALLOWED_ACE.fields_desc


bind_layers(WINNT_ACE_HEADER, WINNT_SYSTEM_SCOPED_POLICY_ID_ACE, AceType=0x13)

# [MS-DTYP] sect 2.4.5


class WINNT_ACL(Packet):
    fields_desc = [
        ByteField("AclRevision", 2),
        ByteField("Sbz1", 0x00),
        # Total size including header:
        # AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
        FieldLenField(
            "AclSize",
            None,
            length_of="Aces",
            adjust=lambda _, x: x + 8,
            fmt="<H",
        ),
        FieldLenField("AceCount", None, count_of="Aces", fmt="<H"),
        ShortField("Sbz2", 0),
        PacketListField(
            "Aces",
            [],
            WINNT_ACE_HEADER,
            count_from=lambda pkt: pkt.AceCount,
        ),
    ]

    def toSDDL(self):
        return [x.toSDDL() for x in self.Aces]


# [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR


class SECURITY_DESCRIPTOR(_NTLMPayloadPacket):
    OFFSET = 20
    _NTLM_PAYLOAD_FIELD_NAME = "Data"
    __slots__ = ["type"]

    fields_desc = [
        ByteField("Revision", 0x01),
        ByteField("Sbz1", 0x00),
        FlagsField(
            "Control",
            0x00,
            -16,
            [
                "OWNER_DEFAULTED",
                "GROUP_DEFAULTED",
                "DACL_PRESENT",
                "DACL_DEFAULTED",
                "SACL_PRESENT",
                "SACL_DEFAULTED",
                "DACL_TRUSTED",
                "SERVER_SECURITY",
                "DACL_COMPUTED",
                "SACL_COMPUTED",
                "DACL_AUTO_INHERITED",
                "SACL_AUTO_INHERITED",
                "DACL_PROTECTED",
                "SACL_PROTECTED",
                "RM_CONTROL_VALID",
                "SELF_RELATIVE",
            ],
        ),
        LEIntField("OwnerSidOffset", None),
        LEIntField("GroupSidOffset", None),
        LEIntField("SACLOffset", None),
        LEIntField("DACLOffset", None),
        _NTLMPayloadField(
            "Data",
            OFFSET,
            [
                ConditionalField(
                    PacketField("OwnerSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.OwnerSidOffset != 0,
                ),
                ConditionalField(
                    PacketField("GroupSid", WINNT_SID(), WINNT_SID),
                    lambda pkt: pkt.GroupSidOffset != 0,
                ),
                ConditionalField(
                    PacketField("SACL", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.SACL_PRESENT,
                ),
                ConditionalField(
                    PacketField("DACL", WINNT_ACL(), WINNT_ACL),
                    lambda pkt: pkt.Control.DACL_PRESENT,
                ),
            ],
            offset_name="Offset",
        ),
    ]

    def __init__(self, *args, **kwargs):
        print("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        super(SECURITY_DESCRIPTOR, self).__init__(*args, **kwargs)
        print("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        self.type = kwargs.pop("type", _WINNT_ACCESS_MASK_SPECIFIC_TYPE.DEFAULT)
        if self.type not in _WINNT_ACCESS_MASK_SPECIFIC_TYPE:
            print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        return (
            _NTLM_post_build(
                self,
                pkt,
                self.OFFSET,
                {
                    "OwnerSid": 4,
                    "GroupSid": 8,
                    "SACL": 12,
                    "DACL": 16,
                },
                config=[
                    ("Offset", _NTLM_ENUM.OFFSET),
                ],
            )
            + pay
        )


# High level access rights definitions


@dataclass
class AccessRight:
    """
    Access right simple dataclass

    :param value: Access right value
    :type value: int

    :param fullname: Full name of the access right
    :type fullname: str

    :param sddl: SDDL representation of the access right
    :type sddl: str
    """

    value: int
    fullname: str
    sddl: str


class AccessRights(Packet):
    """
    Generic access rights:
    https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights
    """

    fields_desc = [
        FlagsField(
            "GenericAccessRights",
            0,
            8,
            {
                0x80: "GENERIC_READ",
                0x40: "GENERIC_WRITE",
                0x20: "GENERIC_EXECUTE",
                0x10: "GENERIC_ALL",
                0x08: "RESERVED_BIT27",
                0x04: "RESERVED_BIT26",
                0x02: "MAXIMUM_ALLOWED",
                0x01: "ACCESS_SYSTEM_SECURITY",
            },
        ),
        FlagsField(
            "StandardAccessRights",
            0,
            8,
            {
                0x01: "DELETE",
                0x02: "READ_CONTROL",
                0x04: "WRITE_DAC",
                0x08: "WRITE_OWNER",
                0x10: "SYNCHRONIZE",
            },
        ),
    ]

    GENERIC_READ = AccessRight(0x80000000, "GENERIC_READ", "GR")
    GENERIC_WRITE = AccessRight(0x40000000, "GENERIC_WRITE", "GW")
    GENERIC_EXECUTE = AccessRight(0x20000000, "GENERIC_EXECUTE", "GX")
    GENERIC_ALL = AccessRight(0x10000000, "GENERIC_ALL", "GA")
    MAXIMUM_ALLOWED = AccessRight(0x02000000, "MAXIMUM_ALLOWED", None)
    ACCESS_SACL = AccessRight(0x01000000, "ACCESS_SYSTEM_SECURITY", None)

    # def __init__(self, value: int):
    #     super().__init__()
    #     self.value = value & 0xFF000000

    # def pre_dissect(self, s: int) -> bytes:
    #     if isinstance(s, str):
    #         try:
    #             s = int(s)
    #         except ValueError:
    #             s = int(s, 16)
    #     if isinstance(s, int):
    #         s = s & 0xFF000000
    #         return s.to_bytes(length=4)
    #     return s

    def toSDDL(self) -> tuple[str, int]:
        """
        Return SDDL string and out-of-scope value

        returns: SDDL representation
        rtype: tuple[str, int]

        .. code-block:: python
            >>> gar = GenericAccessRights(0xC0000000)
            >>> gar.toSDDL()
            ('GRGW', 0)
        """
        sddl = []
        for right in [
            self.GENERIC_READ,
            self.GENERIC_WRITE,
            self.GENERIC_EXECUTE,
            self.GENERIC_ALL,
        ]:
            if self.GenericAccessRights & right.value:
                sddl.append(right.sddl)

        outscope_value = self.GenericAccessRights & ~(
            self.GENERIC_READ.value
            | self.GENERIC_WRITE.value
            | self.GENERIC_EXECUTE.value
            | self.GENERIC_ALL.value
        )
        return "".join(sddl), outscope_value

    def to_fullname(self) -> tuple[str, int]:
        """
        Return full names and out-of-scope value

        returns: Full names representation
        rtype: tuple[str, int]

        .. code-block:: python
            >>> gar = GenericAccessRights(0xC0000000)
            >>> gar.to_fullname()
            ('GENERIC_READ,GENERIC_WRITE', 0)
        """

        names = []
        for right in [
            self.GENERIC_READ,
            self.GENERIC_WRITE,
            self.GENERIC_EXECUTE,
            self.GENERIC_ALL,
            self.MAXIMUM_ALLOWED,
            self.ACCESS_SACL,
        ]:
            if self.value & right.value:
                names.append(right.fullname)

        outscope_value = self.value & ~(
            self.GENERIC_READ.value
            | self.GENERIC_WRITE.value
            | self.GENERIC_EXECUTE.value
            | self.GENERIC_ALL.value
            | self.MAXIMUM_ALLOWED.value
            | self.ACCESS_SACL.value
        )
        return ",".join(names), outscope_value


class StandardAccessRights:
    """
    Standard access rights:
    https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
    """

    DELETE = AccessRight(0x00010000, "DELETE", "SD")
    READ_CONTROL = AccessRight(0x00020000, "READ_CONTROL", "RC")
    WRITE_DAC = AccessRight(0x00040000, "WRITE_DAC", "WD")
    WRITE_OWNER = AccessRight(0x00080000, "WRITE_OWNER", "WO")
    SYNCHRONIZE = AccessRight(0x00100000, "SYNCHRONIZE", None)

    STANDARD_RIGHTS_REQUIRED = AccessRight(
        DELETE.value + READ_CONTROL.value + WRITE_DAC.value + WRITE_OWNER.value,
        "STANDARD_RIGHTS_REQUIRED",
        None,
    )
    STANDARD_RIGHTS_ALL = AccessRight(
        STANDARD_RIGHTS_REQUIRED.value + SYNCHRONIZE.value, "STANDARD_RIGHTS_ALL", None
    )

    STANDARD_RIGHTS_READ = AccessRight(READ_CONTROL.value, "STANDARD_RIGHTS_READ", None)
    STANDARD_RIGHTS_WRITE = AccessRight(
        READ_CONTROL.value, "STANDARD_RIGHTS_READ", None
    )
    STANDARD_RIGHTS_EXECUTE = AccessRight(
        READ_CONTROL.value, "STANDARD_RIGHTS_READ", None
    )

    def __init__(self, value: int = 0):
        self.value = value & 0x0FFF0000

    def toSDDL(self) -> tuple[str, int]:
        sddl = set()
        for right in [
            self.DELETE,
            self.READ_CONTROL,
            self.WRITE_DAC,
            self.WRITE_OWNER,
        ]:
            if self.value & right.value:
                sddl.add(right.sddl)

        outscope_value = self.value & ~(
            self.DELETE.value
            | self.READ_CONTROL.value
            | self.WRITE_DAC.value
            | self.WRITE_OWNER.value
        )
        return "".join(list(sddl)), outscope_value

    def to_fullname(self) -> tuple[str, int]:
        names = []
        for right in [
            self.STANDARD_RIGHTS_ALL,
            self.STANDARD_RIGHTS_REQUIRED,
        ]:
            if self.value & right.value == right.value:
                names.append(right.fullname)
                break
            else:
                for right in [
                    self.DELETE,
                    self.READ_CONTROL,
                    self.WRITE_DAC,
                    self.WRITE_OWNER,
                    self.SYNCHRONIZE,
                ]:
                    if self.value & right.value:
                        names.append(right.fullname)
        outscope_value = self.value & ~(
            self.DELETE.value
            | self.READ_CONTROL.value
            | self.WRITE_DAC.value
            | self.WRITE_OWNER.value
            | self.SYNCHRONIZE.value
        )
        return ",".join(names), outscope_value


class Windows_Access_Rights:
    """
    Windows Access Rights base class
    https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
    """

    def __init__(self, specific_access_rights=None, value: int = 0):
        if specific_access_rights is not None:
            self.SpecificAccessRights = specific_access_rights(value)
        else:
            self.SpecificAccessRights = specific_access_rights

        self.GenericAccessRights = GenericAccessRights(value)
        self.StandardAccessRights = StandardAccessRights(value)
        self.value = value

    def toSDDL(self) -> str:
        """
        Return the SDDL representation of the access rights
        :return: SDDL representation of the access rights
        :rtype: str

        .. code-block:: python
            >>> tmp = Windows_Access_Rights(
            specific_access_rights=RegKeySpecificAccessRights,
            value=0xFFFFFFFFFFFFFFFF
            )
            >>> tmp.toSDDL()
            'GRGWGXGA RCWOWDSD KA 0xff0ffc0'
        """
        sddl_parts = []

        # Generic Access Rights
        generic_sddl, generic_outscope = self.GenericAccessRights.toSDDL()
        if generic_sddl:
            sddl_parts.append(generic_sddl)

        # Standard Access Rights
        standard_sddl, standard_outscope = self.StandardAccessRights.toSDDL()
        if standard_sddl:
            sddl_parts.append(standard_sddl)

        # Specific Access Rights
        specific_sddl, specific_outscope = self.SpecificAccessRights.toSDDL()
        if specific_sddl:
            sddl_parts.append(specific_sddl)

        remaining_outscope = generic_outscope | standard_outscope | specific_outscope
        if remaining_outscope == 0:
            return " ".join(sddl_parts)
        else:
            return (
                " ".join(sddl_parts)
                + " "
                + hex(generic_outscope | standard_outscope | specific_outscope)
            )

    def to_fullname(self) -> str:
        """
        Return the full names of the access rights

        .. code-block:: python

            >>> tmp = Windows_Access_Rights(
                specific_access_rights=RegKeySpecificAccessRights,
                value=0xFFFFFFFFFFFFFFFF
                )
            >>> tmp.to_fullname()
            'GENERIC_READ,GENERIC_WRITE,GENERIC_EXECUTE,GENERIC_ALL,STANDARD_RIGHTS_ALL,
             KEY_WOW64_64KEY,KEY_WOW64_32KEY,KEY_ALL_ACCESS 0xfe0ffc0'

        :return: Full names of the access rights
        :rtype: str
        """
        name_parts = []

        # Generic Access Rights
        generic_name, generic_outscope = self.GenericAccessRights.to_fullname()
        if generic_name:
            name_parts.append(generic_name)

        # Standard Access Rights
        standard_name, standard_outscope = self.StandardAccessRights.to_fullname()
        if standard_name:
            name_parts.append(standard_name)

        # Specific Access Rights
        specific_name, specific_outscope = self.SpecificAccessRights.to_fullname()
        if specific_name:
            name_parts.append(specific_name)

        remaining_outscope = generic_outscope | standard_outscope | specific_outscope
        if remaining_outscope == 0:
            return ",".join(name_parts)
        else:
            return (
                ",".join(name_parts)
                + " "
                + hex(generic_outscope | standard_outscope | specific_outscope)
            )
