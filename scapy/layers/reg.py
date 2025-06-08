"""
DCE/RPC client
"""

import os
import pathlib

from scapy.layers.msrpce.all import *
from scapy.layers.msrpce.raw.ms_samr import *
from scapy.layers.msrpce.raw.ms_rrp import *
from scapy.layers.dcerpc import RPC_C_AUTHN_LEVEL
from scapy.utils import (
    CLIUtil,
    pretty_list,
    human_size,
    valid_ip,
    valid_ip6,
)
from scapy.layers.kerberos import (
    KerberosSSP,
    krb_as_and_tgs,
    _parse_upn,
)
from scapy.config import conf
from scapy.themes import DefaultTheme
from scapy.base_classes import Net
from scapy.utils6 import Net6
import socket
from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import find_dcerpc_interface, DCERPC_Transport
from scapy.layers.ntlm import MD4le, NTLMSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.kerberos import KerberosSSP

conf.color_theme = DefaultTheme()


KEY_QUERY_VALUE = 0x00000001
KEY_ENUMERATE_SUB_KEYS = 0x00000008
MAX_ALLOWED = 0x02000000
ERROR_NO_MORE_ITEMS = 0x00000103

# Predefined keys
HKEY_CLASSES_ROOT = "HKCROOT"  # Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types. The subkeys of the HKEY_CLASSES_ROOT key are a merged view of the following two subkeys:
HKEY_CURRENT_USER = "HKCU"  # Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data on program groups, colors, printers, network connections, and application preferences. The HKEY_CURRENT_USER root key is a subkey of the HKEY_USERS root key, as described in section 3.1.1.8.
HKEY_LOCAL_MACHINE = "HKLM"  # Registry entries subordinate to this key define the physical state of the computer, including data on the bus type, system memory, and installed hardware and software.
HKEY_CURRENT_CONFIG = ""  # This key contains information on the current hardware profile of the local computer.
HKEY_USERS = "HKU"
HKEY_PERFORMANCE_DATA = "HKPERFORMANCE"  # Registry entries subordinate to this key allow access to performance data.
HKEY_PERFORMANCE_TEXT = ""  # Registry entries subordinate to this key reference the text strings that describe counters in U.S. English.
HKEY_PERFORMANCE_NLSTEXT = ""  # Registry entries subordinate to this key reference the text strings that describe counters in the local language of the area in which the computer is running.


@conf.commands.register
class regclient(CLIUtil):
    r"""
    A simple registry CLI

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos: if available, whether to use Kerberos or not
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
    :param password: (string) if provided, used for auth
    :param HashNt: (bytes) if provided, used for auth (NTLM)
    :param ST: if provided, the service ticket to use (Kerberos)
    :param KEY: if provided, the session key associated to the ticket (Kerberos)
    :param cli: CLI mode (default True). False to use for scripting

    Some additional SMB parameters are available under help(SMB_Client). Some of
    them include the following:

    :param REQUIRE_ENCRYPTION: requires encryption.
    """

    def __init__(
        self,
        target: str,
        UPN: str = None,
        password: str = None,
        guest: bool = False,
        kerberos: bool = True,
        kerberos_required: bool = False,
        HashNt: str = None,
        port: int = 445,
        timeout: int = 2,
        debug: int = 0,
        ssp=None,
        ST=None,
        KEY=None,
        cli=True,
        # SMB arguments
        **kwargs,
    ):
        if cli:
            self._depcheck()
        hostname = None
        # Check if target is a hostname / Check IP
        if ":" in target:
            family = socket.AF_INET6
            if not valid_ip6(target):
                hostname = target
            target = str(Net6(target))
        else:
            family = socket.AF_INET
            if not valid_ip(target):
                hostname = target
            target = str(Net(target))
        assert UPN or ssp or guest, "Either UPN, ssp or guest must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP (only if not guest mode)
            if not guest:
                # Check UPN
                try:
                    _, realm = _parse_upn(UPN)
                    if realm == ".":
                        # Local
                        kerberos = False
                except ValueError:
                    # not a UPN: NTLM
                    kerberos = False
                # Do we need to ask the password?
                if HashNt is None and password is None and ST is None:
                    # yes.
                    from prompt_toolkit import prompt

                    password = prompt("Password: ", is_password=True)
                ssps = []
                # Kerberos
                if kerberos and hostname:
                    if ST is None:
                        resp = krb_as_and_tgs(
                            upn=UPN,
                            spn="cifs/%s" % hostname,
                            password=password,
                            debug=debug,
                        )
                        if resp is not None:
                            ST, KEY = resp.tgsrep.ticket, resp.sessionkey
                    if ST:
                        ssps.append(KerberosSSP(UPN=UPN, ST=ST, KEY=KEY, debug=debug))
                    elif kerberos_required:
                        raise ValueError(
                            "Kerberos required but target isn't a hostname !"
                        )
                elif kerberos_required:
                    raise ValueError(
                        "Kerberos required but domain not specified in the UPN, "
                        "or target isn't a hostname !"
                    )
                # NTLM
                if not kerberos_required:
                    if HashNt is None and password is not None:
                        HashNt = MD4le(password)
                    ssps.append(NTLMSSP(UPN=UPN, HASHNT=HashNt))
                # Build the SSP
                ssp = SPNEGOSSP(ssps)
            else:
                # Guest mode
                ssp = None

        # Interface WINREG
        self.interface = find_dcerpc_interface("winreg")

        # Connexion NCACN_NP: SMB
        self.client = DCERPC_Client(
            DCERPC_Transport.NCACN_NP,
            auth_level=RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
            ssp=ssp,
            ndr64=False,
        )

        self.client.verb = False
        self.client.connect(target)
        self.client.open_smbpipe("winreg")
        self.client.bind(self.interface)
        self.root_handle = {}
        self.current_root_handle = None
        self.current_root_path = "CHOOSE ROOT KEY"
        self.current_subkey_handle = None
        self.current_subkey_path = ""
        self.ls_cache = set()

        if cli:
            self.loop(debug=debug)

    def ps1(self):
        return f"reg: {self.current_root_path}\\{self.current_subkey_path} > "

    def close(self):
        print("Connection closed")
        self.client.close()

    @CLIUtil.addcommand()
    def change_root(self, root_path):
        """
        Change
        """
        if root_path.upper().startswith(HKEY_CLASSES_ROOT):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_CLASSES_ROOT,
                self.client.sr1_req(
                    OpenClassesRoot_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    )
                ).phKey,
            )
            self.current_root_path = HKEY_CLASSES_ROOT

        if root_path.upper().startswith(HKEY_LOCAL_MACHINE):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_LOCAL_MACHINE,
                self.client.sr1_req(
                    OpenLocalMachine_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    )
                ).phKey,
            )
            self.current_root_path = HKEY_LOCAL_MACHINE

        if root_path.upper().startswith(HKEY_CURRENT_USER):
            # Change to HKLM root
            self.current_root_handle = self.root_handle.setdefault(
                HKEY_CURRENT_USER,
                self.client.sr1_req(
                    OpenCurrentUser_Request(
                        ServerName=None,
                        samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    )
                ).phKey,
            )
            self.current_root_path = HKEY_CURRENT_USER

        self.go("")

    @CLIUtil.addcommand()
    def version(self):
        """
        Get remote registry server version
        """
        version = self.client.sr1_req(
            BaseRegGetVersion_Request(hKey=self.current_root_handle)
        ).lpdwVersion
        print(f"Remote registry server version: {version}")

    @CLIUtil.addcommand()
    def ls(self):
        """
        EnumKeys of the current subkey path
        """
        if len(self.ls_cache):
            print(self.ls_cache)
            return

        idx = 0
        while True:
            req = BaseRegEnumKey_Request(
                hKey=self.current_subkey_handle,
                dwIndex=idx,
                lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                lpClassIn=RPC_UNICODE_STRING(),
                lpftLastWriteTime=None,
            )

            resp = self.client.sr1_req(req)
            if resp.status == ERROR_NO_MORE_ITEMS:
                break
            elif resp.status:
                print(
                    f"[-] Error : got status {hex(resp.status)} while enumerating keys"
                )
                import sys

                sys.exit(-1)
            print(resp.lpNameOut.valueof("Buffer").decode("utf-8"))
            self.ls_cache.add(resp.lpNameOut.valueof("Buffer").decode("utf-8"))

            idx += 1

    @CLIUtil.addcommand()
    def go(self, subkey: str):
        """
        Change current subkey path
        """
        if subkey == "":
            self.current_subkey_path = ""
            self.get_handle_on_subkey()
            return

        ton_path_de_merde = pathlib.PureWindowsPath(
            os.path.normpath(os.path.join(self.current_subkey_path, subkey))
        )

        self.current_subkey_path = ton_path_de_merde
        print("azer")
        self.get_handle_on_subkey()
        self.ls_cache.clear()

    def get_handle_on_subkey(self):
        print(f"getting handle on subkey : {self.current_subkey_path}")
        req = BaseRegOpenKey_Request(
            hKey=self.current_root_handle,
            # lpSubKey=RPC_UNICODE_STRING(Buffer=str(self.current_subkey_path) + "\x00"),
            lpSubKey=RPC_UNICODE_STRING(Buffer=str(self.current_subkey_path) + "\x00"),
            samDesired=KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
        )
        resp = self.client.sr1_req(req)
        self.current_subkey_handle = resp.phkResult
        return self.current_subkey_handle


if __name__ == "__main__":
    from scapy.utils import AutoArgparse

    AutoArgparse(regclient)
