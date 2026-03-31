#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ansible module for gathering SNMP facts from network devices."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: snmp_facts
short_description: Gather SNMP facts from a remote device
version_added: "0.1.0"
description:
  - Queries a remote SNMP agent and returns device facts as C(ansible_facts).
  - Supports SNMPv2c and SNMPv3 (authNoPriv, authPriv).
  - Uses PySNMP for native Python SNMP operations.
  - Runs on the Ansible controller (connection is SNMP, not SSH).
  - Use I(gather_subset) to control which fact categories are collected.
    By default all categories are gathered, preserving backward compatibility.
requirements:
  - "pysnmp>=6.2.0,<7.0.0"
options:
  host:
    description:
      - Hostname or IP address of the SNMP agent.
      - Must be a bare hostname or IP. No C(host:port) parsing is performed.
    type: str
    required: true
  port:
    description:
      - UDP port of the SNMP agent.
    type: int
    default: 161
  version:
    description:
      - SNMP protocol version to use.
    type: str
    required: true
    choices: ["v2c", "v3"]
  community:
    description:
      - SNMP community string. Required when I(version=v2c).
    type: str
  username:
    description:
      - SNMPv3 USM username. Required when I(version=v3).
    type: str
  level:
    description:
      - SNMPv3 security level. Required when I(version=v3).
    type: str
    choices: ["authNoPriv", "authPriv"]
  integrity:
    description:
      - SNMPv3 authentication algorithm. Required when I(level) is set.
    type: str
    choices: ["md5", "sha", "sha224", "sha256", "sha384", "sha512"]
  authkey:
    description:
      - SNMPv3 authentication passphrase.
    type: str
  privacy:
    description:
      - SNMPv3 privacy algorithm. Required when I(level=authPriv).
    type: str
    choices: ["des", "aes", "aes192", "aes256"]
  privkey:
    description:
      - SNMPv3 privacy passphrase.
    type: str
  timeout:
    description:
      - Timeout in seconds for each SNMP request.
    type: int
    default: 10
  retries:
    description:
      - Number of SNMP request retries.
    type: int
    default: 3
  gather_subset:
    description:
      - List of fact subsets to collect.
      - "C(system): scalar system MIB-II objects (sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation)."
      - "C(interfaces): ifTable-derived interface facts."
      - "C(ipv4): ipAddrTable-derived IPv4 address list."
      - When omitted, all three subsets are gathered (backward-compatible default).
    type: list
    elements: str
    default: ["system", "interfaces", "ipv4"]
    version_added: "1.0.0"
author:
  - Torie-Coding (@Torie-Coding)
"""

EXAMPLES = r"""
- name: Gather all SNMP facts (default, backward compatible)
  torie_coding.snmp.snmp_facts:
    host: 192.168.1.1
    version: v2c
    community: public

- name: Gather only system scalars (fast, no table walks)
  torie_coding.snmp.snmp_facts:
    host: 192.168.1.1
    version: v2c
    community: public
    gather_subset:
      - system

- name: Gather system and interfaces (skip ipv4 table walk)
  torie_coding.snmp.snmp_facts:
    host: 192.168.1.1
    version: v2c
    community: public
    gather_subset:
      - system
      - interfaces

- name: Gather SNMP facts via SNMPv3 authPriv
  torie_coding.snmp.snmp_facts:
    host: switch01.example.com
    version: v3
    username: snmpuser
    level: authPriv
    integrity: sha256
    authkey: "{{ vault_snmp_authkey }}"
    privacy: aes
    privkey: "{{ vault_snmp_privkey }}"

- name: Gather facts on a non-standard port
  torie_coding.snmp.snmp_facts:
    host: 10.0.0.1
    port: 1161
    version: v2c
    community: public
"""

RETURN = r"""
ansible_facts:
  description: Dictionary of SNMP facts added to host facts.
  returned: always
  type: dict
  contains:
    ansible_sysdescr:
      description: System description (sysDescr.0).
      type: str
      returned: when 'system' in gather_subset
    ansible_sysobjectid:
      description: System object ID (sysObjectID.0).
      type: str
      returned: when 'system' in gather_subset
    ansible_sysuptime:
      description: System uptime in timeticks (sysUpTime.0).
      type: int
      returned: when 'system' in gather_subset
    ansible_syscontact:
      description: System contact (sysContact.0).
      type: str
      returned: when 'system' in gather_subset
    ansible_sysname:
      description: System name (sysName.0).
      type: str
      returned: when 'system' in gather_subset
    ansible_syslocation:
      description: System location (sysLocation.0).
      type: str
      returned: when 'system' in gather_subset
    ansible_all_ipv4_addresses:
      description: List of IPv4 addresses (from ipAddrTable), excluding 127.0.0.1.
      type: list
      elements: str
      returned: when 'ipv4' in gather_subset
    ansible_interfaces:
      description: >-
        Dictionary of network interfaces keyed by ifDescr, with sub-keys
        ifindex, ifdescr, iftype, ifspeed, ifadminstatus, ifoperstatus,
        and ifphysaddress.
      type: dict
      returned: when 'interfaces' in gather_subset
"""

from ansible.module_utils.basic import AnsibleModule

# PySNMP import path and constant mappings.
# All names verified against pysnmp>=6.2.0,<7.0.0 (pysnmp.hlapi.asyncio).
HAS_PYSNMP = True
PYSNMP_IMPORT_ERROR = None
try:
    from pysnmp.hlapi.asyncio import (  # noqa: E402
        CommunityData,
        UsmUserData,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
    )
except ImportError as exc:
    HAS_PYSNMP = False
    PYSNMP_IMPORT_ERROR = str(exc)

# --- Protocol mapping tables ---

AUTH_PROTOCOLS = {}
PRIV_PROTOCOLS = {}

if HAS_PYSNMP:
    AUTH_PROTOCOLS = {
        "md5": usmHMACMD5AuthProtocol,
        "sha": usmHMACSHAAuthProtocol,
        "sha224": usmHMAC128SHA224AuthProtocol,
        "sha256": usmHMAC192SHA256AuthProtocol,
        "sha384": usmHMAC256SHA384AuthProtocol,
        "sha512": usmHMAC384SHA512AuthProtocol,
    }
    PRIV_PROTOCOLS = {
        "des": usmDESPrivProtocol,
        "aes": usmAesCfb128Protocol,
        "aes192": usmAesCfb192Protocol,
        "aes256": usmAesCfb256Protocol,
    }

# --- OID definitions ---

# Scalar OIDs fetched via a single SNMP GET request.
SCALAR_OIDS = {
    "ansible_sysdescr": "1.3.6.1.2.1.1.1.0",
    "ansible_sysobjectid": "1.3.6.1.2.1.1.2.0",
    "ansible_sysuptime": "1.3.6.1.2.1.1.3.0",
    "ansible_syscontact": "1.3.6.1.2.1.1.4.0",
    "ansible_sysname": "1.3.6.1.2.1.1.5.0",
    "ansible_syslocation": "1.3.6.1.2.1.1.6.0",
}

# ifTable OIDs walked for ansible_interfaces.
IF_TABLE_OIDS = {
    "ifindex": "1.3.6.1.2.1.2.2.1.1",
    "ifdescr": "1.3.6.1.2.1.2.2.1.2",
    "iftype": "1.3.6.1.2.1.2.2.1.3",
    "ifspeed": "1.3.6.1.2.1.2.2.1.5",
    "ifphysaddress": "1.3.6.1.2.1.2.2.1.6",
    "ifadminstatus": "1.3.6.1.2.1.2.2.1.7",
    "ifoperstatus": "1.3.6.1.2.1.2.2.1.8",
}

# ipAddrTable OIDs walked for ansible_all_ipv4_addresses.
IP_ADDR_TABLE_OIDS = {
    "ipaddress": "1.3.6.1.2.1.4.20.1.1",
    "netmask": "1.3.6.1.2.1.4.20.1.3",
}

# Admin/Oper status value mapping (RFC 2863).
IF_STATUS_MAP = {
    1: "up",
    2: "down",
    3: "testing",
}


# --- Valid gather_subset values ---

VALID_SUBSETS = frozenset(["system", "interfaces", "ipv4"])
DEFAULT_GATHER_SUBSET = ["system", "interfaces", "ipv4"]


def _build_auth_data(params):
    """Build PySNMP auth data from module parameters.

    Returns:
        CommunityData or UsmUserData instance.
    """
    if params["version"] == "v2c":
        return CommunityData(params["community"], mpModel=1)

    # SNMPv3
    auth_proto = AUTH_PROTOCOLS.get(params["integrity"])
    kwargs = {
        "authProtocol": auth_proto,
        "authKey": params["authkey"],
    }
    if params["level"] == "authPriv":
        priv_proto = PRIV_PROTOCOLS.get(params["privacy"])
        kwargs["privProtocol"] = priv_proto
        kwargs["privKey"] = params["privkey"]

    return UsmUserData(params["username"], **kwargs)


def _format_mac(value):
    """Format a MAC address from raw SNMP OctetString to colon-separated hex."""
    if hasattr(value, "asNumbers"):
        octets = value.asNumbers()
        if len(octets) == 6:
            return ":".join("{0:02x}".format(o) for o in octets)
    raw = str(value)
    if len(raw) == 6:
        return ":".join("{0:02x}".format(ord(c)) for c in raw)
    return raw


def _parse_scalar_results(var_binds, warnings):
    """Parse scalar GET results into ansible_facts keys.

    Non-fatal errors (noSuchObject, noSuchInstance) set the key to None
    and add a warning.
    """
    facts = {}
    # Build a reverse lookup: OID string -> fact key
    oid_to_key = {}
    for key, oid in SCALAR_OIDS.items():
        oid_to_key[oid] = key

    for var_bind in var_binds:
        oid = str(var_bind[0])
        value = var_bind[1]

        # Find the matching fact key
        fact_key = None
        for known_oid, key in oid_to_key.items():
            if oid == known_oid or oid.startswith(known_oid.rstrip(".0")):
                fact_key = key
                break

        if fact_key is None:
            continue

        # Check for SNMP error values
        value_class = value.__class__.__name__
        if value_class in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            facts[fact_key] = None
            warnings.append("{0} returned {1}".format(oid, value_class))
        elif fact_key == "ansible_sysuptime":
            try:
                facts[fact_key] = int(value)
            except (ValueError, TypeError):
                facts[fact_key] = str(value)
        else:
            facts[fact_key] = str(value)

    # Ensure all scalar keys exist even if not returned
    for key in SCALAR_OIDS:
        if key not in facts:
            facts[key] = None
            warnings.append("{0} was not returned by the SNMP agent".format(key))

    return facts


def _parse_ip_addr_table(rows, warnings):
    """Parse ipAddrTable WALK results into a list of IPv4 addresses.

    Excludes 127.0.0.1.
    """
    addresses = []
    ip_oid_prefix = IP_ADDR_TABLE_OIDS["ipaddress"]

    for var_bind_row in rows:
        for var_bind in var_bind_row:
            oid = str(var_bind[0])
            value = str(var_bind[1])
            if oid.startswith(ip_oid_prefix) and value != "127.0.0.1":
                addresses.append(value)

    return addresses


def _parse_if_table(rows, warnings):
    """Parse ifTable WALK results into the ansible_interfaces dict.

    Interfaces are keyed by ifDescr. Rows missing ifIndex or ifDescr
    are skipped with a warning.
    """
    # Collect by ifIndex first, then key by ifDescr
    by_index = {}

    for var_bind_row in rows:
        for var_bind in var_bind_row:
            oid = str(var_bind[0])
            value = var_bind[1]

            # Determine which column this OID belongs to
            for col_name, col_prefix in IF_TABLE_OIDS.items():
                if oid.startswith(col_prefix + "."):
                    # Extract the ifIndex from the OID suffix
                    suffix = oid[len(col_prefix) + 1:]
                    if suffix not in by_index:
                        by_index[suffix] = {}

                    if col_name == "ifphysaddress":
                        by_index[suffix][col_name] = _format_mac(value)
                    elif col_name in ("ifadminstatus", "ifoperstatus"):
                        try:
                            by_index[suffix][col_name] = IF_STATUS_MAP.get(
                                int(value), str(value)
                            )
                        except (ValueError, TypeError):
                            by_index[suffix][col_name] = str(value)
                    else:
                        by_index[suffix][col_name] = str(value)
                    break

    interfaces = {}
    for idx, data in by_index.items():
        if "ifindex" not in data or "ifdescr" not in data:
            warnings.append(
                "Skipping interface index {0}: missing ifIndex or ifDescr".format(idx)
            )
            continue
        iface_name = data["ifdescr"]
        interfaces[iface_name] = data

    return interfaces


def main():
    """Module entry point."""
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type="str", required=True),
            port=dict(type="int", default=161),
            version=dict(type="str", required=True, choices=["v2c", "v3"]),
            community=dict(type="str"),
            username=dict(type="str"),
            level=dict(type="str", choices=["authNoPriv", "authPriv"]),
            integrity=dict(
                type="str",
                choices=["md5", "sha", "sha224", "sha256", "sha384", "sha512"],
            ),
            authkey=dict(type="str", no_log=True),
            privacy=dict(type="str", choices=["des", "aes", "aes192", "aes256"]),
            privkey=dict(type="str", no_log=True),
            timeout=dict(type="int", default=10),
            retries=dict(type="int", default=3),
            gather_subset=dict(
                type="list",
                elements="str",
                default=list(DEFAULT_GATHER_SUBSET),
            ),
        ),
        required_if=[
            ("version", "v2c", ("community",)),
            ("version", "v3", ("username", "level", "integrity", "authkey")),
            ("level", "authPriv", ("privacy", "privkey")),
        ],
        supports_check_mode=True,
    )

    # Fail fast if PySNMP is not installed.
    if not HAS_PYSNMP:
        module.fail_json(
            msg=(
                "Missing required Python library 'pysnmp' (>= 6.2.0, < 7.0.0). "
                "Install it on the Ansible controller: "
                "pip install 'pysnmp>=6.2.0,<7.0.0'. "
                "Import error: {0}"
            ).format(PYSNMP_IMPORT_ERROR)
        )

    # Validate gather_subset values.
    gather_subset = set(module.params["gather_subset"])
    invalid = gather_subset - VALID_SUBSETS
    if invalid:
        module.fail_json(
            msg="Invalid gather_subset values: {0}. Valid: {1}".format(
                ", ".join(sorted(invalid)),
                ", ".join(sorted(VALID_SUBSETS)),
            )
        )

    # Import async SNMP poller from module_utils (keeps async def out of
    # the module file, which is required by ansible-test sanity).
    from ansible_collections.torie_coding.snmp.plugins.module_utils.snmp_poller import (  # pylint: disable=import-outside-toplevel,import-error
        gather_snmp_facts,
    )

    try:
        auth_data = _build_auth_data(module.params)
        facts, warnings = gather_snmp_facts(
            module, auth_data,
            SCALAR_OIDS, IP_ADDR_TABLE_OIDS, IF_TABLE_OIDS,
            _parse_scalar_results, _parse_ip_addr_table, _parse_if_table,
            gather_subset,
        )
    except Exception as exc:
        module.fail_json(msg="SNMP operation failed: {0}".format(exc))

    result = dict(changed=False, ansible_facts=facts)
    for warning in warnings:
        module.warn(warning)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
