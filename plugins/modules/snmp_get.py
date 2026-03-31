#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ansible module for targeted SNMP GET requests."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: snmp_get
short_description: Perform targeted SNMP GET requests for specific OIDs
version_added: "1.0.0"
description:
  - Sends SNMP GET requests for one or more explicit OIDs and returns the
    raw results as a list and as a dictionary keyed by OID.
  - Supports SNMPv2c and SNMPv3 (authNoPriv, authPriv).
  - Uses PySNMP for native Python SNMP operations.
  - Runs on the Ansible controller (connection is SNMP, not SSH).
  - All OID keys are returned in numeric dotted notation.
requirements:
  - "pysnmp-lextudio >= 6.1, < 8"
options:
  host:
    description:
      - Hostname or IP address of the SNMP agent.
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
  oids:
    description:
      - List of OIDs to query via SNMP GET.
      - Must be numeric dotted notation (e.g. C(1.3.6.1.2.1.1.1.0)).
    type: list
    elements: str
    required: true
author:
  - Torie-Coding (@Torie-Coding)
"""

EXAMPLES = r"""
- name: Get sysName and sysUpTime
  torie_coding.snmp.snmp_get:
    host: 192.168.1.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.1.5.0
      - 1.3.6.1.2.1.1.3.0
  register: snmp_result

- name: Show the sysName value
  ansible.builtin.debug:
    msg: "sysName = {{ snmp_result.snmp_value['1.3.6.1.2.1.1.5.0'] }}"

- name: Get a single OID via SNMPv3
  torie_coding.snmp.snmp_get:
    host: switch01.example.com
    version: v3
    username: snmpuser
    level: authPriv
    integrity: sha256
    authkey: "{{ vault_snmp_authkey }}"
    privacy: aes
    privkey: "{{ vault_snmp_privkey }}"
    oids:
      - 1.3.6.1.2.1.1.1.0
"""

RETURN = r"""
results:
  description: >-
    Ordered list of SNMP GET results preserving the request order.
    Each entry contains the OID, its value, and the SNMP type name.
  returned: always
  type: list
  elements: dict
  contains:
    oid:
      description: The numeric dotted OID string.
      type: str
    value:
      description: The value returned by the SNMP agent (as string).
      type: str
    type:
      description: The SNMP type class name (e.g. OctetString, Integer32).
      type: str
snmp_value:
  description: >-
    Dictionary of OID to value for convenient access by OID key.
  returned: always
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule

# PySNMP availability check — mirrors snmp_facts.py pattern.
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


def _build_auth_data(params):
    """Build PySNMP auth data from module parameters."""
    if params["version"] == "v2c":
        return CommunityData(params["community"], mpModel=1)

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
            oids=dict(type="list", elements="str", required=True),
        ),
        required_if=[
            ("version", "v2c", ("community",)),
            ("version", "v3", ("username", "level", "integrity", "authkey")),
            ("level", "authPriv", ("privacy", "privkey")),
        ],
        supports_check_mode=True,
    )

    if not HAS_PYSNMP:
        module.fail_json(
            msg=(
                "Missing required Python library 'pysnmp-lextudio' (>= 6.1). "
                "Install it on the Ansible controller: "
                "pip install 'pysnmp>=6.2.0,<7.0.0'. "
                "Import error: {0}"
            ).format(PYSNMP_IMPORT_ERROR)
        )

    from ansible_collections.torie_coding.snmp.plugins.module_utils.snmp_poller import (  # pylint: disable=import-outside-toplevel,import-error
        create_snmp_session,
        close_snmp_session,
        run_get,
    )

    try:
        auth_data = _build_auth_data(module.params)
        loop, engine, transport = create_snmp_session(module.params)
        try:
            var_binds, error = run_get(
                loop, engine, auth_data, transport, module.params["oids"]
            )
        finally:
            close_snmp_session(engine, loop)

        if error:
            module.fail_json(msg="SNMP GET failed: {0}".format(error))

        results = []
        snmp_value = {}
        for var_bind in var_binds:
            oid = str(var_bind[0])
            value = var_bind[1]
            value_type = value.__class__.__name__

            if value_type in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                str_value = None
            else:
                str_value = str(value)

            results.append(dict(oid=oid, value=str_value, type=value_type))
            snmp_value[oid] = str_value

    except Exception as exc:
        module.fail_json(msg="SNMP operation failed: {0}".format(exc))

    module.exit_json(changed=False, results=results, snmp_value=snmp_value)


if __name__ == "__main__":
    main()
