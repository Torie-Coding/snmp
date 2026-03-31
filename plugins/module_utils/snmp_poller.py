# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""SNMP polling helpers shared by snmp_facts, snmp_get, and snmp_walk.

This module avoids top-level ``async def`` and ``import pysnmp`` so that
ansible-test sanity compile and import checks pass on all Python versions
(including Python 2.7, which does not support async syntax).

The PySNMP asyncio coroutines are driven synchronously via the event
loop's ``run_until_complete`` method, preserving the original functionality
without requiring ``async def`` in the source file.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


# ---------------------------------------------------------------------------
# Shared SNMP engine / transport helpers
# ---------------------------------------------------------------------------

def create_snmp_session(params):
    """Create an event loop, SNMP engine and UDP transport from module params.

    Returns:
        Tuple of (loop, engine, transport).
    """
    import asyncio  # pylint: disable=import-outside-toplevel
    from pysnmp.hlapi.asyncio import (  # pylint: disable=import-outside-toplevel
        SnmpEngine,
        UdpTransportTarget,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    engine = SnmpEngine()
    transport = UdpTransportTarget(
        (params["host"], params["port"]),
        timeout=params["timeout"],
        retries=params["retries"],
    )
    return loop, engine, transport


def close_snmp_session(engine, loop):
    """Clean up SNMP engine dispatcher and close the event loop."""
    engine.closeDispatcher()
    loop.close()


# ---------------------------------------------------------------------------
# Low-level GET / WALK primitives
# ---------------------------------------------------------------------------

def run_get(loop, engine, auth_data, transport, oid_strings):
    """Execute an SNMP GET for a list of OID strings.

    Returns:
        Tuple of (var_binds, error_message_or_none).
        var_binds is a list of (oid, value) tuples.
    """
    from pysnmp.hlapi.asyncio import (  # pylint: disable=import-outside-toplevel
        ContextData,
        ObjectIdentity,
        ObjectType,
        getCmd,
    )

    var_bind_args = [
        ObjectType(ObjectIdentity(oid)) for oid in oid_strings
    ]

    error_indication, error_status, error_index, var_bind_table = (
        loop.run_until_complete(
            getCmd(
                engine, auth_data, transport, ContextData(),
                *var_bind_args
            )
        )
    )

    if error_indication:
        return [], str(error_indication)
    if error_status:
        return [], "{0} at {1}".format(
            error_status.prettyPrint(),
            error_index and var_bind_table[int(error_index) - 1][0] or "?",
        )
    return var_bind_table, None


def run_walk(loop, engine, auth_data, transport, oid_strings,
             max_repetitions=25, max_results=0):
    """Execute an SNMP GETBULK WALK for a list of root OID strings.

    Args:
        max_repetitions: GETBULK maxRepetitions parameter.
        max_results: Safety cap on total results (0 = unlimited).

    Returns:
        Tuple of (rows, error_message_or_none).
        rows is a list of varBind tuples.
    """
    from pysnmp.hlapi.asyncio import (  # pylint: disable=import-outside-toplevel
        ContextData,
        ObjectIdentity,
        ObjectType,
        bulkWalkCmd,
    )

    oid_objects = [
        ObjectType(ObjectIdentity(oid)) for oid in oid_strings
    ]

    rows = []
    total_count = 0
    walker = bulkWalkCmd(
        engine,
        auth_data,
        transport,
        ContextData(),
        0,   # nonRepeaters
        max_repetitions,
        *oid_objects
    )

    while True:
        try:
            result = loop.run_until_complete(walker.__anext__())
        except StopAsyncIteration:
            break

        error_indication, error_status, error_index, var_bind_table = result
        if error_indication:
            return rows, str(error_indication)
        if error_status:
            return rows, "{0} at {1}".format(
                error_status.prettyPrint(),
                error_index and var_bind_table[int(error_index) - 1][0] or "?",
            )
        rows.append(var_bind_table)
        total_count += len(var_bind_table)
        if 0 < max_results <= total_count:
            break

    return rows, None


# ---------------------------------------------------------------------------
# snmp_facts high-level entry point (backward compatible)
# ---------------------------------------------------------------------------

def gather_snmp_facts(module, auth_data, scalar_oids, ip_addr_table_oids,
                      if_table_oids, parse_scalar_results,
                      parse_ip_addr_table, parse_if_table,
                      gather_subset=None):
    """Synchronous entry point that performs all SNMP queries and returns facts.

    All parsing functions and OID mappings are passed in from the module
    to avoid circular imports.

    Args:
        gather_subset: Set of subset names to collect.  When None or empty,
            all subsets are gathered (backward compatible).  The module always
            provides this via the argument_spec default; the fallback here is
            a safety net.
    """
    if not gather_subset:
        gather_subset = {"system", "interfaces", "ipv4"}

    params = module.params
    warnings = []

    loop, engine, transport = create_snmp_session(params)

    try:
        facts = {}

        # --- Scalar GET (system subset) ---
        if "system" in gather_subset:
            var_binds, get_error = run_get(
                loop, engine, auth_data, transport,
                list(scalar_oids.values())
            )
            if get_error:
                module.fail_json(msg="SNMP GET failed: {0}".format(get_error))

            facts.update(parse_scalar_results(var_binds, warnings))

        # --- ipAddrTable WALK (ipv4 subset) ---
        if "ipv4" in gather_subset:
            ip_rows, ip_error = run_walk(
                loop, engine, auth_data, transport,
                list(ip_addr_table_oids.values())
            )
            if ip_error:
                warnings.append("ipAddrTable walk error: {0}".format(ip_error))
                facts["ansible_all_ipv4_addresses"] = []
            else:
                facts["ansible_all_ipv4_addresses"] = parse_ip_addr_table(
                    ip_rows, warnings
                )

        # --- ifTable WALK (interfaces subset) ---
        if "interfaces" in gather_subset:
            if_rows, if_error = run_walk(
                loop, engine, auth_data, transport,
                list(if_table_oids.values())
            )
            if if_error:
                warnings.append("ifTable walk error: {0}".format(if_error))
                facts["ansible_interfaces"] = {}
            else:
                facts["ansible_interfaces"] = parse_if_table(if_rows, warnings)

    finally:
        close_snmp_session(engine, loop)

    return facts, warnings
