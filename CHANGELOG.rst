================================
Torie\_Coding.Snmp Release Notes
================================

.. contents:: Topics

v1.0.0
======

Minor Changes
-------------

- snmp_facts - new module for gathering SNMP facts from network devices using native PySNMP. Supports SNMPv2c and SNMPv3 (authNoPriv, authPriv) with configurable authentication and privacy protocols.
- snmp_get - new module for targeted SNMP GET requests. Queries one or more explicit OIDs and returns raw results as a list and as a dictionary keyed by OID.
- snmp_walk - new module for SNMP subtree walking. Uses GETBULK with configurable maxRepetitions and a safety-cap (max_results) to prevent runaway walks on large tables.
