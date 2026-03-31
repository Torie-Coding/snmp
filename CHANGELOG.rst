================================
Torie\_Coding.Snmp Release Notes
================================

.. contents:: Topics

v1.0.3
======

Minor Changes
-------------

- fix missing Python dependency `pysnmp` (>= 6.2.0, < 7.0.0) across CI, development dependencies, documentation, and runtime guidance.
- update changelog config to keep fragments and use nice YAML formatting for changelog.yaml

v1.0.1
======

Minor Changes
-------------

- replace the deprecated Python dependency `pysnmp-lextudio` with `pysnmp>=6.2.0,<7.0.0` across CI, development dependencies, documentation, and runtime guidance.

v1.0.0
======

Minor Changes
-------------

- snmp_facts - new module for gathering SNMP facts from network devices using native PySNMP. Supports SNMPv2c and SNMPv3 (authNoPriv, authPriv) with configurable authentication and privacy protocols.
- snmp_get - new module for targeted SNMP GET requests. Queries one or more explicit OIDs and returns raw results as a list and as a dictionary keyed by OID.
- snmp_walk - new module for SNMP subtree walking. Uses GETBULK with configurable maxRepetitions and a safety-cap (max_results) to prevent runaway walks on large tables.
