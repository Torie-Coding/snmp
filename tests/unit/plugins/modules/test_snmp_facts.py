# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for torie_coding.snmp.snmp_facts module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

# Import the module under test.
from ansible_collections.torie_coding.snmp.plugins.modules import snmp_facts


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def module_args_v2c():
    """Minimal valid v2c module arguments."""
    return {
        "host": "192.168.1.1",
        "port": 161,
        "version": "v2c",
        "community": "public",
        "username": None,
        "level": None,
        "integrity": None,
        "authkey": None,
        "privacy": None,
        "privkey": None,
        "timeout": 10,
        "retries": 3,
        "gather_subset": ["system", "interfaces", "ipv4"],
    }


@pytest.fixture
def module_args_v3():
    """Minimal valid v3 authPriv module arguments."""
    return {
        "host": "10.0.0.1",
        "port": 161,
        "version": "v3",
        "community": None,
        "username": "snmpuser",
        "level": "authPriv",
        "integrity": "sha256",
        "authkey": "authpass123",
        "privacy": "aes",
        "privkey": "privpass123",
        "timeout": 10,
        "retries": 3,
        "gather_subset": ["system", "interfaces", "ipv4"],
    }


# ---------------------------------------------------------------------------
# Protocol mapping tests
# ---------------------------------------------------------------------------

class TestProtocolMappings:
    """Verify AUTH_PROTOCOLS and PRIV_PROTOCOLS are correctly populated."""

    def test_auth_protocols_has_all_keys(self):
        expected = {"md5", "sha", "sha224", "sha256", "sha384", "sha512"}
        assert set(snmp_facts.AUTH_PROTOCOLS.keys()) == expected

    def test_priv_protocols_has_all_keys(self):
        expected = {"des", "aes", "aes192", "aes256"}
        assert set(snmp_facts.PRIV_PROTOCOLS.keys()) == expected


# ---------------------------------------------------------------------------
# _build_auth_data tests
# ---------------------------------------------------------------------------

class TestBuildAuthData:
    """Test _build_auth_data with v2c and v3 parameters."""

    def test_v2c_returns_community_data(self, module_args_v2c):
        result = snmp_facts._build_auth_data(module_args_v2c)
        assert result.__class__.__name__ == "CommunityData"

    def test_v3_authpriv_returns_usm_user_data(self, module_args_v3):
        result = snmp_facts._build_auth_data(module_args_v3)
        assert result.__class__.__name__ == "UsmUserData"


# ---------------------------------------------------------------------------
# _format_mac tests
# ---------------------------------------------------------------------------

class TestFormatMac:
    """Test MAC address formatting."""

    def test_format_mac_string_6_chars(self):
        # Simulate a 6-byte string
        result = snmp_facts._format_mac("\x00\x11\x22\x33\x44\x55")
        assert result == "00:11:22:33:44:55"

    def test_format_mac_non_standard_returns_string(self):
        result = snmp_facts._format_mac("not-a-mac")
        assert result == "not-a-mac"


# ---------------------------------------------------------------------------
# _parse_scalar_results tests
# ---------------------------------------------------------------------------

class TestParseScalarResults:
    """Test parsing of scalar GET results."""

    def test_all_scalars_present(self):
        """All 6 scalar OIDs should map to their ansible_facts keys."""

        class FakeValue:
            def __init__(self, val):
                self._val = val

            def __str__(self):
                return self._val

            def __int__(self):
                return int(self._val)

        var_binds = []
        for key, oid in snmp_facts.SCALAR_OIDS.items():
            if key == "ansible_sysuptime":
                var_binds.append((oid, FakeValue("12345")))
            else:
                var_binds.append((oid, FakeValue("test-{0}".format(key))))

        warnings = []
        facts = snmp_facts._parse_scalar_results(var_binds, warnings)

        assert facts["ansible_sysdescr"] == "test-ansible_sysdescr"
        assert facts["ansible_sysname"] == "test-ansible_sysname"
        assert facts["ansible_sysuptime"] == 12345
        assert len(warnings) == 0

    def test_missing_oid_sets_none_with_warning(self):
        """If an OID is missing from the response, its key should be None."""
        warnings = []
        facts = snmp_facts._parse_scalar_results([], warnings)

        for key in snmp_facts.SCALAR_OIDS:
            assert facts[key] is None
        assert len(warnings) == len(snmp_facts.SCALAR_OIDS)


# ---------------------------------------------------------------------------
# _parse_ip_addr_table tests
# ---------------------------------------------------------------------------

class TestParseIpAddrTable:
    """Test parsing of ipAddrTable WALK results."""

    def test_excludes_loopback(self):
        ip_oid = snmp_facts.IP_ADDR_TABLE_OIDS["ipaddress"]
        rows = [
            [
                ("{0}.10.0.0.1".format(ip_oid), "10.0.0.1"),
                ("{0}.127.0.0.1".format(ip_oid), "127.0.0.1"),
            ],
        ]
        warnings = []
        result = snmp_facts._parse_ip_addr_table(rows, warnings)
        assert result == ["10.0.0.1"]

    def test_empty_walk_returns_empty_list(self):
        warnings = []
        result = snmp_facts._parse_ip_addr_table([], warnings)
        assert result == []


# ---------------------------------------------------------------------------
# _parse_if_table tests
# ---------------------------------------------------------------------------

class TestParseIfTable:
    """Test parsing of ifTable WALK results."""

    def test_basic_interface_parsing(self):
        """A complete interface row should be correctly parsed."""
        prefix = snmp_facts.IF_TABLE_OIDS
        rows = [
            [
                ("{0}.1".format(prefix["ifindex"]), "1"),
                ("{0}.1".format(prefix["ifdescr"]), "eth0"),
                ("{0}.1".format(prefix["iftype"]), "6"),
                ("{0}.1".format(prefix["ifspeed"]), "1000000000"),
                ("{0}.1".format(prefix["ifphysaddress"]), "aa:bb:cc:dd:ee:ff"),
                ("{0}.1".format(prefix["ifadminstatus"]), "1"),
                ("{0}.1".format(prefix["ifoperstatus"]), "1"),
            ],
        ]
        warnings = []
        result = snmp_facts._parse_if_table(rows, warnings)
        assert "eth0" in result
        assert result["eth0"]["ifindex"] == "1"
        assert result["eth0"]["ifadminstatus"] == "up"
        assert result["eth0"]["ifoperstatus"] == "up"

    def test_missing_ifdescr_skips_with_warning(self):
        """An interface row without ifDescr should be skipped."""
        prefix = snmp_facts.IF_TABLE_OIDS
        rows = [
            [
                ("{0}.1".format(prefix["ifindex"]), "1"),
                # No ifDescr
            ],
        ]
        warnings = []
        result = snmp_facts._parse_if_table(rows, warnings)
        assert len(result) == 0
        assert len(warnings) == 1


# ---------------------------------------------------------------------------
# IF_STATUS_MAP tests
# ---------------------------------------------------------------------------

class TestIfStatusMap:
    def test_known_values(self):
        assert snmp_facts.IF_STATUS_MAP[1] == "up"
        assert snmp_facts.IF_STATUS_MAP[2] == "down"
        assert snmp_facts.IF_STATUS_MAP[3] == "testing"


# ---------------------------------------------------------------------------
# VALID_SUBSETS tests
# ---------------------------------------------------------------------------

class TestValidSubsets:
    """Test the VALID_SUBSETS constant."""

    def test_contains_expected_values(self):
        assert snmp_facts.VALID_SUBSETS == frozenset(
            ["system", "interfaces", "ipv4"]
        )


# ---------------------------------------------------------------------------
# gather_subset default behavior tests
# ---------------------------------------------------------------------------

class TestGatherSubsetDefaults:
    """Test that the default gather_subset preserves backward compatibility."""

    def test_default_includes_all_three(self):
        """Default value in argument_spec should be all three subsets."""
        assert set(snmp_facts.DEFAULT_GATHER_SUBSET) == snmp_facts.VALID_SUBSETS
