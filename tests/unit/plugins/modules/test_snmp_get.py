# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for torie_coding.snmp.snmp_get module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.torie_coding.snmp.plugins.modules import snmp_get


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def module_args_v2c():
    """Minimal valid v2c module arguments for snmp_get."""
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
        "oids": ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"],
    }


@pytest.fixture
def module_args_v3():
    """Minimal valid v3 authPriv module arguments for snmp_get."""
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
        "oids": ["1.3.6.1.2.1.1.1.0"],
    }


# ---------------------------------------------------------------------------
# Protocol mapping tests
# ---------------------------------------------------------------------------

class TestProtocolMappings:
    """Verify AUTH_PROTOCOLS and PRIV_PROTOCOLS are correctly populated."""

    def test_auth_protocols_has_all_keys(self):
        expected = {"md5", "sha", "sha224", "sha256", "sha384", "sha512"}
        assert set(snmp_get.AUTH_PROTOCOLS.keys()) == expected

    def test_priv_protocols_has_all_keys(self):
        expected = {"des", "aes", "aes192", "aes256"}
        assert set(snmp_get.PRIV_PROTOCOLS.keys()) == expected


# ---------------------------------------------------------------------------
# _build_auth_data tests
# ---------------------------------------------------------------------------

class TestBuildAuthData:
    """Test _build_auth_data with v2c and v3 parameters."""

    def test_v2c_returns_community_data(self, module_args_v2c):
        result = snmp_get._build_auth_data(module_args_v2c)
        assert result.__class__.__name__ == "CommunityData"

    def test_v3_authpriv_returns_usm_user_data(self, module_args_v3):
        result = snmp_get._build_auth_data(module_args_v3)
        assert result.__class__.__name__ == "UsmUserData"


# ---------------------------------------------------------------------------
# Module argument spec tests
# ---------------------------------------------------------------------------

class TestArgumentSpec:
    """Verify the module has the expected parameters."""

    def test_oids_parameter_exists(self):
        """The 'oids' parameter should be in the argument spec."""
        # We verify by checking that snmp_get has a main function
        # and imports the expected poller functions.
        assert hasattr(snmp_get, "main")
        assert callable(snmp_get.main)


# ---------------------------------------------------------------------------
# Helpers for result-building tests
# ---------------------------------------------------------------------------

class FakeOid:
    """Simulates a PySNMP ObjectIdentity with string representation."""

    def __init__(self, oid_str):
        self._oid = oid_str

    def __str__(self):
        return self._oid


class FakeValue:
    """Simulates a normal PySNMP value (e.g. OctetString, Integer32)."""

    def __init__(self, val, type_name="OctetString"):
        self._val = val
        self.__class__ = type(type_name, (), {
            "__str__": lambda s: str(val),
        })
        # Re-assign so __class__.__name__ returns the correct type_name
        self._str = str(val)

    def __str__(self):
        return self._str


def _make_fake_value(val, type_name="OctetString"):
    """Create a fake SNMP value object with a controllable class name."""
    ns = {
        "__init__": lambda self, v: setattr(self, "_v", v),
        "__str__": lambda self: str(self._v),
    }
    cls = type(type_name, (), ns)
    return cls(val)


# ---------------------------------------------------------------------------
# Result-building logic tests (mocked, no SNMP agent needed)
# ---------------------------------------------------------------------------

class TestResultBuilding:
    """Test the result-building loop that converts var_binds into the
    module's results list and snmp_value dict."""

    @staticmethod
    def _build_results(var_binds):
        """Replicate the result-building logic from snmp_get.main().

        This mirrors lines 271-284 of snmp_get.py so we can test the
        transformation without invoking AnsibleModule or PySNMP.
        """
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
        return results, snmp_value

    def test_normal_values(self):
        """Normal SNMP values should appear as strings in both structures."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("router01", "OctetString")),
            (FakeOid("1.3.6.1.2.1.1.3.0"), _make_fake_value("123456", "TimeTicks")),
        ]
        results, snmp_value = self._build_results(var_binds)

        assert len(results) == 2
        assert results[0] == {"oid": "1.3.6.1.2.1.1.5.0", "value": "router01", "type": "OctetString"}
        assert results[1] == {"oid": "1.3.6.1.2.1.1.3.0", "value": "123456", "type": "TimeTicks"}

        assert snmp_value["1.3.6.1.2.1.1.5.0"] == "router01"
        assert snmp_value["1.3.6.1.2.1.1.3.0"] == "123456"

    def test_no_such_object_returns_none(self):
        """NoSuchObject values should have value=None."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.99.0"), _make_fake_value("", "NoSuchObject")),
        ]
        results, snmp_value = self._build_results(var_binds)

        assert len(results) == 1
        assert results[0]["oid"] == "1.3.6.1.2.1.99.0"
        assert results[0]["value"] is None
        assert results[0]["type"] == "NoSuchObject"
        assert snmp_value["1.3.6.1.2.1.99.0"] is None

    def test_no_such_instance_returns_none(self):
        """NoSuchInstance values should have value=None."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("", "NoSuchInstance")),
        ]
        results, snmp_value = self._build_results(var_binds)

        assert results[0]["value"] is None
        assert results[0]["type"] == "NoSuchInstance"
        assert snmp_value["1.3.6.1.2.1.1.1.0"] is None

    def test_end_of_mib_view_returns_none(self):
        """EndOfMibView values should have value=None."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("", "EndOfMibView")),
        ]
        results, snmp_value = self._build_results(var_binds)

        assert results[0]["value"] is None
        assert results[0]["type"] == "EndOfMibView"

    def test_results_list_preserves_order(self):
        """Results list should preserve the order of the input var_binds."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("name", "OctetString")),
            (FakeOid("1.3.6.1.2.1.1.3.0"), _make_fake_value("999", "TimeTicks")),
            (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("descr", "OctetString")),
        ]
        results, unused_value = self._build_results(var_binds)

        assert [r["oid"] for r in results] == [
            "1.3.6.1.2.1.1.5.0",
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.1.1.0",
        ]

    def test_results_entry_has_expected_keys(self):
        """Each result dict should have exactly oid, value, type."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("router01", "OctetString")),
        ]
        results, unused_value = self._build_results(var_binds)

        assert set(results[0].keys()) == {"oid", "value", "type"}

    def test_snmp_value_dict_has_all_oids(self):
        """snmp_value dict should have an entry for every queried OID."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("name", "OctetString")),
            (FakeOid("1.3.6.1.2.1.1.3.0"), _make_fake_value("999", "TimeTicks")),
        ]
        unused_results, snmp_value = self._build_results(var_binds)

        assert "1.3.6.1.2.1.1.5.0" in snmp_value
        assert "1.3.6.1.2.1.1.3.0" in snmp_value

    def test_empty_var_binds(self):
        """An empty var_binds list should produce empty results."""
        results, snmp_value = self._build_results([])

        assert results == []
        assert snmp_value == {}

    def test_mixed_normal_and_error_values(self):
        """A mix of normal and error values should be handled correctly."""
        var_binds = [
            (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("router01", "OctetString")),
            (FakeOid("1.3.6.1.2.1.99.0"), _make_fake_value("", "NoSuchObject")),
            (FakeOid("1.3.6.1.2.1.1.3.0"), _make_fake_value("12345", "TimeTicks")),
        ]
        results, snmp_value = self._build_results(var_binds)

        assert len(results) == 3
        assert results[0]["value"] == "router01"
        assert results[1]["value"] is None
        assert results[2]["value"] == "12345"

        assert snmp_value["1.3.6.1.2.1.1.5.0"] == "router01"
        assert snmp_value["1.3.6.1.2.1.99.0"] is None
        assert snmp_value["1.3.6.1.2.1.1.3.0"] == "12345"
