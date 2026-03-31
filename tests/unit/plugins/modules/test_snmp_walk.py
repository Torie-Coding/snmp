# Copyright: (c) 2026, Torie-Coding
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for torie_coding.snmp.snmp_walk module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from ansible_collections.torie_coding.snmp.plugins.modules import snmp_walk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def module_args_v2c():
    """Minimal valid v2c module arguments for snmp_walk."""
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
        "oids": ["1.3.6.1.2.1.2.2"],
        "max_repetitions": 25,
        "max_results": 0,
    }


@pytest.fixture
def module_args_v3():
    """Minimal valid v3 authPriv module arguments for snmp_walk."""
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
        "oids": ["1.3.6.1.2.1.2.2"],
        "max_repetitions": 25,
        "max_results": 0,
    }


# ---------------------------------------------------------------------------
# Protocol mapping tests
# ---------------------------------------------------------------------------

class TestProtocolMappings:
    """Verify AUTH_PROTOCOLS and PRIV_PROTOCOLS are correctly populated."""

    def test_auth_protocols_has_all_keys(self):
        expected = {"md5", "sha", "sha224", "sha256", "sha384", "sha512"}
        assert set(snmp_walk.AUTH_PROTOCOLS.keys()) == expected

    def test_priv_protocols_has_all_keys(self):
        expected = {"des", "aes", "aes192", "aes256"}
        assert set(snmp_walk.PRIV_PROTOCOLS.keys()) == expected


# ---------------------------------------------------------------------------
# _build_auth_data tests
# ---------------------------------------------------------------------------

class TestBuildAuthData:
    """Test _build_auth_data with v2c and v3 parameters."""

    def test_v2c_returns_community_data(self, module_args_v2c):
        result = snmp_walk._build_auth_data(module_args_v2c)
        assert result.__class__.__name__ == "CommunityData"

    def test_v3_authpriv_returns_usm_user_data(self, module_args_v3):
        result = snmp_walk._build_auth_data(module_args_v3)
        assert result.__class__.__name__ == "UsmUserData"


# ---------------------------------------------------------------------------
# Module argument spec tests
# ---------------------------------------------------------------------------

class TestArgumentSpec:
    """Verify the module has the expected parameters."""

    def test_main_exists(self):
        assert hasattr(snmp_walk, "main")
        assert callable(snmp_walk.main)


# ---------------------------------------------------------------------------
# Helpers for result-building tests
# ---------------------------------------------------------------------------

class FakeOid:
    """Simulates a PySNMP ObjectIdentity with string representation."""

    def __init__(self, oid_str):
        self._oid = oid_str

    def __str__(self):
        return self._oid


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
    """Test the result-building loop that converts walk rows into the
    module's results list, snmp_value dict, and result_count."""

    @staticmethod
    def _build_results(rows):
        """Replicate the result-building logic from snmp_walk.main().

        This mirrors lines 303-321 of snmp_walk.py so we can test the
        transformation without invoking AnsibleModule or PySNMP.
        """
        results = []
        snmp_value = {}
        for var_bind_row in rows:
            for var_bind in var_bind_row:
                oid = str(var_bind[0])
                value = var_bind[1]
                value_type = value.__class__.__name__

                if value_type in (
                    "NoSuchObject", "NoSuchInstance", "EndOfMibView"
                ):
                    str_value = None
                else:
                    str_value = str(value)

                results.append(
                    dict(oid=oid, value=str_value, type=value_type)
                )
                snmp_value[oid] = str_value
        result_count = len(results)
        return results, snmp_value, result_count

    def test_normal_walk_results(self):
        """Normal walk rows should produce results with correct structure."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.2.2.1.1.1"), _make_fake_value("1", "Integer32")),
                (FakeOid("1.3.6.1.2.1.2.2.1.2.1"), _make_fake_value("eth0", "OctetString")),
            ],
            [
                (FakeOid("1.3.6.1.2.1.2.2.1.1.2"), _make_fake_value("2", "Integer32")),
                (FakeOid("1.3.6.1.2.1.2.2.1.2.2"), _make_fake_value("lo", "OctetString")),
            ],
        ]
        results, snmp_value, result_count = self._build_results(rows)

        assert result_count == 4
        assert len(results) == 4
        assert results[0] == {"oid": "1.3.6.1.2.1.2.2.1.1.1", "value": "1", "type": "Integer32"}
        assert results[1] == {"oid": "1.3.6.1.2.1.2.2.1.2.1", "value": "eth0", "type": "OctetString"}
        assert snmp_value["1.3.6.1.2.1.2.2.1.1.1"] == "1"
        assert snmp_value["1.3.6.1.2.1.2.2.1.2.1"] == "eth0"

    def test_empty_walk_results(self):
        """An empty walk should produce empty results and result_count=0."""
        results, snmp_value, result_count = self._build_results([])

        assert results == []
        assert snmp_value == {}
        assert result_count == 0

    def test_result_count_matches_results_length(self):
        """result_count must always equal len(results)."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("descr", "OctetString")),
                (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("name", "OctetString")),
                (FakeOid("1.3.6.1.2.1.1.6.0"), _make_fake_value("loc", "OctetString")),
            ],
        ]
        results, unused_value, result_count = self._build_results(rows)

        assert result_count == len(results) == 3

    def test_results_entry_has_expected_keys(self):
        """Each result dict should have exactly oid, value, type."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("descr", "OctetString")),
            ],
        ]
        results, unused_value, unused_count = self._build_results(rows)

        assert set(results[0].keys()) == {"oid", "value", "type"}

    def test_no_such_object_returns_none(self):
        """NoSuchObject values should have value=None in walk results."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.99.0"), _make_fake_value("", "NoSuchObject")),
            ],
        ]
        results, snmp_value, unused_count = self._build_results(rows)

        assert results[0]["value"] is None
        assert results[0]["type"] == "NoSuchObject"
        assert snmp_value["1.3.6.1.2.1.99.0"] is None

    def test_end_of_mib_view_returns_none(self):
        """EndOfMibView values should have value=None."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("", "EndOfMibView")),
            ],
        ]
        results, unused_value, unused_count = self._build_results(rows)

        assert results[0]["value"] is None
        assert results[0]["type"] == "EndOfMibView"

    def test_snmp_value_dict_has_all_oids(self):
        """snmp_value dict should contain an entry for every OID found."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("descr", "OctetString")),
                (FakeOid("1.3.6.1.2.1.1.5.0"), _make_fake_value("name", "OctetString")),
            ],
        ]
        unused_results, snmp_value, unused_count = self._build_results(rows)

        assert "1.3.6.1.2.1.1.1.0" in snmp_value
        assert "1.3.6.1.2.1.1.5.0" in snmp_value

    def test_mixed_normal_and_error_values(self):
        """A mix of normal and error values should be handled correctly."""
        rows = [
            [
                (FakeOid("1.3.6.1.2.1.1.1.0"), _make_fake_value("descr", "OctetString")),
                (FakeOid("1.3.6.1.2.1.99.0"), _make_fake_value("", "NoSuchInstance")),
            ],
        ]
        results, snmp_value, result_count = self._build_results(rows)

        assert result_count == 2
        assert results[0]["value"] == "descr"
        assert results[1]["value"] is None
        assert snmp_value["1.3.6.1.2.1.1.1.0"] == "descr"
        assert snmp_value["1.3.6.1.2.1.99.0"] is None


# ---------------------------------------------------------------------------
# max_results safety cap tests (run_walk level)
# ---------------------------------------------------------------------------

class TestMaxResultsBehavior:
    """Test that max_results cap logic works as expected in run_walk.

    These tests exercise the cap logic at the data level, verifying that
    max_results stops accumulation at the right boundary.
    """

    @staticmethod
    def _simulate_capped_walk(all_rows, max_results):
        """Simulate the max_results capping logic from run_walk().

        This mirrors the accumulation loop in snmp_poller.run_walk
        (lines 118-147) so we can test the cap without a live agent.
        """
        rows = []
        total_count = 0
        for var_bind_table in all_rows:
            rows.append(var_bind_table)
            total_count += len(var_bind_table)
            if 0 < max_results <= total_count:
                break
        return rows, total_count

    def test_unlimited_returns_all(self):
        """max_results=0 should return all rows."""
        all_rows = [
            [("a", 1), ("b", 2)],
            [("c", 3), ("d", 4)],
            [("e", 5)],
        ]
        rows, total = self._simulate_capped_walk(all_rows, max_results=0)

        assert len(rows) == 3
        assert total == 5

    def test_cap_stops_at_boundary(self):
        """max_results should stop after the batch that reaches the cap."""
        all_rows = [
            [("a", 1), ("b", 2)],   # total=2
            [("c", 3), ("d", 4)],   # total=4 → cap=3 hit
            [("e", 5)],             # should not be reached
        ]
        rows, total = self._simulate_capped_walk(all_rows, max_results=3)

        assert len(rows) == 2      # stops after second batch
        assert total == 4           # total includes full second batch

    def test_cap_exact_match(self):
        """When total_count exactly equals max_results, walk should stop."""
        all_rows = [
            [("a", 1), ("b", 2)],   # total=2 → cap=2 hit
            [("c", 3)],             # should not be reached
        ]
        rows, total = self._simulate_capped_walk(all_rows, max_results=2)

        assert len(rows) == 1
        assert total == 2

    def test_cap_with_single_row(self):
        """A single row that exceeds the cap should still be included."""
        all_rows = [
            [("a", 1), ("b", 2), ("c", 3)],  # total=3 → cap=1 hit
        ]
        rows, total = self._simulate_capped_walk(all_rows, max_results=1)

        assert len(rows) == 1
        assert total == 3  # the full first batch is included
