# Usage Guide

## Shared Connection Parameters

All three modules (`snmp_facts`, `snmp_get`, `snmp_walk`) share the same
SNMP connection and authentication parameters:

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `host` | str | yes | — | Hostname or IP address only. No `host:port` parsing. |
| `port` | int | no | 161 | SNMP UDP port. |
| `version` | str | yes | — | `v2c` or `v3` |
| `community` | str | when v2c | — | SNMP community string |
| `username` | str | when v3 | — | SNMPv3 USM username |
| `level` | str | when v3 | — | `authNoPriv` or `authPriv` |
| `integrity` | str | when level set | — | `md5`, `sha`, `sha224`, `sha256`, `sha384`, `sha512` |
| `authkey` | str | when level set | — | Authentication passphrase |
| `privacy` | str | when authPriv | — | `des`, `aes`, `aes192`, `aes256` |
| `privkey` | str | when authPriv | — | Privacy passphrase |
| `timeout` | int | no | 10 | Seconds per SNMP request |
| `retries` | int | no | 3 | Number of retries |

---

## Module: `torie_coding.snmp.snmp_facts`

Queries a remote SNMP agent and returns curated device facts as `ansible_facts`.

### Additional Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `gather_subset` | list[str] | no | `["system", "interfaces", "ipv4"]` | Subsets to collect. Valid values: `system`, `interfaces`, `ipv4`. |

When `gather_subset` is omitted, all three subsets are collected (backward compatible).
Only the requested subsets generate SNMP traffic — unrequested tables are not walked
and unrequested scalars are not fetched.

### Returned Facts

#### Scalar Facts (via SNMP GET)

| Fact Key | OID | Type |
|---|---|---|
| `ansible_sysdescr` | 1.3.6.1.2.1.1.1.0 | str |
| `ansible_sysobjectid` | 1.3.6.1.2.1.1.2.0 | str |
| `ansible_sysuptime` | 1.3.6.1.2.1.1.3.0 | int |
| `ansible_syscontact` | 1.3.6.1.2.1.1.4.0 | str |
| `ansible_sysname` | 1.3.6.1.2.1.1.5.0 | str |
| `ansible_syslocation` | 1.3.6.1.2.1.1.6.0 | str |

#### IP Address Table (via SNMP WALK)

| Fact Key | Source Table | Type |
|---|---|---|
| `ansible_all_ipv4_addresses` | ipAddrTable (1.3.6.1.2.1.4.20) | list[str] |

Excludes `127.0.0.1` automatically.

#### Interface Table (via SNMP WALK)

| Fact Key | Source Table | Type |
|---|---|---|
| `ansible_interfaces` | ifTable (1.3.6.1.2.1.2.2) | dict |

Each interface is keyed by `ifDescr` and contains:

```json
{
  "ifindex": "1",
  "ifdescr": "eth0",
  "iftype": "6",
  "ifspeed": "1000000000",
  "ifadminstatus": "up",
  "ifoperstatus": "up",
  "ifphysaddress": "00:11:22:33:44:55"
}
```

### Error Handling

| Scenario | Behavior |
|---|---|
| SNMP agent unreachable | `fail_json` with timeout message |
| Authentication failure | `fail_json` with auth error |
| Single scalar OID returns noSuchObject | Key set to `null`, Ansible warning emitted |
| Table walk returns empty | Empty list/dict returned, warning emitted |
| Interface row missing ifDescr | Row skipped, warning emitted |

### Examples

```yaml
# Basic v2c usage (gathers all subsets by default)
- hosts: localhost
  tasks:
    - torie_coding.snmp.snmp_facts:
        host: 10.0.0.1
        version: v2c
        community: public

    - debug:
        var: ansible_sysname

# Gather only system scalars (no table walks — fast on devices like HPE iLO)
- hosts: localhost
  tasks:
    - torie_coding.snmp.snmp_facts:
        host: ilo.example.com
        version: v2c
        community: public
        gather_subset:
          - system

    - debug:
        var: ansible_sysname

# Gather system and interfaces, skip ipv4
- hosts: localhost
  tasks:
    - torie_coding.snmp.snmp_facts:
        host: switch01
        version: v2c
        community: public
        gather_subset:
          - system
          - interfaces

    - debug:
        var: ansible_interfaces

# v3 with SHA-256 and AES
- hosts: localhost
  tasks:
    - torie_coding.snmp.snmp_facts:
        host: switch01
        version: v3
        username: admin
        level: authPriv
        integrity: sha256
        authkey: "{{ vault_auth }}"
        privacy: aes
        privkey: "{{ vault_priv }}"

    - debug:
        var: ansible_interfaces
```

---

## Module: `torie_coding.snmp.snmp_get`

Sends SNMP GET requests for one or more explicit OIDs. Returns raw results
(not `ansible_facts`). All OIDs are in numeric dotted notation.

### Additional Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oids` | list[str] | yes | — | OIDs to query (numeric dotted notation) |

### Return Values

| Key | Type | Description |
|---|---|---|
| `results` | list[dict] | Ordered list with `oid`, `value`, `type` per entry |
| `snmp_value` | dict | OID-to-value dictionary for quick lookup |

### Examples

```yaml
- name: Get sysName and sysUpTime
  torie_coding.snmp.snmp_get:
    host: 192.168.1.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.1.5.0
      - 1.3.6.1.2.1.1.3.0
  register: snmp_result

- name: Show the sysName
  debug:
    msg: "sysName = {{ snmp_result.snmp_value['1.3.6.1.2.1.1.5.0'] }}"
```

---

## Module: `torie_coding.snmp.snmp_walk`

Walks one or more SNMP OID subtrees using GETBULK and returns all OID/value
pairs found. Returns raw results (not `ansible_facts`). All OIDs are in
numeric dotted notation.

### Additional Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `oids` | list[str] | yes | — | Root OIDs to walk (numeric dotted notation) |
| `max_repetitions` | int | no | 25 | GETBULK maxRepetitions value |
| `max_results` | int | no | 0 | Safety cap on total results (0 = unlimited) |

### Return Values

| Key | Type | Description |
|---|---|---|
| `results` | list[dict] | List with `oid`, `value`, `type` per entry |
| `snmp_value` | dict | OID-to-value dictionary for quick lookup |
| `result_count` | int | Total number of OID/value pairs returned |

### Examples

```yaml
- name: Walk the ifTable
  torie_coding.snmp.snmp_walk:
    host: 192.168.1.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.2.2
  register: walk_result

- name: Show result count
  debug:
    msg: "Got {{ walk_result.result_count }} OID values"

- name: Walk with safety cap
  torie_coding.snmp.snmp_walk:
    host: 10.0.0.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.2.2
    max_repetitions: 50
    max_results: 500
```
