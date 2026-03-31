# torie_coding.snmp

Ansible collection for gathering SNMP facts from network devices using native PySNMP.

## Features

- **SNMPv2c** and **SNMPv3** (authNoPriv, authPriv) support
- Authentication: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- Privacy: DES, AES-128, AES-192, AES-256
- **snmp_facts** — curated device facts (system scalars, IPv4 addresses, interfaces)
- **snmp_get** — targeted GET requests for specific OIDs
- **snmp_walk** — subtree walking with GETBULK, safety cap support
- Fail-fast with clear errors on missing dependencies or SNMP failures
- Partial data handling with Ansible warnings (non-fatal)

## Requirements

- **Ansible**: `ansible-core >= 2.15`
- **Python**: 3.10+ (on the Ansible controller)
- **PySNMP**: `pysnmp-lextudio >= 6.1, < 8`

Install the runtime dependency on the Ansible controller:

```bash
pip install 'pysnmp-lextudio>=6.1,<8'
```

> **Note:** If `pysnmp-lextudio` is not installed, the module will fail immediately
> with a clear error message telling you how to install it.

## Installation

```bash
ansible-galaxy collection install torie_coding.snmp
```

Or from source:

```bash
ansible-galaxy collection build
ansible-galaxy collection install torie_coding-snmp-*.tar.gz
```

## Usage

### Gather SNMP Facts

```yaml
- name: Gather all SNMP facts (default)
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
```

### Targeted GET

```yaml
- name: Get specific OIDs
  torie_coding.snmp.snmp_get:
    host: 192.168.1.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.1.5.0
      - 1.3.6.1.2.1.1.3.0
  register: result
```

### Walk a Subtree

```yaml
- name: Walk ifTable
  torie_coding.snmp.snmp_walk:
    host: 192.168.1.1
    version: v2c
    community: public
    oids:
      - 1.3.6.1.2.1.2.2
  register: walk_result
```

See [docs/usage.md](docs/usage.md) for complete parameter reference and examples.

## Development

See [docs/development.md](docs/development.md) for setup, testing, and contributing.

## Release Process

See [docs/release.md](docs/release.md) for the maintainer release workflow.

## License

[GPL-3.0-or-later](LICENSE)
