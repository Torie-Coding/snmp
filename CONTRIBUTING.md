# Contributing to torie_coding.snmp

## Getting Started

1. Fork the repository
2. Clone your fork
3. Set up a development environment (see [docs/development.md](docs/development.md))

## Making Changes

1. Create a feature branch from `main`
2. Make your changes
3. Add a changelog fragment in `changelogs/fragments/` (see [docs/development.md](docs/development.md))
4. Run the test suite:
   ```bash
   python -m pytest tests/unit/ -v
   ansible-lint
   molecule test -s default
   ```
5. Open a pull request

## Code Guidelines

- Follow the [Ansible module development guidelines](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules.html)
- All modules must include `DOCUMENTATION`, `EXAMPLES`, and `RETURN` docstrings
- Use `module.fail_json()` for hard failures
- Use `module.warn()` for non-fatal warnings
- Add unit tests for new functionality
- Add changelog fragments for user-visible changes

## Reporting Issues

Open an issue at [GitHub Issues](https://github.com/Torie-Coding/snmp/issues).
