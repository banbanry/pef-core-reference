# Contributing to PEF Core Reference

> **Source**: https://github.com/banbanry/pef-core-reference
> **Author**: banbanry (沈鹭)
> **License**: MIT

This is the code reference implementation of the PEF (Anchored Determinism) Meta-Architecture. For the full theory, architecture challenges, and general contribution guidelines, see [pef-architecture/CONTRIBUTING.md](https://github.com/banbanry/pef-architecture/blob/main/CONTRIBUTING.md).

## Quick Start for Contributors

```bash
# Clone
git clone https://github.com/banbanry/pef-core-reference.git
cd pef-core-reference

# Install dependencies
pip install -r requirements.txt

# Run demo
python demo_minimal.py
# Expected: SELF-CHECK: 8/8 PASS

# Run A/B evaluation
cd evaluation
python run_ab_test.py
# Expected: Anomaly detection A=0%, B=100%
```

## What to Contribute

### Code
- Bug fixes in core modules
- New test cases for the A/B evaluation
- Performance improvements
- New operator implementations
- Type hints and documentation

### Tests
- Add edge case tests to the A/B evaluation
- Add unit tests for core modules
- Test on different platforms and Python versions

### Documentation
- Improve module docstrings
- Add usage examples
- Fix typos and clarify comments

## Before Submitting a PR

1. **Demo passes**: `python demo_minimal.py` → `SELF-CHECK: 8/8 PASS`
2. **A/B test passes**: `cd evaluation && python run_ab_test.py` → expected results
3. **All modules import**: No import errors in `pef_core/`
4. **CI passes**: GitHub Actions will run automatically

## Code Style

- PEP 8 compliant
- Type hints for public functions
- Docstrings for modules, classes, and public functions
- PEF-specific mechanisms should have explanatory comments
- Keep the desensitization boundary: no business-specific field names, no internal project references

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`

Examples:
- `fix(state_ledger): correct chain hash computation`
- `feat(evaluation): add identity spoofing test case`
- `test(pefmod): add anchor reuse detection tests`

## Architecture Challenges

For challenges to the PEF architecture itself (not code bugs), please open an issue in the [pef-architecture](https://github.com/banbanry/pef-architecture/issues) repository using the Architecture Challenge template.

---

*PEF Core Reference © 2026 banbanry. Anchored Determinism Meta-Architecture.
Source: https://github.com/banbanry/pef-core-reference*
