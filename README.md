# socket-demo

Open Source Dependency Risk Scanner

Scans a dependency manifest, resolves direct and transitive dependencies, and
reports packages linked to known vulnerabilities.

## Usage

```bash
pip install -e ".[dev]"

scanner tests/fixtures/requirements.txt
scanner tests/fixtures/requirements.txt --format json --output report.json
```

## Design notes

### Dependencies

- **`packaging`** (PyPA) for version specifiers, environment markers, and PEP 503
  name canonicalization. Using `canonicalize_name()` means package names normalize
  exactly the way pip normalizes them, so `zope.interface`, `zope-interface` and
  `zope_interface` are correctly treated as one project rather than three.
- **`requests`** for HTTP.

### Why not `pip-requirements-parser`

`pip-requirements-parser` wraps pip's own internal parsing code and handles more
requirements-file syntax than this project does, including hash pinning and the
full set of pip options.

I chose not to use it. Its last release was December 2022, and adding an
unmaintained dependency to a supply chain security tool is the wrong tradeoff to
make here: "no releases in the last N months" is precisely the signal this kind of
scanner exists to surface. `packaging.Requirement` already covers the requirement
grammar itself, and the remaining work (recognising pip options, editable installs,
VCS references and direct URLs before attempting to parse a line) is small enough
to own outright and explain.

The cost of that decision is that some rarer pip syntax is skipped rather than
interpreted. Skipped lines are recorded rather than silently dropped, so the report
can say what it did not understand.
