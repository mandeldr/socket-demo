# socket-demo

Open Source Dependency Risk Scanner

Scans a dependency manifest, resolves direct and transitive dependencies, and
reports packages linked to known vulnerabilities from OSV.dev and GitHub
Security Advisories.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.10 or newer. Tested on 3.10, 3.12 and 3.14.

## Usage

```bash
scanner requirements.txt
```

Exits `0` when nothing is found and `1` when it finds something, so a CI job
fails on a vulnerable dependency.

| Option | What it does |
|---|---|
| `--format console\|json` | Output format. Default `console` |
| `--output PATH` | Also write the JSON report to a file |
| `--ignore ID` | Suppress an advisory by CVE or GHSA id. Repeatable |
| `--min-severity LEVEL` | Only list findings at least this serious |
| `--stale-after DAYS` | Flag packages with no release in this many days |
| `--show-skipped` | List the manifest lines that were not scanned |

```bash
# machine readable, safe to pipe: progress goes to stderr
scanner requirements.txt --format json | jq '.summary'

# quieten a finding you have already triaged, and say so in the report
scanner requirements.txt --ignore CVE-2025-50181

# only the serious ones, and flag anything unmaintained for two years
scanner requirements.txt --min-severity HIGH --stale-after 730
```

### Output

```
requirements.txt
12 requirements (10 packages)
33 packages resolved (10 direct, 23 transitive)

6 vulnerable (18.2% of packages), 48 findings
  CRITICAL 2  HIGH 15  MEDIUM 23  LOW 7  UNKNOWN 1

urllib3 1.26.20  (via boto3 -> botocore)
  upgrade botocore, which requires urllib3, to at least 2.7.0
severity   advisory         fixed in   summary
─────────────────────────────────────────────────────────────────────────────
HIGH       CVE-2025-66418   2.6.0      urllib3 allows an unbounded number of
                                       links in the decompression chain
```

The remediation line names the package you actually have to change, which is
not always the vulnerable one: a transitive package is pinned by whatever
required it, so bumping `urllib3` in the manifest would do nothing here.

`--format json` carries everything the console shows plus the advisory URLs,
the full dependency path, and the list of manifest lines that were skipped.

## How it works

| Module | Job |
|---|---|
| `parsers.py` | manifest text → direct dependencies |
| `resolver.py` | breadth-first walk → dependency graph |
| `pypi.py` | one request per package for version and requirements |
| `osv.py` | one request per package for known vulnerabilities |
| `github.py` | asked only about findings OSV described incompletely |
| `sources.py` | one severity scale, deduplication on CVE |
| `report.py` | one dictionary — what `--format json` prints |
| `console.py` | the human version, rendered from that same dictionary |

The graph is built once and used twice: as the visited set while walking it,
and afterwards to explain findings — `path_to` answers "why is this here" and
`dependents_of` answers "what do I actually upgrade".

## Design notes

### Dependencies

- **`packaging`** (PyPA) for version specifiers, environment markers, and PEP 503
  name canonicalization. Using `canonicalize_name()` means package names normalize
  exactly the way pip normalizes them, so `zope.interface`, `zope-interface` and
  `zope_interface` are correctly treated as one project rather than three. Its
  marker evaluation is what makes `celery[redis]` pull in redis while plain
  `celery` does not.
- **`requests`** for HTTP, with `urllib3`'s own `Retry` for backoff — it already
  ships underneath requests and honours `Retry-After`, so there was nothing to
  hand-roll.
- **`rich`** for the findings table. Forty-eight findings printed four lines each
  is unreadable; as a table it is one line each and long summaries wrap to the
  terminal instead of running off it.

### Why not `pip-requirements-parser`

`pip-requirements-parser` wraps pip's own internal parsing code and handles more
requirements-file syntax than this project does, including the full set of pip
options.

I chose not to use it. Its last release was December 2022, and adding an
unmaintained dependency to a supply chain security tool is the wrong tradeoff to
make here: "no releases in the last N months" is precisely the signal this kind of
scanner exists to surface. `packaging.Requirement` already covers the requirement
grammar itself, and the remaining work (joining line continuations, recognising
pip options, editable installs, VCS references and direct URLs before attempting
to parse a line) is small enough to own outright and explain.

The cost of that decision is that some rarer pip syntax is skipped rather than
interpreted. Skipped lines are recorded rather than silently dropped, so the report
can say what it did not understand.

### Why one request per package, not OSV's batch endpoint

`POST /v1/querybatch` takes many packages at once, but it returns vulnerability
ids rather than records — anything worth showing a user needs a second request
per id. So its cost is `packages + vulnerabilities`, and the second term is
unbounded.

Measured both ways. On a healthy manifest the batch wins: 13 requests against 47.
On a neglected one — 83% of packages vulnerable, 580 advisory records — it needs
roughly 400 requests where one-per-package needs 30. Per-package is bounded by
the package count, so a stale manifest costs the same as a clean one. That is the
trade I want: worse best case, predictable worst case.

### Why GitHub is only asked about gaps

Across the packages tested, GitHub found no CVE that OSV had not — unsurprising,
since OSV republishes GitHub's advisories. What GitHub has is better metadata: a
severity word and a patched version on every record, where OSV sometimes carries
only a CVSS vector.

So it is asked only about findings OSV described incompletely, looked up by CVE.
Scanning Airflow's 711 pinned packages produced 278 findings and needed 12 GitHub
requests, comfortably inside the unauthenticated limit of 60 per hour. Set
`GITHUB_TOKEN` to raise that to 5000; without one the scan still completes and
reports which source did not finish.

REST rather than GraphQL because GitHub's unauthenticated GraphQL limit is zero —
the tool would do nothing at all for anyone without a token — and because
`?cve_id=` is exactly the question being asked.

### Why severity is a word and not a number

Some records carry only a CVSS vector string. Turning one into a score means
implementing the CVSS formula, and getting it subtly wrong would mislabel how
serious something is. Asking GitHub instead resolves every vector-bearing record
in practice; measured across 300 findings, computing scores locally would have
changed none of them. Anything still unresolved is reported as `UNKNOWN` rather
than guessed at, and `--min-severity` never hides those — unknown means we could
not determine it, not that it does not matter.

## Limitations

- **No backtracking.** A package is resolved once, against every constraint seen
  before that point. A constraint arriving afterwards that would have narrowed the
  choice is reported as a conflict rather than applied, because revisiting it would
  invalidate the subtree already walked. Checked against `uv pip compile` on
  Airflow's 711 pinned packages: 715 of 717 versions match, nothing is missed, and
  92 genuine constraint conflicts are named.
- **Dependencies are read, not built.** Metadata comes from PyPI's JSON API, so
  nothing being scanned is ever downloaded or executed. The cost is that a package
  computing its requirements at build time is invisible — pip sees those because it
  builds; we do not, deliberately.
- **Requests are sequential.** Scanning 1,316 packages takes about five minutes,
  most of it waiting on OSV. The requests are independent, so this is the obvious
  next thing to parallelise.
- **Known vulnerabilities only.** A package with no CVE reports as clean, which is
  not the same as safe — a brand new malicious package has no advisory to find.

## Not yet supported

`package.json` and its lock files. The lock file already contains the fully
resolved tree, so that side is a parsing problem rather than a resolution one.

## Development

```bash
pytest            # 282 tests, no network — every client takes an injected session
pytest -m network # compares our resolution against `uv pip compile`
ruff format .
ruff check .
mypy scanner/ tests/
```

Fixtures under `tests/fixtures/` include `hostile.txt`, which collects the things
that show up in real requirements files and should not take the scan down.
