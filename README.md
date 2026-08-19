# Dependency Risk Scanner

Scans a dependency manifest, resolves every package it installs — direct and
transitive — and reports the ones with known vulnerabilities, what to upgrade,
and what the scan could not read.

Advisories come from [OSV.dev](https://osv.dev) and
[GitHub Security Advisories](https://github.com/advisories). Nothing being
scanned is ever downloaded or executed: metadata is read from PyPI's JSON API
and from lock files, so scanning a hostile manifest cannot run its code.

| Manifest | Read with |
|---|---|
| `requirements.txt` | resolved against PyPI |
| `package.json` + `package-lock.json` | lockfileVersion 2 and 3 |
| `package.json` + `yarn.lock` | yarn 1 and berry |

[Install](#install) · [Usage](#usage) · [Exit codes](#exit-codes) ·
[Output](#output) · [What it does not do](#what-it-does-not-do) ·
[Known limitations](#known-limitations) · [How it works](#how-it-works) ·
[Design notes](#design-notes) ·
[Verified against other tools](#verified-against-other-tools) ·
[Development](#development)

## Install

Python 3.10 or newer. Tested on 3.10, 3.12 and 3.14.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Or with [uv](https://docs.astral.sh/uv/): `uv venv && uv pip install -e ".[dev]"`.

## Usage

```bash
scanner requirements.txt
scanner package.json          # reads the lock file sitting beside it
scanner yarn.lock             # or point at the lock and the manifest is found
```

One argument. Point it at a `package.json` and the lock beside it is found;
point it at a lock file and the `package.json` is. A `package.json` with no
lock is refused, with the command that makes one — a range is not something
that can be scanned, and guessing which version it means would report
vulnerabilities against packages nobody installed.

Manifests are recognised by name, and anything unrecognised is refused rather
than read:

```
$ scanner poetry.lock
error: poetry.lock is not a format this reads. Supported: requirements.txt,
package.json (with package-lock.json or yarn.lock)
  to scan this project, run: poetry export -f requirements.txt --output requirements.txt
```

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

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran, asked every source, found nothing |
| `1` | Found at least one vulnerability |
| `2` | Usage error — bad arguments, unreadable or unrecognised manifest |
| `3` | **Ran, found nothing, but a source did not finish** |
| `130` | Interrupted with Ctrl-C |

`3` exists because "nothing found" and "nothing there" are not the same
sentence. If OSV is unreachable or GitHub rate-limits halfway through, the scan
has not proved anything, and a pipeline that treated that as a pass would turn
an outage into a clean bill of health. A real finding outranks it: with both a
finding and a failed source, the exit code is `1`.

## Output

Real output, `tests/fixtures/demo.txt`, 2.3 seconds:

```
tests/fixtures/demo.txt
2 requirements
5 packages resolved (2 direct, 3 transitive)

2 vulnerable (40.0% of packages), 10 findings
  HIGH 4  MEDIUM 6

urllib3 2.2.1  (direct)
  upgrade urllib3 in the manifest, to at least 2.7.0
severity   advisory         fixed in   summary
────────────────────────────────────────────────────────────────────────────────
HIGH       CVE-2025-66418   2.6.0      urllib3 allows an unbounded number of
                                       links in the decompression chain
```

**The remediation line names the package you actually have to change, which is
not always the vulnerable one.** On a JavaScript monorepo it is one of the
project's own workspaces:

```
tests/fixtures/npm/monorepo/package.json
1 requirements (3 packages)
57 packages resolved (3 direct, 54 transitive)

9 vulnerable (15.8% of packages), 18 findings
  CRITICAL 1  HIGH 6  MEDIUM 5  LOW 6

minimist 0.0.8  (via @acme/web)
  upgrade @acme/web, which requires minimist, to at least 0.2.4
severity   advisory         fixed in       summary
────────────────────────────────────────────────────────────────────────────────
CRITICAL   CVE-2021-44906   1.2.6, 0.2.4   Prototype Pollution in minimist

body-parser 1.19.0  (via @acme/api -> express)
  upgrade express, which requires body-parser, to at least 1.20.6
```

`body-parser` is the vulnerable package and `express` is what you edit — a
transitive package is pinned by whatever required it, so bumping `body-parser`
in the manifest would do nothing. That is what the dependency graph is for, and
it is what a flat package list cannot tell you.

`1 requirements (3 packages)` is not a typo: the root `package.json` declares
one dependency, and the two workspace packages are direct as well — they are
code the project ships rather than something it pulled in, which is how
`npm ls` counts them too.

Two more sections appear when they have anything to say, and they mean
different things:

```
conflicts 3, each scanned at the version shown:
  django 4.2.7: conflicting constraints: ==4.2.7,>=5.2
  redis 5.0.1: conflicting constraints: !=4.5.5,<5.0.0,==5.0.1,>=4.5.2

could not resolve 1:
  light-s3-client: no release satisfies ==0.0.41 (latest is 0.0.40)
```

A **conflict** was resolved and scanned, at the version named — something later
in the walk disagreed with the choice. An **unresolved** package has no version
at all, so it was never queried and is excluded from every count.

`--format json` carries everything the console shows plus the advisory URLs,
the full dependency path, and the list of manifest lines that were skipped.

## What it does not do

Worth being explicit, because a scanner that quietly looks at less reports
fewer vulnerabilities, and on screen that is indistinguishable from a clean
project.

- **It finds known vulnerabilities only.** A package with no advisory reports
  as clean, which is not the same as safe. A newly published malicious package
  has no CVE to find, by construction. This is the largest gap between this and
  a tool like Socket, which also does behavioural and malware analysis,
  typosquat detection and reachability.
- **It does not tell you whether the vulnerable code is reachable.** Every CVE
  in the tree is reported with equal weight.
- **It does not separate production from development dependencies.** On OWASP
  NodeGoat, 750 of the 1,073 packages scanned — 70% — are reachable only
  through `devDependencies`. There is no `--omit dev` yet; there should be.
- **It does not install or build anything.** A package that computes its
  requirements at build time is invisible, deliberately.
- **It reads two ecosystems.** `poetry.lock`, `Pipfile.lock`, `pnpm-lock.yaml`,
  `go.mod`, `Gemfile.lock` and the rest are named and refused, never guessed at.
- **A scan sends package names to a third party.** Private workspace package
  names in a monorepo are included, since the tool asks OSV about every
  resolved package.

## Known limitations

- **No backtracking, and resolution order decides.** A package is resolved at
  the first requirement the breadth-first walk reaches for it; later
  requirements are checked against that choice rather than folded into it.
  Direct dependencies are queued before the walk starts, so a manifest pin
  always beats a transitive request — but two packages at the same depth
  constraining a third are not intersected first: `a` needing `shared>=1.0`
  alongside `b` needing `shared<2.0` resolves `shared` to the newest release,
  where pip installs the one satisfying both. The disagreement is always
  reported as a conflict, so the answer is visible rather than silent. On the
  Airflow constraints file the measured cost is one version out of 715.
- **Some conflicts are artifacts.** Markers are deliberately not evaluated for
  the local machine, so a package declaring `urllib3<1.27` under
  `python_version < "3.10"` and a different range above it has both branches
  intersected. Each entry prints the combined specifier so a reader can judge
  it; the tool does not yet say which kind you are looking at.
- **Yanked releases are treated as installable.** `_best_match` does not read
  PEP 592 yanked markers, so `cryptography<=45.0.0` resolves to 45.0.0 where
  pip and uv both pick 44.0.3. Findings can attach to a version nobody would
  install.
- **Requests are sequential.** Measured: 1,073 packages in 3 minutes 34
  seconds, about 0.20 s per package, nearly all of it waiting on OSV. The
  requests are independent, so this is the first thing to parallelise.
- **Severity is a word, not a score.** Records carrying only a CVSS vector are
  reported as `UNKNOWN` rather than scored by a hand-rolled implementation of
  the CVSS formula. `--min-severity` never hides an `UNKNOWN`.

### JavaScript specifically

- **A lock file is required.** `package.json` alone names ranges; resolving
  those means implementing npm's semver grammar and a second resolver. Refused
  with `npm install --package-lock-only`, which needs no network.
- **`--stale-after` finds nothing**, because a lock file carries no release
  dates. The tool says so rather than reporting zero.
- **`lockfileVersion 1`** (npm 6, end of life 2022) is named and refused rather
  than misread — its shape is different enough that reading it as a modern lock
  finds no packages at all.
- **Aliased packages get imprecise remediation.** `"utils": "npm:lodash@4.17.15"`
  is correctly identified and scanned as `lodash`, but the advice names
  `lodash` where the manifest key is `utils`.
- **yarn does not follow peerDependencies** where npm 7 and later do, so the
  same project scans slightly differently depending on which lock you have.
  That matches the tools themselves.

## How it works

| Module | Job |
|---|---|
| `manifests/requirements_txt.py` | manifest text → direct dependencies |
| `manifests/package_lock.py` | package.json + npm lock → dependency graph |
| `manifests/yarn_lock.py` | package.json + yarn lock → dependency graph |
| `manifests/package_json.py` | the manifest both JavaScript readers start from |
| `manifests/lock_walk.py` | the breadth-first walk both of them share |
| `resolver.py` | breadth-first walk → dependency graph |
| `pypi.py` | one request per package for version and requirements |
| `osv.py` | one request per package for known vulnerabilities |
| `github.py` | asked only about findings OSV described incompletely |
| `sources.py` | one severity scale, deduplication on CVE |
| `report.py` | one dictionary — what `--format json` prints |
| `console.py` | the human version, rendered from that same dictionary |

`manifests/` reads files. Everything else talks to a service, holds the shared
vocabulary, or renders.

The graph is built once and used twice: as the visited set while walking it,
and afterwards to explain findings — `path_to` answers "why is this here" and
`dependents_of` answers "what do I actually upgrade".

### The pipeline forks once, at parsing

```
                     ┌ requirements.txt ─→ parse ─→ resolve (PyPI) ─┐
manifest ─→ dispatch ┤                                              ├─→ graph ─→ OSV ─→ GitHub ─→ report
                     └ package.json + lock ─→ parse ────────────────┘
```

**A lock file is a resolution somebody already performed and committed**, so
the JavaScript path skips the resolver entirely. That is not a shortcut, it is
the only correct answer: `resolver.py` exists to collapse a package name to one
version, and npm routinely installs several. On `tests/fixtures/npm/nested`, a
three-dependency project puts `ms` on disk at 2.0.0, 2.1.1 and 2.1.3 at once.

The branch is six lines in `cli.py` and is left visible rather than hidden
behind one uniform call, because the difference between the two paths is the
interesting part. Everything after the graph — OSV, GitHub, the report, the
console — never learns there is more than one ecosystem.

## Design notes

### Dependencies

Four at runtime, each carrying its weight:

- **`packaging`** (PyPA) for version specifiers, environment markers and PEP 503
  name canonicalization. Using `canonicalize_name()` means package names
  normalize exactly the way pip normalizes them, so `zope.interface`,
  `zope-interface` and `zope_interface` are correctly one project rather than
  three. Its marker evaluation is what makes `celery[redis]` pull in redis while
  plain `celery` does not.
- **`requests`** for HTTP, with `urllib3`'s own `Retry` for backoff — it already
  ships underneath requests and honours `Retry-After`.
- **`rich`** for the findings table. Two hundred findings printed four lines each
  is unreadable; as a table it is one line each, and long summaries wrap to the
  terminal instead of running off it.
- **`pyyaml`** for yarn berry locks, which are real YAML. Yarn 1 locks are not,
  and are read by hand — see below.

### Why package names are normalized per registry, not once

PyPI folds `.`, `-` and `_` together (PEP 503), so `zope.interface` and
`zope_interface` are one project. npm does not, and applying PyPI's rule there
is the worst kind of wrong — measured against live OSV, `lodash.merge@4.6.1`:

```
lodash.merge  ->  GHSA-h726-x36v-rx45
lodash-merge  ->  no advisories
```

A package with 30M weekly downloads reporting clean. `canonical_name(name,
ecosystem)` holds the rule, and every place that compares against a package
name uses it — including the two that match an advisory's own name, where
getting it wrong deletes the "fixed in" column and the upgrade advice while
still showing the finding.

OSV does normalize PyPI names on its side (`Products.CMFPlone` and
`products-cmfplone` return identical results), so the Python half is safe by
the registry's own rule as well as ours.

### Why the yarn 1 reader is written here rather than imported

Yarn berry writes real YAML and is read with PyYAML. Yarn 1 writes a format
that only looks like YAML: a parser fails on the first `dependencies:` block,
whose entries are `name "range"` pairs with no colon.

Both yarn.lock parsers on PyPI were tried. Both get the same thing wrong — a
single resolution often satisfies several requirements, and yarn writes them as
one comma-separated key:

```
"@babel/generator@^7.29.7", "@babel/generator@^7.29.8":
```

Neither library splits it, so a lookup for either range finds nothing. Measured
on the lock under `tests/fixtures/npm/yarn-v1`: 94 entries, of which **11 carry
a joined key covering 22 ranges** — and **42 of the 168 edge lookups in the
file, 25%, are answered by one of them**. Those edges would silently resolve to
nothing. Neither library has shipped a release in over a year, which is the
signal this tool exists to surface.

### Why not `pip-requirements-parser`

It wraps pip's own parsing code and handles more requirements-file syntax than
this does. Its last release was December 2022, and adding an unmaintained
dependency to a supply chain security tool is the wrong trade to make here.
`packaging.Requirement` already covers the requirement grammar; the rest —
joining line continuations, recognising pip options, editable installs, VCS
references and direct URLs — is small enough to own outright and explain.

The cost is that rarer pip syntax is skipped rather than interpreted. Skipped
lines are recorded rather than dropped, so the report can say what it did not
read — and a file where *nothing* could be read is refused outright rather than
reported as clean. A `requirements.txt` that only lists `-r` includes is the
common way to hit that.

### Why one request per package, not OSV's batch endpoint

`POST /v1/querybatch` takes many packages at once, but returns vulnerability
ids rather than records — anything worth showing a user needs a second request
per id. So its cost is `packages + vulnerabilities`, and the second term is
unbounded. Per-package is bounded by the package count, so a stale manifest
costs the same as a clean one: worse best case, predictable worst case.

### Why GitHub is only asked about gaps

Across the packages tested, GitHub found no CVE that OSV had not — unsurprising,
since OSV republishes GitHub's advisories. What GitHub has is better metadata: a
severity word and a patched version on every record, where OSV sometimes carries
only a CVSS vector.

So it is asked only about findings OSV described incompletely, looked up by CVE,
and the answers are cached by CVE including the negative ones. Scanning OWASP
NodeGoat — 1,073 packages, 205 findings — completed **with no GitHub token and
no rate limit hit**, inside the unauthenticated ceiling of 60 requests an hour.
Set `GITHUB_TOKEN` to raise that to 5000; without one the scan still completes
and reports which source did not finish.

REST rather than GraphQL because GitHub's unauthenticated GraphQL limit is zero —
the tool would do nothing at all for anyone without a token — and because
`?cve_id=` is exactly the question being asked.

## Verified against other tools

Correctness here is checked against implementations written by other people,
because a test suite that only asserts the code does what the code was written
to do will agree with a bug. That is not hypothetical: an earlier resolver bug
reported 434 of 805 packages at two versions, and 295 passing tests said nothing.

### Python, against `uv pip compile`

Airflow 2.9.3's constraints file — 711 pins — resolved and compared against
`uv pip compile` on the same file:

| | |
|---|---|
| packages uv installs that we miss | **0** |
| versions agreeing with uv | **714 of 715** |
| packages resolved at two versions | **0** |
| extra packages we keep | 25, every one marker-guarded |

The 25 extras are packages uv drops for this interpreter and we keep on purpose
— `dataclasses`, `enum34`, `pywin32`, the `backports-*` family. A manifest
scanned on a Mac may well be installed on Windows, so markers are not evaluated
for the local platform and the answer is a deliberate superset.

The one disagreement is `apache-airflow` itself, and it is the no-backtracking
limitation with a name on it: the file does not pin it, a provider requires
`>=2.7.0`, uv backtracks to 2.9.3 and we take the newest satisfying release.

That run was a one-off against the Airflow file. `pytest -m network` runs the
same four comparisons continuously against a smaller fixture: nothing uv
installs is missed, no package resolves at two versions, at most one version
differs, and every extra package is one uv dropped for this interpreter.

### JavaScript, against `npm ls --all --json --package-lock-only`

npm reads the lock offline, so this runs in the ordinary suite. Across three
fixtures including OWASP NodeGoat's 1,391 lock entries: nothing missing,
nothing extra, no dangling edges. NodeGoat resolves to 1,073 packages nested
twelve deep, with 36 direct.

The one deliberate difference is aliases. `npm ls` reports an aliased dependency
under the name it was declared as, because it is describing the tree on disk. We
report the name the registry knows, because we are about to ask an advisory
database about it — and `utils` has no advisories while `lodash@4.17.11` has
several.

### The two lock formats against each other, and against `npm audit`

A six-dependency project, locked twice — once with `npm install
--package-lock-only`, once with `yarn install`:

```
package-lock.json   355 packages resolved (6 direct, 349 transitive)   1 vulnerable, 3 findings
yarn.lock           355 packages resolved (6 direct, 349 transitive)   1 vulnerable, 3 findings
```

Identical, from two files that look nothing alike. `npm audit` on the same
project independently reports one vulnerable package, `jsonwebtoken`, which is
the one we report.

On the larger fixtures the two yarn readers are checked against each other:
same `package.json`, **94 packages each with identical names**. One version
differs, because the locks were generated on different days and the range
floats — the lock files disagree, not the readers.

## Development

```bash
pytest            # 462 tests, no network — every client takes an injected session
pytest -m network # 4 more, comparing against `uv pip compile`
ruff format .
ruff check .
mypy scanner/ tests/
```

The default suite needs `npm` on PATH for the comparison tests and skips them
without it. It never reaches the network.

Fixtures under `tests/fixtures/` include two collections of things that show up
in real manifests and should not take a scan down: `hostile.txt` for Python, and
`npm/hostile/` for JavaScript — an alias, a `file:` path, a git dependency and an
optional peer nobody installed, in one manifest. Broken npm cases live in the
tests themselves: a byte order mark, a trailing comma, a lock that is a JSON
array, a dependency cycle.

### A note on the test suite

Test count is not coverage. Deleting the `canonicalize_name` call from
`pypi.py` once passed all 422 tests then in the suite, including the one named
after the behaviour it breaks — it asserted `fetch(...) is not None`, and
`fetch` returns a `PackageMetadata` even for a 404. It now asserts the URL
actually requested, and three other tests that could not fail were fixed the
same way.

The suite is checked by mutation: change a decision, run the tests, and see
whether anything fails. 18 mutations of real decisions — folding npm names like
PyPI names, moving `graph.link` below the visited check, ignoring node_modules
shadowing, reading an alias off its install path, hiding `UNKNOWN` severities,
taking the exit code from the printed list — are caught by the tests that name
them. The one that is not is documented above: the constraint fold in
`resolver.py` cannot change which version is chosen, only what the conflict
report says, because a package is fetched at its first pop when nothing else
has been folded in yet.
