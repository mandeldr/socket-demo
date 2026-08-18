# socket-demo

Open Source Dependency Risk Scanner

Scans a dependency manifest, resolves direct and transitive dependencies, and
reports packages linked to known vulnerabilities from OSV.dev and GitHub
Security Advisories.

| Manifest | Read with |
|---|---|
| `requirements.txt` | resolved against PyPI |
| `package.json` + `package-lock.json` | lockfileVersion 2 and 3 |
| `package.json` + `yarn.lock` | yarn 1 and berry |

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
scanner package.json          # reads the lock file sitting beside it
```

One argument. Point it at a `package.json` and the lock beside it is found;
point it at a lock file and the `package.json` is. A `package.json` with no
lock is refused, with the command that makes one — a range is not something
that can be scanned, and guessing which version it means would report
vulnerabilities against packages nobody installed.

Manifests are recognised by name, and anything unrecognised is refused rather
than read. A `poetry.lock` or a `go.mod` names the format and, where there is
one, the command that produces something scannable:

```
$ scanner poetry.lock
error: poetry.lock is not a format this reads. Supported: requirements.txt,
package.json (with package-lock.json or yarn.lock)
  to scan this project, run: poetry export -f requirements.txt --output requirements.txt
```

Exits `0` when nothing is found and `1` when it finds something, so a CI job
fails on a vulnerable dependency. Usage errors exit `2`, so a broken invocation
never looks like a vulnerability.

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

The remediation line names the package you actually have to change, which is
not always the vulnerable one. On a JavaScript monorepo the package to change
is one of the project's own workspaces:

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
in the manifest would do nothing. That is what the graph is for, and it is what
a flat package list cannot tell you.

`1 requirements (3 packages)` is not a typo: the root `package.json` declares
one dependency, and the two workspace packages are direct as well — they are
code the project ships rather than something it pulled in, which is how `npm ls`
counts them too.

`--format json` carries everything the console shows plus the advisory URLs,
the full dependency path, and the list of manifest lines that were skipped.

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
version, and npm routinely installs several. On `tests/fixtures/npm/nested`,
a three-dependency project puts `ms` on disk at 2.0.0, 2.1.1 and 2.1.3 at once.

The branch is six lines in `cli.py` and is left visible rather than hidden
behind one uniform call, because the difference between the two paths is the
interesting part. Everything after the graph — OSV, GitHub, the report, the
console — never learns there is more than one ecosystem.

## Design notes

### Dependencies

Four at runtime, each carrying its weight:

- **`packaging`** (PyPA) for version specifiers, environment markers, and PEP 503
  name canonicalization. Using `canonicalize_name()` means package names normalize
  exactly the way pip normalizes them, so `zope.interface`, `zope-interface` and
  `zope_interface` are correctly treated as one project rather than three. Its
  marker evaluation is what makes `celery[redis]` pull in redis while plain
  `celery` does not.
- **`requests`** for HTTP, with `urllib3`'s own `Retry` for backoff — it already
  ships underneath requests and honours `Retry-After`, so there was nothing to
  hand-roll.
- **`rich`** for the findings table. Two hundred findings printed four lines each
  is unreadable; as a table it is one line each and long summaries wrap to the
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

### Why the yarn 1 reader is written here rather than imported

Yarn berry writes real YAML and is read with PyYAML. Yarn 1 writes a format
that only looks like YAML: a parser fails on the first `dependencies:` block,
whose entries are `name "range"` pairs with no colon.

Both yarn.lock parsers on PyPI were tried. Both get the same thing wrong — a
single resolution often satisfies several requirements, and yarn writes them as
one comma separated key:

```
"@babel/generator@^7.29.7", "@babel/generator@^7.29.8":
```

Neither library splits it, so a lookup for either range finds nothing. Measured
on the lock under `tests/fixtures/npm/yarn-v1`: 94 entries, of which **11 carry
a joined key covering 22 ranges** — and **42 of the 168 edge lookups in the
file, 25%, are answered by one of them**. Those edges would silently resolve to
nothing.

Neither library has shipped a release in over a year, which is the signal this
tool exists to surface. Twenty lines here, cross-checked against both, was the
better trade.

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

Per-package is bounded by the package count, so a stale manifest costs the same
as a clean one. That is the trade I want: worse best case on a healthy project,
predictable worst case on a neglected one.

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

### Why severity is a word and not a number

Some records carry only a CVSS vector string. Turning one into a score means
implementing the CVSS formula, and getting it subtly wrong would mislabel how
serious something is. Asking GitHub instead resolves every vector-bearing record
in practice. Anything still unresolved is reported as `UNKNOWN` rather than
guessed at, and `--min-severity` never hides those — unknown means we could not
determine it, not that it does not matter.

## Verified against other tools

Correctness here is checked against implementations written by other people,
because a test suite that only asserts the code does what the code was written
to do will agree with a bug. That is not hypothetical: an earlier resolver bug
reported 434 of 805 packages at two versions and 295 passing tests said nothing.

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

**The one disagreement is `apache-airflow` itself, and it is the no-backtracking
limitation with a name on it.** The constraints file does not pin it; a provider
requires `apache-airflow>=2.7.0`. uv backtracks and lands on 2.9.3. We take the
newest release satisfying the constraint, 3.3.1, and never revisit it. Run with
`apache-airflow==2.9.3` added — how the file is actually meant to be used — and
the disagreement disappears.

Run it: `pytest -m network`.

### JavaScript, against `npm ls --all --json --package-lock-only`

npm reads the lock offline, so this runs in the ordinary suite. Across three
fixtures including OWASP NodeGoat's 1,391 lock entries: nothing missing,
nothing extra, no dangling edges. NodeGoat resolves to 1,073 packages nested
twelve deep, with 36 direct — the 16 dependencies and 20 devDependencies its
`package.json` declares.

The one deliberate difference is aliases. `npm ls` reports an aliased dependency
under the name it was declared as, because it is describing the tree on disk. We
report the name the registry knows, because we are about to ask an advisory
database about it — and `utils` has no advisories while `lodash@4.17.11` has
several.

### yarn 1 against berry

`npm ls` cannot read a yarn.lock, so the two formats are checked against each
other. Same `package.json`, two files that look nothing alike, **94 packages
each and identical package names**. One version differs — `electron-to-chromium`
at 1.5.407 against 1.5.406 — because the two locks were generated on different
days and the range floats. That is the lock files disagreeing, not the readers.

### Socket's own CLI, by hand

It agrees on aliases. It differs on workspace packages, naming them by directory
where `npm ls` and this tool use the name in their `package.json` — `api` rather
than `@acme/api`, and `api` is a real package on the public registry.

## Limitations

- **No backtracking.** A package is resolved once, against every constraint seen
  before that point. A constraint arriving afterwards that would have narrowed the
  choice is reported as a conflict rather than applied, because revisiting it would
  invalidate the subtree already walked. On Airflow that costs exactly one version
  out of 715, named above.
- **Conflicts are reported, not diagnosed, and some are artifacts.** The same
  Airflow run records 45 conflict entries across 9 distinct packages. The count
  inflates because every later requester of an already-settled package re-checks
  it: `urllib3` alone accounts for 21 of the 45. And at least that one is
  spurious — `opensearch-py` declares `urllib3<1.27` under
  `python_version < "3.10"` and a different range above it, and because markers
  are deliberately not evaluated for the local platform, both branches are
  intersected. Each entry prints the combined specifier so a reader can judge it,
  but the tool does not yet tell you which kind you are looking at.
- **Dependencies are read, not built.** Metadata comes from PyPI's JSON API, so
  nothing being scanned is ever downloaded or executed. The cost is that a package
  computing its requirements at build time is invisible — pip sees those because it
  builds; we do not, deliberately.
- **Requests are sequential.** Measured: 1,073 packages in 3 minutes 34 seconds,
  about 0.20 s per package, nearly all of it waiting on OSV. The requests are
  independent, so this is the obvious next thing to parallelise.
- **Known vulnerabilities only.** A package with no CVE reports as clean, which is
  not the same as safe — a brand new malicious package has no advisory to find.
- **Two ecosystems.** `poetry.lock`, `Pipfile.lock`, `go.mod`, `Gemfile.lock`
  and the rest are named and refused. That refusal is deliberate and was added
  after finding the alternative: an unrecognised file used to reach the
  requirements reader, fail to parse every line, and report a clean scan
  exiting 0. `Gemfile.lock` was worse than silent — it read `GEM` and `rails`
  as Python package names, found them on PyPI, and scanned three packages the
  project does not have. A scanner is only allowed to say "clean" about
  something it actually read.

### JavaScript specifically

- **A lock file is required.** `package.json` alone names ranges, and resolving
  those means implementing npm's semver grammar and a second resolver. It is
  refused with `npm install --package-lock-only`, which needs no network. This
  is a deliberate choice, not an omission: inventing versions a user may not
  have installed is how a scanner starts reporting things that are not there.
- **`--stale-after` does nothing.** A lock file carries no release dates. The
  tool says so rather than reporting zero, which would read as "none found"
  when it means "never looked".
- **`lockfileVersion 1`** (npm 6, end of life 2022) is named and refused rather
  than misread. Its shape is different enough that reading it as a modern lock
  finds no packages at all.
- **Aliased packages get imprecise remediation.** `"utils": "npm:lodash@4.17.15"`
  is correctly identified and scanned as `lodash`, but the advice says to
  upgrade `lodash` where the manifest key is `utils`. The finding is right; the
  sentence names the wrong key.
- **yarn does not follow peerDependencies** where npm does. That matches the
  tools, but it means an npm lock and a yarn lock of the same project differ.
- **pnpm and bun** are named and refused, like every other format this does
  not read.

## Development

```bash
pytest            # 441 tests, no network — every client takes an injected session
pytest -m network # 4 more, comparing against `uv pip compile`
ruff format .
ruff check .
mypy scanner/ tests/
```

445 tests in total. The default suite needs `npm` on PATH for the comparison
tests and skips them without it. It never reaches the network.

Fixtures under `tests/fixtures/` include two collections of things that show up
in real manifests and should not take a scan down: `hostile.txt` for Python, and
`npm/hostile/` for JavaScript — an alias, a `file:` path, a git dependency and an
optional peer nobody installed, in one manifest. `npm/broken` cases live in the
tests themselves: a byte order mark, a trailing comma, a lock that is a JSON
array, a dependency cycle.

### A note on the test suite

Deleting the `canonicalize_name` call from `pypi.py` once passed all 422 tests
then in the suite, including the one named after the behaviour it breaks. That
test asserted `fetch(...) is not None`, and `fetch` returns a `PackageMetadata`
even for a 404. It now asserts the URL actually requested, and fails when the
call is removed; three other tests that could not fail were fixed the same way.

Test count is not coverage. Mutation testing the rest is the first thing on the
list.
