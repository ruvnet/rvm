# rvm-docs-mcp

MCP server and CLI tool for searching, navigating, and querying the RVM user guide documentation.

Provides six tools for fast, structured access to the RVM documentation set -- from keyword search to task-oriented reading paths.

## Installation

```bash
cd userguide/mcp
npm install
npm run build
```

## Adding to Claude Code

Register the MCP server so Claude Code can use the documentation tools:

```bash
claude mcp add rvm-docs -- node /absolute/path/to/userguide/mcp/dist/index.js
```

Once registered, the six `docs_*` tools are available in any Claude Code session.

## CLI Usage

The CLI provides the same functionality as the MCP tools, with colored terminal output.

```bash
# Run via npm
npm run cli -- search "capability"

# Or after npm link / global install
rvm-docs search "capability"
```

### Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `search <query>` | `s` | Full-text search across all documentation files |
| `nav [chapter]` | `n` | Show table of contents or a specific chapter |
| `xref <concept>` | `x` | Find cross-references for a concept across all files |
| `glossary <term>` | `g` | Look up a term in the glossary |
| `api <symbol>` | `a` | Find API documentation for a type, trait, or function |
| `howto <task>` | `h` | Task-oriented search with recommended reading paths |

### Examples

```bash
# Search all docs for a keyword
rvm-docs search "capability"
rvm-docs search "proof gate" --max-results 5

# Show table of contents
rvm-docs nav

# Show a specific chapter by number, name, or filename
rvm-docs nav 05
rvm-docs nav security
rvm-docs nav 10-security.md

# Cross-references for a concept
rvm-docs xref "witness"
rvm-docs xref "coherence domain"

# Glossary lookup
rvm-docs glossary "partition"
rvm-docs glossary "proof gate"

# API documentation
rvm-docs api "CapToken"
rvm-docs api "WitnessRecord"
rvm-docs api "ProofLevel"

# Task-oriented search
rvm-docs howto "build rvm"
rvm-docs howto "run wasm agent"
rvm-docs howto "benchmark performance"
```

### Options

| Option | Description |
|--------|-------------|
| `--max-results <n>` | Maximum search results (default: 10, applies to `search`) |
| `--help`, `-h` | Show help message |

## MCP Tools Reference

### docs_search

Search across all documentation files by keyword or phrase.

**Input:**
```json
{ "query": "capability delegation", "max_results": 5 }
```

**Output:** Matching paragraphs with file path, line number, and surrounding context. Results are ranked: exact phrase match > all terms present > any term present.

---

### docs_navigate

Get the table of contents or a specific chapter's content.

**Input:**
```json
{ "chapter": "05" }
```

Omit `chapter` to get the full table of contents from README.md. The chapter parameter accepts a number (`"05"`), partial name (`"security"`), or full filename (`"10-security.md"`).

**Output:** Chapter content as markdown, or the TOC table.

---

### docs_xref

Find all cross-references for a concept across the documentation set.

**Input:**
```json
{ "concept": "witness" }
```

**Output:** Grouped by file, showing headings (likely primary definitions), link references, and mention counts. Files with heading-level references are listed first.

---

### docs_glossary

Look up a term in the glossary.

**Input:**
```json
{ "term": "coherence domain" }
```

**Output:** The glossary definition from 15-glossary.md (if present), plus definition-like references from other chapters (headings, bold terms).

---

### docs_api

Find documentation for an RVM type, trait, function, or constant.

**Input:**
```json
{ "symbol": "CapToken" }
```

**Output:** Matching API signatures, code blocks, and surrounding documentation from the crate reference and detailed chapters. Prioritizes code blocks containing the symbol.

---

### docs_howto

Task-oriented documentation search. Describe what you want to do and get a recommended reading path.

**Input:**
```json
{ "task": "run wasm agent" }
```

**Output:** Matched guide(s) with description and ordered list of recommended chapters. Falls back to full-text search if no specific guide matches.

**Built-in task mappings include:** build rvm, boot qemu, create partition, use capabilities, write proofs, audit witness, manage memory, run wasm agent, secure rvm, benchmark performance, bare metal boot, troubleshoot debug, understand architecture, api reference, and more.

## Architecture

The package has two entry points sharing the same core logic:

```
src/
  index.ts   -- MCP server (stdio transport) + exported tool functions
  cli.ts     -- CLI wrapper with colored terminal output
```

Documentation files are read from the parent directory (`../`) relative to the package root. Files are cached in memory on startup for fast repeated queries. Missing files are skipped silently, so the tools work with partial documentation sets.

## Documentation Files

The tools operate on these files from the userguide directory:

| File | Topic |
|------|-------|
| README.md | Guide overview, paths, prerequisites |
| 01-quickstart.md | Clone, build, boot in QEMU |
| 02-core-concepts.md | Partitions, capabilities, witnesses, proofs |
| 03-architecture.md | Crate layering, dependency graph, four-layer stack |
| 04-crate-reference.md | Per-crate API surface |
| 05-capabilities-proofs.md | Three-tier proof system, capability delegation |
| 06-witness-audit.md | Witness records, hash chains, replay |
| 07-partitions-scheduling.md | Partition lifecycle, split/merge, scheduler |
| 08-memory-model.md | Four-tier memory, buddy allocator |
| 09-wasm-agents.md | WebAssembly guest runtime |
| 10-security.md | Security gate, attestation, threat model |
| 11-performance.md | Benchmarks, profiling, optimization |
| 12-bare-metal.md | AArch64 boot, EL2, UART, GICv2 |
| 13-advanced-exotic.md | Seed profiles, appliance, chip targets |
| 14-troubleshooting.md | Build errors, QEMU issues, FAQ |
| 15-glossary.md | Term definitions |
| cross-reference.md | Topic-to-chapter index |
