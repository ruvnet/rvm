#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Documentation file list (order matters for TOC)
// ---------------------------------------------------------------------------

const DOC_FILES = [
  "README.md",
  "01-quickstart.md",
  "02-core-concepts.md",
  "03-architecture.md",
  "04-crate-reference.md",
  "05-capabilities-proofs.md",
  "06-witness-audit.md",
  "07-partitions-scheduling.md",
  "08-memory-model.md",
  "09-wasm-agents.md",
  "10-security.md",
  "11-performance.md",
  "12-bare-metal.md",
  "13-advanced-exotic.md",
  "14-troubleshooting.md",
  "15-glossary.md",
  "cross-reference.md",
] as const;

// ---------------------------------------------------------------------------
// Task-to-chapter mapping for howto tool
// ---------------------------------------------------------------------------

const HOWTO_MAP: Record<string, { chapters: string[]; description: string }> = {
  "build rvm": {
    chapters: ["01-quickstart.md"],
    description: "Clone, compile, and run the full test suite.",
  },
  "boot qemu": {
    chapters: ["01-quickstart.md", "12-bare-metal.md"],
    description: "Boot RVM on QEMU aarch64 virtual machine.",
  },
  "create partition": {
    chapters: ["02-core-concepts.md", "07-partitions-scheduling.md"],
    description: "Understand and create coherence-domain partitions.",
  },
  "split merge partition": {
    chapters: ["07-partitions-scheduling.md"],
    description: "Split partitions along mincut boundaries or merge on rising coherence.",
  },
  "use capabilities": {
    chapters: ["05-capabilities-proofs.md", "02-core-concepts.md"],
    description: "Create, delegate, and attenuate capability tokens.",
  },
  "write proofs": {
    chapters: ["05-capabilities-proofs.md"],
    description: "Understand P1/P2/P3 proof tiers and proof gates.",
  },
  "audit witness": {
    chapters: ["06-witness-audit.md"],
    description: "Query witness trails, verify hash chains, replay events.",
  },
  "manage memory": {
    chapters: ["08-memory-model.md"],
    description: "Work with Hot/Warm/Dormant/Cold memory tiers and buddy allocator.",
  },
  "run wasm agent": {
    chapters: ["09-wasm-agents.md"],
    description: "Deploy and manage WebAssembly guest agents.",
  },
  "secure rvm": {
    chapters: ["10-security.md", "05-capabilities-proofs.md"],
    description: "Understand threat model, attestation chains, DMA budgets.",
  },
  "benchmark performance": {
    chapters: ["11-performance.md", "01-quickstart.md"],
    description: "Run criterion benchmarks and interpret results.",
  },
  "bare metal boot": {
    chapters: ["12-bare-metal.md"],
    description: "AArch64 EL2 entry, PL011 UART, GICv2, stage-2 page tables.",
  },
  "advanced exotic": {
    chapters: ["13-advanced-exotic.md"],
    description: "Seed profiles, appliance deployment, chip targets, RuVector.",
  },
  "troubleshoot debug": {
    chapters: ["14-troubleshooting.md"],
    description: "Fix common build errors, QEMU issues, debugging tips.",
  },
  "understand architecture": {
    chapters: ["03-architecture.md", "02-core-concepts.md"],
    description: "Crate layering, dependency graph, four-layer stack.",
  },
  "api reference": {
    chapters: ["04-crate-reference.md", "15-glossary.md"],
    description: "Per-crate API surface, public types, traits, constants.",
  },
  "cross reference": {
    chapters: ["cross-reference.md"],
    description: "Topic-to-chapter mapping for quick navigation.",
  },
  "scheduling": {
    chapters: ["07-partitions-scheduling.md"],
    description: "2-signal scheduler and scheduling modes.",
  },
};

// ---------------------------------------------------------------------------
// Document cache
// ---------------------------------------------------------------------------

interface DocEntry {
  filename: string;
  filepath: string;
  content: string;
  lines: string[];
}

let docCache: DocEntry[] = [];

function getDocsDir(): string {
  return path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
}

export function loadDocs(docsDir?: string): DocEntry[] {
  const dir = docsDir ?? getDocsDir();
  const entries: DocEntry[] = [];

  for (const filename of DOC_FILES) {
    const filepath = path.join(dir, filename);
    try {
      const content = fs.readFileSync(filepath, "utf-8");
      entries.push({
        filename,
        filepath,
        content,
        lines: content.split("\n"),
      });
    } catch {
      // File may not exist yet -- skip silently
    }
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Tool implementations (exported for CLI reuse)
// ---------------------------------------------------------------------------

export function docsSearch(
  docs: DocEntry[],
  query: string,
  maxResults: number = 10,
): string {
  const lowerQuery = query.toLowerCase();
  const terms = lowerQuery.split(/\s+/).filter(Boolean);

  interface Match {
    filename: string;
    lineNum: number;
    context: string;
    score: number;
  }

  const matches: Match[] = [];

  for (const doc of docs) {
    for (let i = 0; i < doc.lines.length; i++) {
      const line = doc.lines[i];
      const lowerLine = line.toLowerCase();

      // Score: exact phrase match > all terms present > any term present
      let score = 0;
      if (lowerLine.includes(lowerQuery)) {
        score = 3;
      } else if (terms.every((t) => lowerLine.includes(t))) {
        score = 2;
      } else if (terms.some((t) => lowerLine.includes(t))) {
        score = 1;
      }

      if (score > 0) {
        // Gather context: 1 line before and 1 line after
        const start = Math.max(0, i - 1);
        const end = Math.min(doc.lines.length - 1, i + 1);
        const contextLines: string[] = [];
        for (let j = start; j <= end; j++) {
          contextLines.push(doc.lines[j]);
        }

        matches.push({
          filename: doc.filename,
          lineNum: i + 1,
          context: contextLines.join("\n"),
          score,
        });
      }
    }
  }

  // Deduplicate overlapping context windows
  const deduped: Match[] = [];
  const seen = new Set<string>();

  matches.sort((a, b) => b.score - a.score || a.lineNum - b.lineNum);

  for (const m of matches) {
    const key = `${m.filename}:${m.lineNum}`;
    if (!seen.has(key)) {
      deduped.push(m);
      seen.add(key);
      // Mark nearby lines as seen to reduce noise
      seen.add(`${m.filename}:${m.lineNum - 1}`);
      seen.add(`${m.filename}:${m.lineNum + 1}`);
    }
  }

  const results = deduped.slice(0, maxResults);

  if (results.length === 0) {
    return `No results found for "${query}".`;
  }

  const parts: string[] = [`## Search Results for "${query}"\n`];
  parts.push(`Found ${results.length} result(s):\n`);

  for (const r of results) {
    parts.push(`### ${r.filename} (line ${r.lineNum})\n`);
    parts.push("```");
    parts.push(r.context);
    parts.push("```\n");
  }

  return parts.join("\n");
}

export function docsNavigate(docs: DocEntry[], chapter?: string): string {
  if (!chapter) {
    // Return the TOC from README.md
    const readme = docs.find((d) => d.filename === "README.md");
    if (!readme) {
      return "README.md not found. Available files:\n" +
        docs.map((d) => `- ${d.filename}`).join("\n");
    }

    // Extract the Table of Contents section
    const tocStart = readme.content.indexOf("## Table of Contents");
    if (tocStart === -1) {
      return readme.content;
    }
    const afterToc = readme.content.indexOf("\n---", tocStart + 1);
    const tocSection = afterToc === -1
      ? readme.content.slice(tocStart)
      : readme.content.slice(tocStart, afterToc);

    return tocSection.trim();
  }

  // Find the matching chapter
  const normalized = chapter.replace(/^0+/, "").toLowerCase();
  const match = docs.find((d) => {
    const name = d.filename.toLowerCase();
    // Match by number prefix, partial name, or full filename
    return (
      name === chapter.toLowerCase() ||
      name === `${chapter.toLowerCase()}.md` ||
      name.startsWith(`${chapter.padStart(2, "0")}-`) ||
      name.includes(normalized)
    );
  });

  if (!match) {
    const available = docs.map((d) => `- ${d.filename}`).join("\n");
    return `Chapter "${chapter}" not found.\n\nAvailable chapters:\n${available}`;
  }

  return `# ${match.filename}\n\n${match.content}`;
}

export function docsXref(docs: DocEntry[], concept: string): string {
  const lowerConcept = concept.toLowerCase();

  interface Ref {
    filename: string;
    lineNum: number;
    line: string;
    isHeading: boolean;
    isLink: boolean;
  }

  const refs: Ref[] = [];

  for (const doc of docs) {
    for (let i = 0; i < doc.lines.length; i++) {
      const line = doc.lines[i];
      const lowerLine = line.toLowerCase();

      if (lowerLine.includes(lowerConcept)) {
        refs.push({
          filename: doc.filename,
          lineNum: i + 1,
          line: line.trim(),
          isHeading: line.startsWith("#"),
          isLink: /\[.*\]\(.*\.md.*\)/.test(line),
        });
      }
    }
  }

  if (refs.length === 0) {
    return `No cross-references found for "${concept}".`;
  }

  // Group by file
  const byFile = new Map<string, Ref[]>();
  for (const ref of refs) {
    const existing = byFile.get(ref.filename) ?? [];
    existing.push(ref);
    byFile.set(ref.filename, existing);
  }

  const parts: string[] = [`## Cross-References for "${concept}"\n`];
  parts.push(`Found references in ${byFile.size} file(s):\n`);

  // Sort: files with headings first (likely primary definition)
  const sorted = [...byFile.entries()].sort((a, b) => {
    const aHasHeading = a[1].some((r) => r.isHeading) ? 0 : 1;
    const bHasHeading = b[1].some((r) => r.isHeading) ? 0 : 1;
    return aHasHeading - bHasHeading;
  });

  for (const [filename, fileRefs] of sorted) {
    const headingRefs = fileRefs.filter((r) => r.isHeading);
    const linkRefs = fileRefs.filter((r) => r.isLink && !r.isHeading);
    const otherRefs = fileRefs.filter((r) => !r.isHeading && !r.isLink);

    parts.push(`### ${filename}`);

    if (headingRefs.length > 0) {
      parts.push("\n**Headings:**");
      for (const r of headingRefs) {
        parts.push(`- Line ${r.lineNum}: ${r.line}`);
      }
    }

    if (linkRefs.length > 0) {
      parts.push("\n**Links:**");
      for (const r of linkRefs.slice(0, 5)) {
        parts.push(`- Line ${r.lineNum}: ${r.line}`);
      }
    }

    if (otherRefs.length > 0) {
      parts.push(`\n**Mentions:** ${otherRefs.length} occurrence(s)`);
      for (const r of otherRefs.slice(0, 3)) {
        parts.push(`- Line ${r.lineNum}: ${r.line.slice(0, 120)}${r.line.length > 120 ? "..." : ""}`);
      }
    }

    parts.push("");
  }

  return parts.join("\n");
}

export function docsGlossary(docs: DocEntry[], term: string): string {
  const glossary = docs.find(
    (d) => d.filename === "15-glossary.md",
  );

  // If no dedicated glossary file, search all docs for definition-like patterns
  const lowerTerm = term.toLowerCase();
  const results: string[] = [];

  if (glossary) {
    // Search the glossary file first
    const lines = glossary.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.toLowerCase().includes(lowerTerm)) {
        // Grab context: heading + body until next heading or blank section
        let start = i;
        // Walk back to find the term's heading
        while (start > 0 && !lines[start].startsWith("#") && !lines[start].startsWith("**")) {
          start--;
        }
        let end = i + 1;
        // Walk forward to find the end of the definition
        while (
          end < lines.length &&
          !lines[end].startsWith("#") &&
          !(lines[end].startsWith("**") && end > i + 1)
        ) {
          end++;
        }
        const block = lines.slice(start, end).join("\n").trim();
        if (block.length > 0) {
          results.push(`### From 15-glossary.md (line ${start + 1})\n\n${block}`);
          break; // Take the first glossary match
        }
      }
    }
  }

  // Also search other docs for definitions
  for (const doc of docs) {
    if (doc.filename === "15-glossary.md") continue;

    for (let i = 0; i < doc.lines.length; i++) {
      const line = doc.lines[i];
      const lowerLine = line.toLowerCase();

      // Look for heading-level definitions or bold definitions
      if (
        lowerLine.includes(lowerTerm) &&
        (line.startsWith("#") || line.startsWith("**") || line.startsWith("- **"))
      ) {
        const end = Math.min(i + 4, doc.lines.length);
        const block = doc.lines.slice(i, end).join("\n").trim();
        results.push(`### From ${doc.filename} (line ${i + 1})\n\n${block}`);

        if (results.length >= 5) break;
      }
    }

    if (results.length >= 5) break;
  }

  if (results.length === 0) {
    return `No glossary entry found for "${term}". Try docs_search for a broader search.`;
  }

  return `## Glossary: "${term}"\n\n${results.join("\n\n---\n\n")}`;
}

export function docsApi(docs: DocEntry[], symbol: string): string {
  const lowerSymbol = symbol.toLowerCase();

  interface ApiMatch {
    filename: string;
    lineNum: number;
    block: string;
    isCodeBlock: boolean;
    score: number;
  }

  const matches: ApiMatch[] = [];

  for (const doc of docs) {
    let inCodeBlock = false;
    let codeBlockStart = -1;

    for (let i = 0; i < doc.lines.length; i++) {
      const line = doc.lines[i];

      if (line.startsWith("```")) {
        if (inCodeBlock) {
          // End of code block -- check if the block contains the symbol
          const blockContent = doc.lines.slice(codeBlockStart, i + 1).join("\n");
          if (blockContent.toLowerCase().includes(lowerSymbol)) {
            // Include heading context before the code block
            let headingLine = codeBlockStart;
            while (headingLine > 0 && !doc.lines[headingLine].startsWith("#")) {
              headingLine--;
            }
            const contextStart = Math.max(headingLine, codeBlockStart - 3);
            const fullBlock = doc.lines.slice(contextStart, i + 1).join("\n");
            matches.push({
              filename: doc.filename,
              lineNum: codeBlockStart + 1,
              block: fullBlock,
              isCodeBlock: true,
              score: 3,
            });
          }
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
          codeBlockStart = i;
        }
        continue;
      }

      if (!inCodeBlock && line.toLowerCase().includes(lowerSymbol)) {
        // Check for struct/type/trait/fn definitions or heading-level API docs
        const isApiLine =
          line.startsWith("#") ||
          line.includes("pub struct") ||
          line.includes("pub enum") ||
          line.includes("pub trait") ||
          line.includes("pub fn") ||
          line.includes("pub type") ||
          line.includes("pub const") ||
          line.startsWith("| `") ||
          line.startsWith("- `");

        if (isApiLine) {
          const start = Math.max(0, i - 1);
          const end = Math.min(doc.lines.length, i + 6);
          const block = doc.lines.slice(start, end).join("\n");
          matches.push({
            filename: doc.filename,
            lineNum: i + 1,
            block,
            isCodeBlock: false,
            score: line.startsWith("#") ? 2 : 1,
          });
        }
      }
    }
  }

  if (matches.length === 0) {
    return `No API documentation found for "${symbol}". Try docs_search for a broader search.`;
  }

  matches.sort((a, b) => b.score - a.score);
  const top = matches.slice(0, 8);

  const parts: string[] = [`## API Documentation for "${symbol}"\n`];
  parts.push(`Found ${matches.length} match(es), showing top ${top.length}:\n`);

  for (const m of top) {
    parts.push(`### ${m.filename} (line ${m.lineNum})\n`);
    parts.push(m.block);
    parts.push("\n");
  }

  return parts.join("\n");
}

export function docsHowto(docs: DocEntry[], task: string): string {
  const lowerTask = task.toLowerCase();
  const taskTerms = lowerTask.split(/\s+/).filter(Boolean);

  interface HowtoMatch {
    key: string;
    entry: { chapters: string[]; description: string };
    score: number;
  }

  const matches: HowtoMatch[] = [];

  for (const [key, entry] of Object.entries(HOWTO_MAP)) {
    const lowerKey = key.toLowerCase();
    const lowerDesc = entry.description.toLowerCase();
    const combined = `${lowerKey} ${lowerDesc}`;

    let score = 0;
    if (combined.includes(lowerTask)) {
      score = 3;
    } else {
      const matchedTerms = taskTerms.filter((t) => combined.includes(t));
      score = matchedTerms.length;
    }

    if (score > 0) {
      matches.push({ key, entry, score });
    }
  }

  matches.sort((a, b) => b.score - a.score);

  if (matches.length === 0) {
    // Fall back to search
    const searchResult = docsSearch(docs, task, 5);
    return `## How To: "${task}"\n\nNo specific guide found. Here are search results:\n\n${searchResult}`;
  }

  const parts: string[] = [`## How To: "${task}"\n`];
  parts.push(`Found ${matches.length} relevant guide(s):\n`);

  for (const m of matches.slice(0, 5)) {
    parts.push(`### ${m.key}`);
    parts.push(`${m.entry.description}\n`);
    parts.push("**Recommended reading:**");
    for (const ch of m.entry.chapters) {
      const doc = docs.find((d) => d.filename === ch);
      const title = doc
        ? (doc.lines.find((l) => l.startsWith("# "))?.replace(/^#\s+/, "") ?? ch)
        : ch;
      parts.push(`- [${title}](${ch})`);
    }
    parts.push("");
  }

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new Server(
  {
    name: "rvm-docs",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "docs_search",
      description:
        "Search across all RVM documentation files by keyword or phrase. Returns matching paragraphs with file paths and line numbers.",
      inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "The search query (keyword or phrase)",
          },
          max_results: {
            type: "number",
            description: "Maximum number of results to return (default: 10)",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "docs_navigate",
      description:
        "Get the table of contents or a specific chapter's content. If chapter is omitted, returns the full TOC.",
      inputSchema: {
        type: "object" as const,
        properties: {
          chapter: {
            type: "string",
            description:
              'Chapter identifier: number (e.g. "05"), partial name (e.g. "security"), or full filename (e.g. "10-security.md")',
          },
        },
      },
    },
    {
      name: "docs_xref",
      description:
        "Find all cross-references for a concept across all documentation files. Returns the primary chapter and all files that reference it.",
      inputSchema: {
        type: "object" as const,
        properties: {
          concept: {
            type: "string",
            description: "The concept to find cross-references for (e.g. \"witness\", \"partition\", \"capability\")",
          },
        },
        required: ["concept"],
      },
    },
    {
      name: "docs_glossary",
      description:
        "Look up a term in the RVM glossary. Returns the definition and cross-references to related documentation.",
      inputSchema: {
        type: "object" as const,
        properties: {
          term: {
            type: "string",
            description: "The glossary term to look up (e.g. \"coherence domain\", \"proof gate\")",
          },
        },
        required: ["term"],
      },
    },
    {
      name: "docs_api",
      description:
        "Find documentation for an RVM type, trait, function, or constant. Searches crate-reference and detailed chapters for API signatures and code examples.",
      inputSchema: {
        type: "object" as const,
        properties: {
          symbol: {
            type: "string",
            description: "The API symbol to search for (e.g. \"CapToken\", \"WitnessRecord\", \"ProofLevel\")",
          },
        },
        required: ["symbol"],
      },
    },
    {
      name: "docs_howto",
      description:
        'Task-oriented documentation search. Describe what you want to do and get a recommended reading path. Example: "boot qemu", "create partition", "run wasm agent".',
      inputSchema: {
        type: "object" as const,
        properties: {
          task: {
            type: "string",
            description: "What you want to accomplish (e.g. \"build rvm\", \"use capabilities\", \"benchmark performance\")",
          },
        },
        required: ["task"],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // Ensure docs are loaded
  if (docCache.length === 0) {
    docCache = loadDocs();
  }

  switch (name) {
    case "docs_search": {
      const query = (args as { query: string; max_results?: number }).query;
      const maxResults = (args as { max_results?: number }).max_results ?? 10;
      return {
        content: [{ type: "text" as const, text: docsSearch(docCache, query, maxResults) }],
      };
    }

    case "docs_navigate": {
      const chapter = (args as { chapter?: string }).chapter;
      return {
        content: [{ type: "text" as const, text: docsNavigate(docCache, chapter) }],
      };
    }

    case "docs_xref": {
      const concept = (args as { concept: string }).concept;
      return {
        content: [{ type: "text" as const, text: docsXref(docCache, concept) }],
      };
    }

    case "docs_glossary": {
      const term = (args as { term: string }).term;
      return {
        content: [{ type: "text" as const, text: docsGlossary(docCache, term) }],
      };
    }

    case "docs_api": {
      const symbol = (args as { symbol: string }).symbol;
      return {
        content: [{ type: "text" as const, text: docsApi(docCache, symbol) }],
      };
    }

    case "docs_howto": {
      const task = (args as { task: string }).task;
      return {
        content: [{ type: "text" as const, text: docsHowto(docCache, task) }],
      };
    }

    default:
      return {
        content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

// ---------------------------------------------------------------------------
// Start server (only when run directly, not when imported by CLI)
// ---------------------------------------------------------------------------

async function main() {
  docCache = loadDocs();

  const fileCount = docCache.length;
  const totalLines = docCache.reduce((sum, d) => sum + d.lines.length, 0);

  console.error(
    `rvm-docs MCP server started. Loaded ${fileCount} doc(s), ${totalLines} lines.`,
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Only start the MCP server when this module is the entry point
const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith("/index.js") ||
   process.argv[1].endsWith("\\index.js"));

if (isDirectRun) {
  main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}
