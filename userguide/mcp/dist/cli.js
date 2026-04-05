#!/usr/bin/env node
import * as path from "node:path";
import { loadDocs, docsSearch, docsNavigate, docsXref, docsGlossary, docsApi, docsHowto, } from "./index.js";
// ---------------------------------------------------------------------------
// Terminal colors (ANSI escape codes, no dependencies)
// ---------------------------------------------------------------------------
const isColorSupported = process.stdout.isTTY && !process.env["NO_COLOR"];
const c = {
    reset: isColorSupported ? "\x1b[0m" : "",
    bold: isColorSupported ? "\x1b[1m" : "",
    dim: isColorSupported ? "\x1b[2m" : "",
    red: isColorSupported ? "\x1b[31m" : "",
    green: isColorSupported ? "\x1b[32m" : "",
    yellow: isColorSupported ? "\x1b[33m" : "",
    blue: isColorSupported ? "\x1b[34m" : "",
    magenta: isColorSupported ? "\x1b[35m" : "",
    cyan: isColorSupported ? "\x1b[36m" : "",
    white: isColorSupported ? "\x1b[37m" : "",
};
function colorize(text) {
    return text
        // Headings
        .replace(/^(#{1,4}\s.+)$/gm, `${c.bold}${c.cyan}$1${c.reset}`)
        // Bold text
        .replace(/\*\*(.+?)\*\*/g, `${c.bold}$1${c.reset}`)
        // Code blocks - just dim the fences
        .replace(/^```\w*$/gm, `${c.dim}$&${c.reset}`)
        // Inline code
        .replace(/`([^`]+)`/g, `${c.yellow}\`$1\`${c.reset}`)
        // Links
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, `${c.blue}$1${c.reset} ${c.dim}($2)${c.reset}`)
        // List markers
        .replace(/^(\s*[-*])\s/gm, `${c.green}$1${c.reset} `)
        // Line numbers in results
        .replace(/\(line (\d+)\)/g, `${c.dim}(line $1)${c.reset}`);
}
// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------
function printUsage() {
    console.log(`
${c.bold}${c.cyan}rvm-docs${c.reset} -- RVM Documentation Search and Navigation

${c.bold}USAGE:${c.reset}
  rvm-docs <command> [arguments]

${c.bold}COMMANDS:${c.reset}
  ${c.green}search${c.reset} <query>          Search all documentation files
  ${c.green}nav${c.reset} [chapter]           Show table of contents or chapter content
  ${c.green}xref${c.reset} <concept>          Find cross-references for a concept
  ${c.green}glossary${c.reset} <term>         Look up a glossary term
  ${c.green}api${c.reset} <symbol>            Find API documentation for a type/function
  ${c.green}howto${c.reset} <task>            Task-oriented search ("I want to...")

${c.bold}EXAMPLES:${c.reset}
  rvm-docs search "capability"
  rvm-docs search "proof gate" --max-results 5
  rvm-docs nav
  rvm-docs nav 05
  rvm-docs nav security
  rvm-docs xref "witness"
  rvm-docs glossary "partition"
  rvm-docs api "CapToken"
  rvm-docs howto "build rvm"
  rvm-docs howto "run wasm agent"

${c.bold}OPTIONS:${c.reset}
  --max-results <n>    Maximum number of search results (default: 10)
  --help, -h           Show this help message
`);
}
// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
function parseArgs(argv) {
    const args = argv.slice(2); // skip node and script path
    if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
        printUsage();
        process.exit(0);
    }
    const command = args[0];
    let maxResults = 10;
    // Collect positional args and flags
    const positionalParts = [];
    for (let i = 1; i < args.length; i++) {
        if (args[i] === "--max-results" && i + 1 < args.length) {
            maxResults = parseInt(args[i + 1], 10) || 10;
            i++; // skip value
        }
        else if (!args[i].startsWith("--")) {
            positionalParts.push(args[i]);
        }
    }
    return {
        command,
        positional: positionalParts.join(" "),
        maxResults,
    };
}
// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
    const { command, positional, maxResults } = parseArgs(process.argv);
    // Resolve docs directory: two levels up from src/ (mcp/src -> mcp -> userguide)
    const docsDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
    const docs = loadDocs(docsDir);
    if (docs.length === 0) {
        console.error(`${c.red}Error:${c.reset} No documentation files found in ${docsDir}`);
        console.error("Make sure you are running from within the rvm-docs-mcp package.");
        process.exit(1);
    }
    console.error(`${c.dim}Loaded ${docs.length} doc(s) from ${docsDir}${c.reset}\n`);
    let output;
    switch (command) {
        case "search":
        case "s":
            if (!positional) {
                console.error(`${c.red}Error:${c.reset} search requires a query argument.`);
                process.exit(1);
            }
            output = docsSearch(docs, positional, maxResults);
            break;
        case "nav":
        case "navigate":
        case "n":
            output = docsNavigate(docs, positional || undefined);
            break;
        case "xref":
        case "x":
            if (!positional) {
                console.error(`${c.red}Error:${c.reset} xref requires a concept argument.`);
                process.exit(1);
            }
            output = docsXref(docs, positional);
            break;
        case "glossary":
        case "g":
            if (!positional) {
                console.error(`${c.red}Error:${c.reset} glossary requires a term argument.`);
                process.exit(1);
            }
            output = docsGlossary(docs, positional);
            break;
        case "api":
        case "a":
            if (!positional) {
                console.error(`${c.red}Error:${c.reset} api requires a symbol argument.`);
                process.exit(1);
            }
            output = docsApi(docs, positional);
            break;
        case "howto":
        case "h":
            if (!positional) {
                console.error(`${c.red}Error:${c.reset} howto requires a task description.`);
                process.exit(1);
            }
            output = docsHowto(docs, positional);
            break;
        default:
            console.error(`${c.red}Unknown command:${c.reset} ${command}`);
            printUsage();
            process.exit(1);
    }
    console.log(colorize(output));
}
main();
//# sourceMappingURL=cli.js.map