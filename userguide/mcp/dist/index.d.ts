#!/usr/bin/env node
interface DocEntry {
    filename: string;
    filepath: string;
    content: string;
    lines: string[];
}
export declare function loadDocs(docsDir?: string): DocEntry[];
export declare function docsSearch(docs: DocEntry[], query: string, maxResults?: number): string;
export declare function docsNavigate(docs: DocEntry[], chapter?: string): string;
export declare function docsXref(docs: DocEntry[], concept: string): string;
export declare function docsGlossary(docs: DocEntry[], term: string): string;
export declare function docsApi(docs: DocEntry[], symbol: string): string;
export declare function docsHowto(docs: DocEntry[], task: string): string;
export {};
//# sourceMappingURL=index.d.ts.map