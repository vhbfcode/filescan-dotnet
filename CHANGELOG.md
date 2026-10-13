# Changelog

## 0.3.0

> **SECURITY — 0.2.0 (and earlier) is vulnerable to a denial of service of the host process.** A crafted PDF
> makes `PdfDocument.Open` (PdfPig 0.1.16) recurse without limit and overflow the stack (exit code
> `0xC00000FD`). A .NET stack overflow cannot be caught: the whole process dies, and it only takes an
> upload. Measured: a 2-node cycle in `/Names /Dests /Kids`; a `/Dests` chain of 5k+ nodes with no cycle (2k
> survives); a page tree nested 20k levels deep (5k survives); a dictionary value that is an indirect-reference
> alias pointing to itself (`/Info << /Title 31 0 R >>`, `31 0 obj 31 0 R`) or a chain of 50k aliases. A
> `/Dests` tree with a repeated or shared child does not crash but needs 2^n steps (CPU hang). Alias
> cycles/chains reached through `/Root`, `/Pages` or `/Info` itself, and array-wrapped aliases, are handled
> by PdfPig (it throws) — the guard refuses them anyway. 0.3.0 adds a
> guard that runs **before** `Open` (see below). Upgrade as soon as it is published. PdfPig stays at
> 0.1.16 (no alpha); the guard is kept even if a later stable PdfPig fixes these paths.
>
> **0.3.0 is an INTERMEDIATE release and its guard is best effort, not a defence.** It blocks the trivial
> attack and the structures found so far, but a file crafted on purpose may still find a path that PdfPig walks
> and the guard does not model, and **can still crash the hosting process**. **0.4.0 will isolate
> `PdfDocument.Open` in a separate process** (crash or timeout ⇒ `NotInspected`); the guard then stays as a
> cheap pre-filter. **Until 0.4.0, restrict who can upload** (authenticated users only, rate limits, size limits)
> and run the scanner somewhere a restart is cheap.

Broader PDF coverage, still fail-closed: whatever is not inspected is still `NotInspected`.
Motivated by real-world insurer/ERP/browser-printed PDFs that 0.2.0 refused.

- **Chained stream filters.** `FlateDecode`, `ASCII85Decode` and `ASCIIHexDecode` can be chained
  (up to 4 filters). Every step is charged to the per-stream and aggregate expansion budgets, the
  ASCII85 `z` shortcut (1 -> 4 bytes) is bounded before decoding, and `/DecodeParms` arrays are
  honoured per filter. LZW, RunLength and image codecs inside a chain remain unsupported.
- **PNG predictors.** `/FlateDecode` with `/Predictor 10-15` (Acrobat/iText/Word xref streams and
  images) is decoded after the budgeted inflation (the predictor never expands). The TIFF predictor
  (2), malformed/indirect `/DecodeParms`, non-integer or out-of-range parameters, a data length that
  is not a multiple of the row stride and an invalid row-filter byte still fail closed.
- **Image streams.** A `/Subtype /Image` stream that is not an attachment is no longer decoded (and
  no longer makes the file `NotInspected` for DCT/JPX/JBIG2/CCITT, nor spends the 16 MB / 64 MB
  budget on a scanned page): image bytes are never interpreted as PDF syntax. The same codec on a
  non-image stream, or an image stream reachable as an embedded file, still fails closed.
- **Final `%%EOF` is now checked against the last `startxref` (fix, also affects 0.2.0).** After the
  LAST `startxref` only `<offset>`, EOL, `%%EOF` and whitespace are accepted. The 0.2.0 check only
  looked at the file's last bytes, so `PDF + <script>...</script>\n%%EOF` (a second `%%EOF`) or loose
  objects redefining the catalog were reported `Clean`. Legitimate incremental updates (each with its
  own xref/startxref/`%%EOF`) are unaffected. Trailing HTML/text is deliberately NOT tolerated.
- **Byte coverage (fix, also affects 0.2.0).** Checking only the bytes after the last `startxref` was
  not enough: `PDF + garbage + a fake startxref/%%EOF` (or a fake empty xref section with a valid
  `/Prev`, or "linearized" layouts with text between objects) still ended `Clean`. Now the whole file is
  walked once, end to end: every non-whitespace, non-comment byte must belong to an indirect object
  (`n g obj ... endobj`), an `xref` table + `trailer`, or a `startxref` line. Any gap (HTML, text,
  binary, a stray keyword) is `NotInspected`. A well-formed object that no xref section of the `/Prev`
  chain lists (and that is not an xref stream) is scanned for action names, and refused if it carries a
  stream. Cost is linear (stream bodies are skipped by `/Length`/`endstream`); free (`f`) entries,
  object streams, incremental updates and linearized files are unaffected.
- **Pre-Open guard (fix, also affects 0.2.0 — DoS).** Fail-closed by construction: before calling
  `PdfDocument.Open`, every object is read with **PdfPig's own public tokenizers** (`CoreTokenScanner`), so
  `#xx` escapes in names (`/K#69ds`), comments, indirect references and dictionaries have exactly PdfPig's
  semantics; object streams are read with the same algorithm as PdfPig's `ParseObjectStream`. A stream is an
  object stream if it has `/N` + `/First` (any `/Type`, or none) **or** is the target of a type-2 xref entry;
  an undecodable one refuses the file. The xref must be consistent with what was read (last `startxref`,
  `/Prev`, `/XRefStm` and every in-use entry must point at a top-level object or section — so a "hidden"
  object inside stream data cannot be reached). The file is refused (`NotInspected`) on: a cycle or a chain
  longer than 32 in indirect-reference aliases; a cycle, shared node, repeated element or more than 64 levels
  in the `/Kids` graph (name trees, page tree, form fields); any exceeded cap (alias fan-out, edges,
  tokens) — caps refuse, they never truncate. PDFs with `/Encrypt` are refused without being opened. The guard
  unions **all** definitions of an object (it cannot know which one PdfPig will use), which is the safe side.
  Cost is linear (memoised alias resolution, early detection of shared nodes, cancellation checked in the loops).
  Also refused: `/Kids` that reaches children through **direct dictionaries/arrays** (PdfPig descends into
  them too); and a **hidden object** found by a raw-bytes rule that depends on whether PdfPig can be made to
  brute-force the file. PdfPig scans the raw bytes of the whole file for `N g obj` — inside strings, comments and
  stream data, filtered or not — through three mechanisms (`XrefBruteForcer`, `BruteForceSearcher`, and the
  token-based search), and accepts variations (any whitespace including NUL, any amount of it, leading zeros, a
  number glued to the previous byte, `obj` in any case and without a boundary after it); the guard repeats that
  scan with the same variations. **Once brute force runs, the offsets it finds take precedence over the xref for
  every object, in-use ones included** (`ObjectLocationProvider.TryGetOffset` consults them first, and
  `BruteForceSearcher` keeps the last occurrence). So the guard treats brute force as *reachable* when any of these
  holds, and fails closed when it cannot tell: a reference (also `/Length`, trailer, object-stream member) to a
  number that is not an in-use xref entry; any generation other than 0 in a reference, xref entry or object (PdfPig
  matches number **and** generation; pairs are not modelled); a type-1 xref entry whose offset leads to a
  different object; an object-stream target that is not an in-use entry; a cyclic `/Prev` chain or a section
  offset that is not exactly a section start (PdfPig then discards the whole xref and brute-forces everything);
  an xref section **outside the chain** (last `startxref` -> `/Prev` / `/XRefStm`) — PdfPig ignores it, so only the
  entries of the sections the chain reaches count as "in use", and the mere existence of an orphan section is a
  reachable trigger.
  When reachable, **any hidden occurrence of a referenced number (or of an object-stream container) is refused**;
  when not reachable, only a hidden occurrence of a referenced number that is not an in-use entry is refused, and
  a reference to a missing or free object with no hidden occurrence is *not* refused (PdfPig resolves it to
  null), nor is the text `7 0 obj` inside a stream that nobody references.
  **Known limitations (false positives, by design):** an xref whose offsets are even slightly wrong is refused
  (fail-closed; PdfPig would brute-force the file); a legitimate incremental update that *moves* a node of the
  `/Kids` tree (e.g. restructures the page tree) is refused as a "shared node" because old and new definitions
  are both considered; a file with a generation other than 0 (e.g. an object revised with generation 1) **and** the
  text `N 0 obj` inside an unfiltered stream (typically an uncompressed PDF attached as an embedded file whose
  object numbers are referenced by the outer file) is refused, because the non-zero generation makes brute force
  reachable; a comment *inside* an indirect reference (`2 %c` + newline + `0 R`) is refused as a gap.
  The guard is a **best-effort pre-filter**, not a proof: a crafted file can still crash the process (stack
  overflow in `PdfDocument.Open` is uncatchable). Brute-force triggers the guard does not model (for example an
  object that PdfPig's scanner cannot read at its xref offset although the guard's grammar accepted it) are
  not excluded (known residual: the token-based mechanism, `TryBruteForceFileToFindReference`, is only partly
  modelled — it keeps the last definition of every top-level object it reads, and the guard unions all definitions).
  Isolating `Open` in a separate process is planned for 0.4.0;
  until then, restrict who can upload.
- **Bounded recursion (fix, also affects 0.2.0).** The `/EmbeddedFiles` name-tree walk (`/Kids`) was only
  bounded against cycles: a long acyclic chain of nodes overflowed the stack and killed the process.
  It is now capped at 64 levels (`NotInspected`), like every other token walk; the byte-coverage scanner
  has the same cap.
- **Any dictionary with `/EF` is a FileSpec.** The optional `/Type /Filespec` is no longer required
  (e.g. `/GoToE`); a malformed `/EF` fails closed.
- **PDF object limit.** New `MaxPdfObjects` (default 50,000) replaces `MaxContainerEntries` for PDF
  objects (the old 1,024 default refused ordinary multi-hundred-KB PDFs). `MaxContainerEntries` still
  governs OOXML zip entries. Streams are no longer counted twice.
- **Binary streams are not "unterminated strings".** TrueType/CFF font programs (`/FontFile*`),
  `/CIDToGIDMap` and ICC profiles (`[/ICCBased n 0 R]`) are identified by *who references them*;
  their stray `(`/`<` no longer makes the stream "incomplete". The lexical name scan still runs on
  them, but it is best effort there (a stray `(` hides what follows it); that is acceptable because
  nothing interprets font/ICC bytes as actions. An `ObjStm` is never treated as binary.
- Encrypted PDFs are unchanged: still `NotInspected`.
