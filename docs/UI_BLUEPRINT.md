# PacketDPI Optional UI Blueprint

The UI is an optional companion dashboard for PacketDPI. The CLI remains the source of truth because PacketDPI is a systems/security tool. The UI exists to make results easier to present in a portfolio, demo, interview, or security review.

## Product Position

PacketDPI UI should feel like a focused security operations console:

- Dense enough for technical users.
- Clear enough for a recruiter or reviewer to understand in one minute.
- No marketing hero, decorative landing page, or generic card wall.
- No live network capture. It visualizes offline PCAP analysis and filtering results.

## Visual Direction

- Palette: graphite background, restrained panel surfaces, off-white text, teal success, amber warning, red drop accents.
- Geometry: crisp 1px borders, 8px max radius, compact spacing, strong table/list anatomy.
- Typography: system sans-serif, small UI labels, clear metric numbers, no oversized hero type.
- Motion: subtle hover/selection only. The product should feel calm and precise.
- Imagery: no stock art. The interface itself is the visual asset.

## Panel Blueprint

### 1. Left Navigation Rail

Purpose: make the UI feel like a real product shell.

Contents:

- PacketDPI mark and version.
- Navigation entries: Overview, Applications, Domains, Rules, Timeline, Export.
- CI status indicator.

Behavior:

- Clicking nav entries scrolls to the related panel.
- Active section is highlighted.

### 2. Top Command Bar

Purpose: connect the UI back to the CLI workflow.

Contents:

- Loaded capture name: `test_dpi.pcap`.
- Analysis status: parsed, filtered, CI verified.
- Primary actions: Export JSON, Copy CLI, Open docs.

Behavior:

- Copy CLI writes the recommended commands to clipboard.
- Export JSON downloads the current dashboard data.

### 3. Overview Metrics

Purpose: answer "what happened?" instantly.

Metrics:

- Packets parsed.
- Parse errors.
- TLS SNI hits.
- DNS query hits.
- Dropped packets.
- Forwarded packets.

Behavior:

- Hover states show compact descriptions.
- Metrics use semantic accents: success for parsed, red for dropped, amber for warnings.

### 4. Application Distribution

Purpose: show classification quality and traffic mix.

Contents:

- Horizontal bars for app categories.
- Counts and percentages.
- Unknown traffic remains visible instead of hidden.

Behavior:

- Selecting an app filters the domain table and inspector context.

### 5. Top Domains Table

Purpose: provide evidence-level review.

Columns:

- Domain.
- App classification.
- Evidence source: SNI, HTTP Host, DNS, or port fallback.
- Packet count.
- Rule action.

Behavior:

- Search domains.
- Select a row to populate the inspector.
- Rule action is color-coded.

### 6. Rule Impact Panel

Purpose: show filtering value.

Contents:

- Rules loaded from `demo/rules.txt`.
- Dropped packet count by reason.
- Forwarded vs dropped ratio.

Behavior:

- Toggle between "demo rules" and "no rules" simulated states.

### 7. Packet Timeline

Purpose: make the capture feel inspectable without building a full Wireshark clone.

Contents:

- Compact timeline bins.
- Color bands for HTTPS, DNS, dropped, and unknown packets.

Behavior:

- Hover/focus reveals bin details.

### 8. Right Inspector

Purpose: explain the selected signal.

Contents:

- Selected domain/app.
- Evidence chain.
- Matched rule.
- Recommended CLI command.
- Notes on limitations.

Behavior:

- Updates when a domain row or app bar is selected.

### 9. Export and Handoff Panel

Purpose: support portfolio presentation.

Contents:

- Commands to reproduce analysis.
- Files produced by the CLI.
- Links to architecture, ethics, demo, benchmark docs.

Behavior:

- Copy individual commands.

## Data Contract

The UI reads a JSON snapshot:

```json
{
  "capture": "test_dpi.pcap",
  "summary": {},
  "applications": [],
  "domains": [],
  "rules": [],
  "timeline": []
}
```

For now the dashboard ships with `ui/sample-data.json`, based on the bundled demo PCAP. Later the CLI can add `--json` or `--html` export without changing the UI shell.

## Success Criteria

- Opens locally without a server.
- Looks intentional and modern at desktop and mobile widths.
- Explains the CLI output better than terminal text alone.
- Does not pretend to capture live traffic.
- Does not dilute the C++ backend; it presents the backend professionally.
