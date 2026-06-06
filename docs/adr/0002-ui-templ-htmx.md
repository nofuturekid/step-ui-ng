# 0002. Server-rendered UI with Templ + htmx (no React/Node)

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The previous app used Next.js/React purely as a static SPA (no SSR features used),
paying the full Node toolchain cost for a CRUD-style admin UI.

## Decision Drivers
- Eliminate the second toolchain (Node) from build/CI/image.
- Match the interaction model (forms, tables, actions).
- Keep a single language and a single static binary.

## Considered Options
- Templ + htmx (server-rendered Go)
- React via Vite, embedded with go:embed
- Keep Next.js static export

## Decision Outcome
Chosen option: "Templ + htmx", because it removes Node entirely, fits the admin/CRUD
nature of the app, and yields one self-contained binary.

### Consequences
- Good, because no Node, type-safe templates, simple partial updates.
- Bad, because rich client-side interactions are more awkward than in React.
- Neutral, htmx + a small CSS (Pico.css) are vendored and embedded.

## More Information
If very rich client UX is later required, revisit with an embedded Vite+React SPA.
