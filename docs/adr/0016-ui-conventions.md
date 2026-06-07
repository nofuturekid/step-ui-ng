# 0016. UI conventions: design tokens, popover component, dark mode, per-page width

- Status: accepted
- Date: 2026-06-07
- Deciders: maintainer

## Context and Problem Statement

The UI grew quickly (logo, centered topbar, Settings dropdown, responsive nav) and
accumulated duplication and magic numbers in `internal/app/static/app.css`: the
Settings dropdown and the new mobile nav panel shared identical chrome, `8px`/`6px`
radii and one box-shadow were repeated, and several colors were hardcoded outside the
existing CSS variables. Before adding more UI we wanted a small, deliberate
foundation so future changes stay consistent — without adopting heavy tooling.

## Decision Drivers

- Consistency as the UI keeps changing; one source of truth for shape/elevation/color.
- No Node/React, no CSS build step or preprocessor (project constraint).
- Keep it minimal — avoid a full design system / utility framework (YAGNI).

## Considered Options

- A full design system (spacing scale, component library, tokens for everything).
- Ad-hoc per-change CSS (status quo).
- A lightweight token + component layer in plain CSS.

## Decision Outcome

Chosen option: "lightweight token + component layer in plain CSS". Concretely:

- **Design tokens** in `:root`: surfaces/tints (`--input-bg`, `--surface-2`,
  `--error-bg/-border`, `--info-bg/-border`), shape/elevation (`--radius`,
  `--radius-sm`, `--shadow`), and layout widths (`--content-width`,
  `--content-width-wide`). Components reference tokens instead of literals.
- **`.popover` component**: shared floating-surface chrome (card bg, border, radius,
  shadow). The Settings dropdown and the mobile nav panel both use it; each keeps only
  its own layout/positioning.
- **Dark mode** via `@media (prefers-color-scheme: dark)` that overrides only the
  `:root` tokens. Because every component reads tokens, no per-component dark rules are
  needed. Follows the OS setting (no manual toggle for now).
- **Per-page content width**: `pageData.Wide` adds `class="wide"` to `<main>`;
  data-heavy pages (inventory, audit) opt into `--content-width-wide`, forms/detail
  stay at `--content-width`.
- **JS-free responsive nav**: a `<details class="navmenu">` hamburger whose content
  (`.navwrap`) is a **sibling** (not a child) so a closed `<details>` never hides the
  desktop nav; the panel toggles via `.navmenu[open] ~ .navwrap`. One breakpoint
  (`max-width: 47.99em`); desktop layout is unchanged.

### Consequences

- Good: one place to change radius/shadow/width/colors; dark mode is essentially free;
  the popover chrome is defined once.
- Good: stays plain CSS — no toolchain, fits the no-Node ethos; `<details>` keeps the
  nav and dropdowns JS-free and keyboard-accessible.
- Neutral: CSS custom properties can't be used inside `@media` queries, so the single
  responsive breakpoint is a documented literal, not a token.
- Bad: a modest token vocabulary to keep in mind; not a complete design system, so some
  spacing values remain literal by choice.

## More Information

Verified across desktop / narrow (collapsed + open) / dark via a static preview
harness. Builds on the topbar/logo/centering work; see `app.css` and `templates.templ`.
