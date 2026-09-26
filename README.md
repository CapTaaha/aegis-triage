# Aegis Triage

🚧 **Active Development**

Aegis Triage is an interactive code-analysis and triage dashboard built with TypeScript and React. It helps you explore call graphs, inspect functions, manage targets, and run lightweight triage workflows from a feature-rich web UI.

> UI-first tool for codebase triage, visual analysis, and lightweight automation.

---

## Quick start

These commands get the app running locally (assumes pnpm is installed):

```bash
# clone and enter
git clone https://github.com/CapTaaha/aegis-triage.git
cd aegis-triage

# install dependencies and run the dev server
pnpm install
pnpm dev

# build for production
pnpm build
pnpm preview
```

Open the dev server at the URL Vite prints (usually http://localhost:5173).

Notes:
- This repo uses pnpm workspaces (see pnpm-workspace.yaml) and TailwindCSS for styling.
- The repository contains vercel.json and nitro.config.ts for server/runtime deployment hints.

---

## What you'll find here (high level)

- src/pages/Index.tsx — main dashboard that composes the UI and feature pages.
- src/components/ — feature components (TriageDashboard, TargetManager, CallGraphExplorer, SiteInventory, etc.).
- src/components/ui/ — UI primitives and reusable controls (sidebar, table, dialogs, toasts).
- src/data/analysis-data.ts — example/sample analysis data used by the UI.
- server/ — lightweight server routes and helpers (server/routes, server/utils) for API endpoints.
- AI_RULES.md — project-specific AI guidance and rules.

---

## Selected features

- Triage dashboard with rich tables, filters and verification flows (see src/components/TriageDashboard.tsx).
- Target management UI (src/components/TargetManager.tsx) to register, view and triage targets.
- Call graph explorer and function details panel for navigating code relationships (CallGraphExplorer, FunctionDetailsPanel).
- LLM configurator UI (LLMConfigurator.tsx) for experimenting with model settings.
- A comprehensive set of UI primitives in src/components/ui used across the app.

---

## Project structure

```
src/
  main.tsx                 # React bootstrap
  globals.css, App.css     # Global styles
  pages/
    Index.tsx              # Main app page (dashboard & routes)
    NotFound.tsx           # 404
  components/              # Feature UIs
    TriageDashboard.tsx
    TargetManager.tsx
    CallGraphExplorer.tsx
    FunctionDetailsPanel.tsx
    LLMConfigurator.tsx
    SiteInventory.tsx
    VerificationDialog.tsx
    ui/                    # UI primitives (table, sidebar, dialog, toasts, etc.)
  data/
    analysis-data.ts       # Sample/fixture analysis data
  hooks/                   # Small custom hooks
  lib/                     # Utilities

server/
  routes/                  # API route handlers
  utils/                   # Server-side helpers

package.json
pnpm-workspace.yaml
pnpm-lock.yaml
vite.config.ts
tailwind.config.ts
vercel.json
AI_RULES.md
```

---

## Development notes & recommendations

- Styling: The project uses Tailwind; run `pnpm dev` to see hot-reload styling iterations.
- UI primitives in src/components/ui are intentionally comprehensive; consider extracting them into a workspace package if you plan to reuse across projects.
- If you plan to deploy, Vercel is a first-class target (vercel.json) — ensure any serverless endpoints in server/ meet Vercel's function constraints.

---

## Data & AI guidance

- analysis-data.ts is sample data used for demonstration. If you add real analysis results, be mindful of sensitive data.
- AI rules and usage guidance live in AI_RULES.md — read that before using any automated/AI-driven features.

---

## Contributing

1. Open an issue to propose larger changes or features.
2. For code changes, create a topic branch, make your changes, and open a PR against the repository default branch.
3. Keep changes small and focused. Describe intent and include screenshots for UI changes.

---

## Contact

Maintainer: @CapTaaha — raise issues or PRs on GitHub.
