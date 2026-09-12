# ZimaScope frontend

Local-first observability UI for the ZimaScope agent, styled after Apple's
design language: solid canvases, materials only where chrome floats over
content, system typography, and critically damped motion that respects
`prefers-reduced-motion`, `prefers-reduced-transparency` and
`prefers-contrast`.

## Stack

- **React 19 + Vite** SPA (no SSR), routed with **react-router** in hash mode
  so `#/flows?ip=…` deep links keep working.
- **Tailwind CSS v4** (CSS-first `@theme` tokens in `src/index.css`) with
  **shadcn/ui** components in `src/components/ui/` (Radix primitives).
- **TanStack Query** for REST caching; the SSE live tick is bridged into React
  with `useSyncExternalStore` (`src/hooks/use-tick.ts`).
- **Recharts** for the timeline and sparklines, **motion** for springs,
  **lucide-react** for icons, **sonner** for toasts.

## Structure

- `src/api.ts` — typed client for the full API surface (status, flows,
  endpoints, domains, settings, exports, history, SSE stream).
- `src/store.ts` — data facade (real agent only, no demo data) and the SSE tick subscription.
- `src/types.ts` — wire types mirroring the agent's DTOs.
- `src/hooks/` — TanStack Query bindings, theme (system/light/dark), topbar
  and detail-panel state.
- `src/components/` — shell (sidebar, topbar, detail sheet) and composed
  pieces (flow table, charts, segmented control, rank lists).
- `src/views/` — the five routed views.

## Views

- **Overview** — live inbound/outbound rates with sparklines, a traffic
  timeline, top domains/endpoints/regions/networks, and recent flows.
- **Flows** — search, direction/state/evidence filters, pagination and a
  detail panel. Live ticks patch rows in place; interacting with the list
  pauses live re-sorting (PRD 9.2).
- **Endpoints** — remote peers ranked by bytes with ports and associated
  domains in the detail panel.
- **Domains** — associated domains with DNS / TLS SNI / HTTP Host evidence
  and resolved addresses.
- **Settings** — collection, domain observation, history retention,
  resource limits, export and clear-history.

Deep links: `#/flows?ip=…`, `#/flows?domain=…`, `#/flows?asn=…`,
`#/flows?country=…`, plus `?flow=` / `?address=` / `?domain=` to open a
detail panel on load. Press `/` anywhere to jump to Flow search.

## Running against a real agent

```sh
# terminal 1: agent with a dev-only local TCP listener (never set in production)
ZIMASCOPE_API_TCP=127.0.0.1:8787 ZIMASCOPE_DATABASE=/tmp/zimascope.db \
  ./target/debug/zimascope-agent

# terminal 2
npm install
npm run dev
```

The Vite dev proxy forwards `/v1` to `ZIMASCOPE_API_URL` (default
`http://127.0.0.1:8787`). There is no demo data: an unreachable agent shows an
explicit **Agent unavailable** state on each view instead of fabricated
observations.

`npm run build` type-checks (`tsc --noEmit`) and bundles to `dist/`.
