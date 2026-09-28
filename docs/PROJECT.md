# Project Architecture & Refactoring Plan: NetOps AI Agent

## Architecture Overview

NetOps AI Agent is a full-stack network topology diagnosis and management platform with an Express backend, SQLite persistence, RAG knowledge base, and React (Vite + Ant Design) frontend.

The deep refactoring modularizes the backend into single-responsibility DB files and Express domain routers, enforces TypeScript generic safety over SQLite calls without `as any` casts, removes top-level initialization side effects, decouples monolithic frontend components into custom hooks and sub-components, and centralizes error handling.

```
e:\netops-ai-agent\
├── server.ts                             # Application entry point & Express bootstrap
├── src/
│   ├── types.ts                          # Unified type system & DB row schemas
│   ├── db/                               # Modular DB layer
│   │   ├── client.ts                     # DatabaseSync instance & lifecycle
│   │   ├── generic.ts                    # Generic type-safe query helpers (queryOne, queryAll, execute)
│   │   ├── schema.ts                     # DDL table creation & initDatabase()
│   │   ├── seed.ts                       # Seeding default data
│   │   ├── queries/                      # Domain-specific SQL queries
│   │   │   ├── devices.ts
│   │   │   ├── topology.ts
│   │   │   ├── providers.ts
│   │   │   └── kb.ts
│   │   └── index.ts                      # DB facade re-exporting client, schema, seed, queries, and types
│   ├── routes/                           # Modular Express Routers
│   │   ├── index.ts                      # Aggregator mounting domain routers under /api
│   │   ├── topology.ts                   # /api/topology, /api/topology/fetch, /api/device/*
│   │   ├── kb.ts                         # /api/kb/upload, /api/kb/crawl, /api/kb/documents/*
│   │   ├── models.ts                     # /api/models/providers, /api/models/config, /api/models/test-connection
│   │   └── agent.ts                      # /api/agent/chat
│   ├── middleware/
│   │   ├── asyncHandler.ts               # Async route wrapper for Express 4.x
│   │   └── errorMiddleware.ts            # Centralized global error handling middleware
│   ├── utils/
│   │   └── errors.ts                     # Custom AppError classes
│   ├── hooks/                            # Decoupled React custom hooks
│   │   ├── useTopology.ts
│   │   ├── useAuditLogs.ts
│   │   ├── useSystemSettings.ts
│   │   ├── useModalState.ts
│   │   └── useModelMarketplace.ts
│   ├── components/
│   │   ├── layout/                       # App layout sub-components
│   │   │   ├── HeaderBar.tsx
│   │   │   ├── FooterBar.tsx
│   │   │   └── SidebarMenu.tsx
│   │   ├── modals/                       # App modal sub-components
│   │   │   ├── DiagnosticReportModal.tsx
│   │   │   └── SettingsModal.tsx
│   │   ├── marketplace/                  # ModelMarketplaceModal sub-components
│   │   │   ├── MarketplaceHeader.tsx
│   │   │   ├── ProviderCard.tsx
│   │   │   └── ProviderConfigModal.tsx
│   │   └── ModelMarketplaceModal.tsx     # Clean refactored marketplace modal
│   └── App.tsx                           # Clean refactored main application component
```

---

## Feature Inventory & Requirement Mapping

| # | Feature | Description | Requirement | Assigned Milestone | Source |
|---|---------|-------------|-------------|--------------------|--------|
| 1 | Centralized Types & Schema | Consolidate DB row schemas and domain models in `src/types.ts`, eliminate interface duplication | R1 | M1 | Survey 1 |
| 2 | Generic SQLite Layer | Implement `queryOne<T>`, `queryAll<T>`, `execute` in `src/db/generic.ts`, remove all `as any` casts | R1 | M1 | Survey 1 |
| 3 | Modular DB Split | Split `src/db/index.ts` into `client.ts`, `schema.ts`, `seed.ts`, `queries/*.ts` | R2 | M2 | Survey 1 |
| 4 | Side-Effect Elimination | Remove top-level `initDatabase()`/`seedSOPDocuments()`, implement `ensureInitialized()` guard & explicit startup | R2 | M2 | Survey 1 |
| 5 | Express Domain Routers | Split `server.ts` routes into `src/routes/` (`topology.ts`, `kb.ts`, `models.ts`, `agent.ts`, `index.ts`) | R3 | M3 | Survey 2 |
| 6 | Global Error Middleware | Implement `AppError`, `asyncHandler`, `errorMiddleware` catching global exceptions with standard JSON responses | R3 | M3 | Survey 2 |
| 7 | App.tsx Decoupling | Extract `useTopology`, `useAuditLogs`, `useSystemSettings`, `useModalState` and layout/modal components | R4 | M4 | Survey 3 |
| 8 | Marketplace Decoupling | Extract `initialProviders.ts`, `useModelMarketplace`, and sub-components from `ModelMarketplaceModal.tsx` | R4 | M4 | Survey 3 |
| 9 | Verification & Regression | Run `npx tsc --noEmit`, `npx tsx test_backend.ts`, `npx tsx run_m3_tests.ts` to ensure 100% pass | Criteria 1,2,3 | M5 | Survey 3 |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | TypeScript Safety & Unified Types | Consolidate `src/types.ts`, introduce `src/db/generic.ts`, eliminate all `as any` in DB calls | None | DONE |
| M2 | DB Monolith Split & Side-Effect Removal | Modularize `src/db/` into single-responsibility modules, remove top-level side effects, add lazy guard | M1 | DONE |
| M3 | Express Router Architecture & Global Error Middleware | Create `src/routes/` domain routers, error classes, `asyncHandler`, `errorMiddleware`, refactor `server.ts` | M2 | DONE |
| M4 | Frontend Component & Custom Hook Decoupling | Refactor `App.tsx` and `ModelMarketplaceModal.tsx` into custom hooks and modular sub-components | M1 | DONE |
| M5 | E2E Integration & Verification | Run strict `tsc`, `test_backend.ts`, `run_m3_tests.ts`, and server startup verification | M1, M2, M3, M4 | DONE |

---

## Interface Contracts

### 1. Database Generic Interface (`src/db/generic.ts`)
```ts
export type QueryParam = string | number | boolean | null | undefined;
export function queryOne<T>(sql: string, ...params: QueryParam[]): T | null;
export function queryAll<T>(sql: string, ...params: QueryParam[]): T[];
export function execute(sql: string, ...params: QueryParam[]): { changes: number | bigint; lastInsertRowid: number | bigint };
```

### 2. Express Global Error Interface (`src/middleware/errorMiddleware.ts`)
Standard JSON error response format:
```json
{
  "error": "Error description string",
  "message": "Error description string",
  "success": false
}
```

### 3. Modular Router Endpoints (`src/routes/`)
- `topology.ts`: `GET /api/topology`, `POST /api/topology/fetch`, `GET /api/device/:id`, `POST /api/device/:id/diagnose`
- `kb.ts`: `POST /api/kb/upload`, `POST /api/kb/crawl`, `GET /api/kb/documents`, `DELETE /api/kb/documents/:id`
- `models.ts`: `GET /api/models/providers`, `POST /api/models/config`, `POST /api/models/test-connection`
- `agent.ts`: `POST /api/agent/chat`

---

## Code Layout

- `src/types.ts`: Domain models & SQLite row definitions.
- `src/db/`: Modular SQLite layer (`client.ts`, `generic.ts`, `schema.ts`, `seed.ts`, `queries/`, `index.ts`).
- `src/routes/`: Express domain routers (`index.ts`, `topology.ts`, `kb.ts`, `models.ts`, `agent.ts`).
- `src/middleware/`: Express middleware (`asyncHandler.ts`, `errorMiddleware.ts`).
- `src/utils/`: Custom errors (`errors.ts`).
- `src/hooks/`: React custom hooks (`useTopology.ts`, `useAuditLogs.ts`, `useSystemSettings.ts`, `useModalState.ts`, `useModelMarketplace.ts`).
- `src/components/`: Sub-components by domain (`layout/`, `modals/`, `marketplace/`).
- `server.ts`: Application bootstrap.
