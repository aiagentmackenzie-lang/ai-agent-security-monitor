# Continue AI Agent Security Monitor

**Location:** `/Users/main/Security Apps/AI Agent Security Monitor/`

**Status:** Phase 1 ✅ Phase 2 ✅ Phase 3 ⏳ NOT STARTED

**Start:**
```bash
cd "/Users/main/Security Apps/AI Agent Security Monitor"
docker compose up -d postgres
npm run dev
```

**Verify:** `curl http://localhost:8000/health`

**Static check:** `npm run typecheck && npm run lint && npm test` (must pass before declaring work done)

**Next:** Phase 3 - Compliance Evidence Collector
- Read `IMPLEMENTATION_PLAN.md` Section "Phase 3" first
- Start with Chunk 3.1: Compliance Evidence Mapping
- Map agent events to regulations, store in `compliance_records` table
- Track controls satisfied per agent per regulation

**Key files:** `src/api/server.ts`, `src/compliance/mapper.ts`, `src/db/init.ts`