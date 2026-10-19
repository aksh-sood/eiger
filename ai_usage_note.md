# AI Usage Note

I used Claude Code, an AI coding assistant, throughout this exercise. I had no prior AI-security background, so I used it to explain concepts I didn't know, such as direct vs. indirect prompt injection and fail-closed design. I also used it to navigate the Eiger codebase, help trace the root cause, draft the code changes and tests, diagnose debugging problems (a 401 from the judge API, a stale validator session) and organise and edit these write-ups.

I directed the work and made the final call on each change. When I asked what covered the stretch goal, it turned out to rely only on the existing flag, so I had a real fix built. I chose to build independent fixes rather than just enable `SEC_RAG_PROVENANCE`. When Claude pointed out that my early tests used direct question injection, which can't satisfy the M3 validator on its own, I switched to the stored-note attack. I ran every command, read the outputs and checked claims myself, for example by querying the audit table to confirm whether an attack had fired.

Nothing AI-generated went in unreviewed: I read and tested every code change before treating it as final, and I can explain each one.
