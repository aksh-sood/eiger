from halcyon import audit, canary, guards
from halcyon import jev as jev_screen
from halcyon.config import Settings
from halcyon.jev import Jev
from halcyon.kb import Chunk, KnowledgeBase
from halcyon.llm import LLM
from halcyon.question_judge import jev_judge_question, judge_question
from halcyon.store import Store

REPLY_BLOCKED_MESSAGE = "Sorry, I can't share that answer. Please rephrase your question."


def add_note(kb: KnowledgeBase, jev: Jev | None, store: Store, settings: Settings,
             session_id: str, text: str, module: str = "m3") -> bool:
    # JEV layer 1: screen a user note before it is ever stored.
    if settings.sec_rag_jev_notes and jev_screen.flagged(
            jev, settings.sec_rag_jev_threshold,
            jev_screen.NOTE_QUESTION, jev_screen.NOTE_CRITERIA, text):
        audit.record(store, session_id, module, audit.NOTE_REJECTED, session_id, {"by": "jev"})
        return False
    kb.add(text, "user", owner_session=session_id)
    return True


def answer(kb: KnowledgeBase, llm: LLM, store: Store, settings: Settings,
           session_id: str, query: str, module: str = "m3",
           jev: Jev | None = None) -> tuple[str, list[Chunk]]:
    if settings.sec_rag_question_judge:
        # Exactly one model judges the question. JEV layer 3 is the "jev" backend.
        backend = settings.sec_rag_question_judge_backend
        if backend == "jev":
            verdict = jev_judge_question(jev, query, settings.sec_rag_jev_threshold)
        else:
            verdict = judge_question(llm, query)
        if not verdict.allowed:
            audit.record(store, session_id, module, audit.QUESTION_BLOCKED, session_id,
                         {"by": backend})
            return verdict.text, []
        query = verdict.text  # the refined (or label-stripped) question from here on
    chunks = kb.retrieve(query, session_id, k=3)
    if settings.sec_rag_provenance:
        visible = [c for c in chunks
                   if c.access != "restricted" or c.owner_session == session_id]
    else:
        visible = chunks
    for c in visible:
        if c.access == "restricted" and c.owner_session != session_id:
            audit.record(store, session_id, module, audit.RESTRICTED_DOC_RETRIEVED,
                         session_id, {"chunk": c.id})
    if settings.sec_rag_jev_chunks:
        # JEV layer 2: drop untrusted chunks that read as instructions. Trusted chunks
        # are never sent to JEV. Same fail-closed split as guards: only "trusted" is trusted.
        kept = []
        for c in visible:
            if c.provenance != "trusted" and jev_screen.flagged(
                    jev, settings.sec_rag_jev_threshold,
                    jev_screen.NOTE_QUESTION, jev_screen.NOTE_CRITERIA, c.text):
                audit.record(store, session_id, module, audit.CHUNK_DROPPED, session_id,
                             {"chunk": c.id, "by": "jev"})
            else:
                kept.append(c)
        visible = kept
    messages, instruction_chunks = guards.assemble_rag(settings, query, visible)
    for c in instruction_chunks:
        if c.provenance == "user" and guards.RAG_MARKER in c.text:
            audit.record(store, session_id, module, audit.POISONED_CHUNK_IN_CONTEXT,
                         session_id, {"chunk": c.id})
    reply = llm.chat(messages)
    if settings.sec_rag_jev_reply and jev_screen.flagged(
            jev, settings.sec_rag_jev_threshold, jev_screen.REPLY_QUESTION,
            jev_screen.REPLY_CRITERIA,
            {"question": query,
             "trusted_knowledge": [c.text for c in visible if c.provenance == "trusted"],
             "reply": reply}):
        # JEV layer 4: the customer gets a fixed message instead of the flagged reply.
        audit.record(store, session_id, module, audit.REPLY_BLOCKED, session_id, {"by": "jev"})
        reply = REPLY_BLOCKED_MESSAGE
    # Scan what the customer actually receives.
    canary.scan_and_record(store, session_id, module, reply, actor=session_id)
    restricted_seen = any(
        c.access == "restricted" and c.owner_session != session_id for c in visible
    )
    if restricted_seen and guards.RAG_MEMO_CANARY in reply:
        audit.record(store, session_id, module, audit.RESTRICTED_DOC_DISCLOSED,
                     session_id, {})
    return reply, visible
