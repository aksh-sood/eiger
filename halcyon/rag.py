from halcyon import audit, canary, guards
from halcyon.config import Settings
from halcyon.kb import Chunk, KnowledgeBase
from halcyon.llm import LLM
from halcyon.question_judge import judge_question
from halcyon.store import Store


def answer(kb: KnowledgeBase, llm: LLM, store: Store, settings: Settings,
           session_id: str, query: str, module: str = "m3") -> tuple[str, list[Chunk]]:
    if settings.sec_rag_question_judge:
        verdict = judge_question(llm, query)
        if not verdict.allowed:
            audit.record(store, session_id, module, audit.QUESTION_BLOCKED, session_id, {})
            return verdict.text, []
        query = verdict.text  # the refined question replaces the original from here on
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
    messages, instruction_chunks = guards.assemble_rag(settings, query, visible)
    for c in instruction_chunks:
        if c.provenance == "user" and guards.RAG_MARKER in c.text:
            audit.record(store, session_id, module, audit.POISONED_CHUNK_IN_CONTEXT,
                         session_id, {"chunk": c.id})
    reply = llm.chat(messages)
    canary.scan_and_record(store, session_id, module, reply, actor=session_id)
    restricted_seen = any(
        c.access == "restricted" and c.owner_session != session_id for c in visible
    )
    if restricted_seen and guards.RAG_MEMO_CANARY in reply:
        audit.record(store, session_id, module, audit.RESTRICTED_DOC_DISCLOSED,
                     session_id, {})
    return reply, visible
