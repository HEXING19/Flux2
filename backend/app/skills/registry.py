from __future__ import annotations

from app.core.context import SkillContextManager
from app.core.requester import APIRequester

from .block_skills import BlockActionSkill, BlockQuerySkill
from .entity_skill import EntityQuerySkill
from .event_skills import EventActionSkill, EventDetailSkill, EventQuerySkill
from .log_stats_skill import LogStatsSkill


class SkillRegistry:
    def __init__(self, requester: APIRequester, context_manager: SkillContextManager):
        self._skills = {
            "event_query": EventQuerySkill(requester, context_manager),
            "event_detail": EventDetailSkill(requester, context_manager),
            "event_action": EventActionSkill(requester, context_manager),
            "block_query": BlockQuerySkill(requester, context_manager),
            "block_action": BlockActionSkill(requester, context_manager),
            "entity_query": EntityQuerySkill(requester, context_manager),
            "log_stats": LogStatsSkill(requester, context_manager),
        }

    def get(self, intent: str):
        return self._skills.get(intent)
