from __future__ import annotations

from app.playbook.schemas import PlaybookTemplateMeta, PlaybookTemplateParam


class PlaybookRegistry:
    def __init__(self) -> None:
        self._templates: dict[str, PlaybookTemplateMeta] = {
            "routine_check": PlaybookTemplateMeta(
                id="routine_check",
                name="今日安全早报",
                description="聚合过去24小时日志总量、高危未处置事件与样本证据，生成晨报结论。",
                button_label="☕ 生成今日安全早报",
                default_params={"window_hours": 24, "sample_size": 3},
                params=[
                    PlaybookTemplateParam(
                        key="window_hours",
                        label="统计窗口(小时)",
                        description="默认24小时。",
                        required=False,
                        default=24,
                    ),
                    PlaybookTemplateParam(
                        key="sample_size",
                        label="样本事件数",
                        description="默认3条。",
                        required=False,
                        default=3,
                    ),
                ],
            ),
            "alert_triage": PlaybookTemplateMeta(
                id="alert_triage",
                name="单点告警深度研判",
                description="围绕指定事件进行实体画像、外部情报与内部影响面计数，给出处置建议。",
                button_label="🔍 一键深度研判",
                default_params={"window_days": 7, "mode": "analyze"},
                params=[
                    PlaybookTemplateParam(
                        key="incident_uuid",
                        label="事件UUID",
                        description="优先使用该参数定位事件。",
                        required=False,
                    ),
                    PlaybookTemplateParam(
                        key="event_index",
                        label="事件序号",
                        description="配合 session_id，从上下文序号映射到事件UUID。",
                        required=False,
                    ),
                    PlaybookTemplateParam(
                        key="window_days",
                        label="内部影响统计窗口(天)",
                        description="默认7天。",
                        required=False,
                        default=7,
                    ),
                ],
            ),
            "threat_hunting": PlaybookTemplateMeta(
                id="threat_hunting",
                name="攻击者活动轨迹",
                description="围绕目标IP在默认90天窗口内扫描事件并生成时间线故事。",
                button_label="🕵️ 攻击者活动轨迹生成",
                default_params={"window_days": 90, "max_scan": 2000, "evidence_limit": 20},
                params=[
                    PlaybookTemplateParam(
                        key="ip",
                        label="目标IP",
                        description="必填，目标攻击者IP。",
                        required=True,
                    ),
                    PlaybookTemplateParam(
                        key="startTimestamp",
                        label="开始时间戳",
                        description="可选；不填默认回溯90天。",
                        required=False,
                    ),
                    PlaybookTemplateParam(
                        key="endTimestamp",
                        label="结束时间戳",
                        description="可选；不填默认当前时间。",
                        required=False,
                    ),
                ],
            ),
        }

    def list_templates(self) -> list[dict]:
        return [template.model_dump() for template in self._templates.values()]

    def get_template(self, template_id: str) -> PlaybookTemplateMeta | None:
        return self._templates.get(template_id)
