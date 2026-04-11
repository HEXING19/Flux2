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
            "threat_hunting": PlaybookTemplateMeta(
                id="threat_hunting",
                name="攻击者活动轨迹",
                description="围绕目标IP在默认90天窗口内扫描告警并生成时间线故事。",
                button_label="🕵️ 攻击者活动轨迹生成",
                default_params={"window_days": 90, "max_scan": 10000, "evidence_limit": 20},
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
            "asset_guard": PlaybookTemplateMeta(
                id="asset_guard",
                name="核心资产防线透视",
                description="围绕核心资产IP进行双向流量/告警体检，输出管理层可读的风险结论。",
                button_label="🏥 核心资产一键体检",
                default_params={"window_hours": 24, "top_external_ip": 5},
                params=[
                    PlaybookTemplateParam(
                        key="asset_ip",
                        label="核心资产IP",
                        description="必填，保护对象IP。",
                        required=True,
                    ),
                    PlaybookTemplateParam(
                        key="asset_name",
                        label="资产名称",
                        description="可选，便于管理层识别业务对象。",
                        required=False,
                    ),
                    PlaybookTemplateParam(
                        key="window_hours",
                        label="统计窗口(小时)",
                        description="默认24小时。",
                        required=False,
                        default=24,
                    ),
                    PlaybookTemplateParam(
                        key="top_external_ip",
                        label="外部IP TopN",
                        description="默认5个。",
                        required=False,
                        default=5,
                    ),
                ],
            ),
        }

    def list_templates(self) -> list[dict]:
        return [template.model_dump() for template in self._templates.values()]

    def get_template(self, template_id: str) -> PlaybookTemplateMeta | None:
        return self._templates.get(template_id)
