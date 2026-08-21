import { useEffect, useState } from "react";
import { useParams, Card, Descriptions, Tag, Tabs, message, Button, Modal, Form, Select, Input } from "antd";
import { api } from "../api/client";
import ApprovalPanel from "../components/ApprovalPanel";
import Timeline from "../components/Timeline";

const STATUS_COLORS: Record<string, string> = {
  open: "default",
  investigating: "blue",
  pending_approval: "orange",
  contained: "purple",
  resolved: "green",
  closed: "default",
};

export default function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const [caseData, setCaseData] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);

  const load = async () => {
    if (!caseId) return;
    const c = await api.getCase(caseId);
    setCaseData(c);
    try {
      const e = await api.getEvidence(caseId);
      setEvidence(e);
    } catch {
      setEvidence(null);
    }
  };

  useEffect(() => {
    load();
  }, [caseId]);

  if (!caseData) return <Card loading />;

  const judgment = caseData.judgment;

  return (
    <div>
      <Card
        title={
          <span>
            Case {caseData.case_id?.slice(0, 8)}...
            <Tag color={STATUS_COLORS[caseData.status]} style={{ marginLeft: 12 }}>
              {caseData.status}
            </Tag>
          </span>
        }
        style={{ marginBottom: 16 }}
      >
        <Descriptions column={2}>
          <Descriptions.Item label="剧本">{caseData.playbook_id || "未匹配"}</Descriptions.Item>
          <Descriptions.Item label="自主性默认">{caseData.autonomy_level_default}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{caseData.created_at?.slice(0, 19)}</Descriptions.Item>
          <Descriptions.Item label="TTTR(秒)">{caseData.tttr_seconds ?? "进行中"}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Tabs
        items={[
          {
            key: "alerts",
            label: "告警",
            children: (
              <Card>
                <pre style={{ maxHeight: 400, overflow: "auto" }}>
                  {JSON.stringify(caseData.alerts, null, 2)}
                </pre>
              </Card>
            ),
          },
          {
            key: "judgment",
            label: "研判报告",
            children: judgment ? (
              <Card>
                <Descriptions column={1}>
                  <Descriptions.Item label="摘要">{judgment.incident_summary}</Descriptions.Item>
                  <Descriptions.Item label="严重性">
                    <Tag color="red">{judgment.severity}</Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="置信度">{judgment.confidence}</Descriptions.Item>
                  <Descriptions.Item label="TTPs">{judgment.ttps?.join(", ")}</Descriptions.Item>
                  <Descriptions.Item label="真阳性">{judgment.true_positive}</Descriptions.Item>
                  <Descriptions.Item label="建议动作">
                    {judgment.recommended_actions?.join(", ")}
                  </Descriptions.Item>
                  <Descriptions.Item label="推理依据">{judgment.rationale}</Descriptions.Item>
                </Descriptions>
              </Card>
            ) : (
              <Card>暂无研判</Card>
            ),
          },
          {
            key: "actions",
            label: `处置动作 (${caseData.proposed_actions?.length || 0})`,
            children: <ApprovalPanel caseId={caseId!} actions={caseData.proposed_actions} approvals={caseData.approvals} onApproved={load} />,
          },
          {
            key: "timeline",
            label: "执行时间线",
            children: <Timeline steps={caseData.execution_log} />,
          },
          {
            key: "evidence",
            label: "Evidence Pack",
            children: evidence ? (
              <Card>
                <pre style={{ maxHeight: 400, overflow: "auto" }}>
                  {JSON.stringify(evidence, null, 2)}
                </pre>
              </Card>
            ) : (
              <Card>暂无 Evidence Pack</Card>
            ),
          },
        ]}
      />
    </div>
  );
}
