import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Card, Descriptions, Tag, Tabs, message, Button, Progress, Space, Empty } from "antd";
import { DownloadOutlined, FileTextOutlined, ReloadOutlined } from "@ant-design/icons";
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

const SEVERITY_COLORS: Record<string, string> = {
  critical: "red", high: "volcano", medium: "gold", low: "green",
};

export default function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const [caseData, setCaseData] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);
  const [reportLoading, setReportLoading] = useState(false);

  const load = async () => {
    if (!caseId) return;
    try {
      const c = await api.getCase(caseId);
      setCaseData(c);
      const e = await api.getEvidence(caseId);
      setEvidence(e);
    } catch {
      setEvidence(null);
    }
  };

  useEffect(() => {
    load();
  }, [caseId]);

  const downloadReport = async (format: "html" | "markdown") => {
    setReportLoading(true);
    try {
      const res = await api.generateReport(caseId!, format);
      const blob = new Blob([res.content], {
        type: format === "html" ? "text/html" : "text/markdown",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `secsight-report-${caseId!.slice(0, 8)}.${format === "html" ? "html" : "md"}`;
      a.click();
      URL.revokeObjectURL(url);
      message.success(`${format.toUpperCase()} 报告已下载`);
    } catch (e: any) {
      message.error("报告生成失败");
    } finally {
      setReportLoading(false);
    }
  };

  if (!caseData) return <Card loading />;

  const judgment = caseData.judgment;
  const sevColor = SEVERITY_COLORS[(judgment?.severity || "").toLowerCase()] || "default";

  return (
    <div>
      <Card
        title={
          <Space>
            <span>Case {caseData.case_id?.slice(0, 8)}</span>
            <Tag color={STATUS_COLORS[caseData.status]}>{caseData.status}</Tag>
            {judgment && <Tag color={sevColor}>{judgment.severity}</Tag>}
          </Space>
        }
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load} size="small">刷新</Button>
            <Button
              icon={<DownloadOutlined />}
              loading={reportLoading}
              onClick={() => downloadReport("html")}
              size="small"
              disabled={!judgment}
            >
              HTML 报告
            </Button>
            <Button
              icon={<FileTextOutlined />}
              loading={reportLoading}
              onClick={() => downloadReport("markdown")}
              size="small"
              disabled={!judgment}
            >
              MD 报告
            </Button>
          </Space>
        }
        style={{ marginBottom: 16 }}
      >
        <Descriptions column={3} size="small">
          <Descriptions.Item label="剧本">{caseData.playbook_id || "未匹配"}</Descriptions.Item>
          <Descriptions.Item label="自主性">{caseData.autonomy_level_default}</Descriptions.Item>
          <Descriptions.Item label="TTTR">{caseData.tttr_seconds ? `${caseData.tttr_seconds} 秒` : "进行中"}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{caseData.created_at?.slice(0, 19).replace("T", " ")}</Descriptions.Item>
          <Descriptions.Item label="告警数">{caseData.alerts?.length}</Descriptions.Item>
          <Descriptions.Item label="动作数">{caseData.proposed_actions?.length}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Tabs
        items={[
          {
            key: "judgment",
            label: "研判报告",
            children: judgment ? (
              <Card>
                <Descriptions column={2} bordered size="small">
                  <Descriptions.Item label="摘要" span={2}>{judgment.incident_summary}</Descriptions.Item>
                  <Descriptions.Item label="严重性">
                    <Tag color={sevColor}>{judgment.severity}</Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="真阳性">{judgment.true_positive}</Descriptions.Item>
                  <Descriptions.Item label="置信度" span={2}>
                    <Progress
                      percent={Math.round((judgment.confidence || 0) * 100)}
                      size="small"
                      status={judgment.confidence > 0.7 ? "success" : judgment.confidence > 0.4 ? "normal" : "exception"}
                      format={(p) => `${p}%`}
                    />
                  </Descriptions.Item>
                  <Descriptions.Item label="TTPs" span={2}>
                    <Space wrap>
                      {(judgment.ttps || []).map((t: string) => (
                        <Tag key={t} color="geekblue">{t}</Tag>
                      ))}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="建议动作" span={2}>
                    <Space wrap>
                      {(judgment.recommended_actions || []).map((a: string) => (
                        <Tag key={a}>{a}</Tag>
                      ))}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="推理依据" span={2}>{judgment.rationale}</Descriptions.Item>
                  <Descriptions.Item label="引用" span={2}>
                    {(judgment.citations || []).join(", ")}
                  </Descriptions.Item>
                </Descriptions>
              </Card>
            ) : (
              <Empty description="暂无研判报告" />
            ),
          },
          {
            key: "alerts",
            label: `告警 (${caseData.alerts?.length || 0})`,
            children: (
              <Card>
                <pre style={{ maxHeight: 400, overflow: "auto", fontSize: 12 }}>
                  {JSON.stringify(caseData.alerts, null, 2)}
                </pre>
              </Card>
            ),
          },
          {
            key: "actions",
            label: `处置动作 (${caseData.proposed_actions?.length || 0})`,
            children: (
              <ApprovalPanel
                caseId={caseId!}
                actions={caseData.proposed_actions}
                approvals={caseData.approvals}
                onApproved={load}
              />
            ),
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
                <Descriptions column={2} size="small" bordered>
                  <Descriptions.Item label="Pack ID">{evidence.pack_id?.slice(0, 8)}</Descriptions.Item>
                  <Descriptions.Item label="时间线条目">{evidence.timeline?.length}</Descriptions.Item>
                  <Descriptions.Item label="MITRE 战术" span={2}>
                    {evidence.mitre_mapping?.tactics?.join(", ")}
                  </Descriptions.Item>
                  <Descriptions.Item label="MITRE 技术" span={2}>
                    {evidence.mitre_mapping?.techniques?.join(", ")}
                  </Descriptions.Item>
                </Descriptions>
                <pre style={{ marginTop: 16, maxHeight: 300, overflow: "auto", fontSize: 12 }}>
                  {JSON.stringify(evidence, null, 2)}
                </pre>
              </Card>
            ) : (
              <Empty description="暂无 Evidence Pack" />
            ),
          },
        ]}
      />
    </div>
  );
}
