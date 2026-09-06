import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Progress,
  Space,
  Spin,
  Statistic,
  Table,
  Tag,
  message,
} from "antd";
import {
  DownloadOutlined,
  FileMarkdownOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import { api } from "../api/client";

const STATUS_COLORS: Record<string, string> = {
  open: "default",
  investigating: "blue",
  pending_approval: "orange",
  contained: "purple",
  resolved: "green",
  closed: "default",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export default function Compliance() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [chain, setChain] = useState<any>(null);
  const [chainLoading, setChainLoading] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const list = await api.listCases();
      setCases(list || []);
    } catch {
      setCases([]);
    } finally {
      setLoading(false);
    }
  };

  const verifyChain = async () => {
    setChainLoading(true);
    try {
      const result = await api.verifyAuditChain();
      setChain(result);
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "审计链校验失败");
      setChain(null);
    } finally {
      setChainLoading(false);
    }
  };

  useEffect(() => {
    load();
    verifyChain();
  }, []);

  const download = async (caseId: string, format: "html" | "markdown") => {
    setDownloading(`${caseId}:${format}`);
    try {
      const res = await api.generateReport(caseId, format);
      const blob = new Blob([res.content], {
        type: format === "html" ? "text/html" : "text/markdown",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `secsight-report-${caseId.slice(0, 8)}.${format === "html" ? "html" : "md"}`;
      a.click();
      URL.revokeObjectURL(url);
      message.success("报告已下载");
    } catch (e: any) {
      message.error(e?.response?.data?.detail || `报告生成失败 (${caseId.slice(0, 8)})`);
    } finally {
      setDownloading(null);
    }
  };

  // 有研判(可用于报告)的 case 优先;按严重性 + 时间排序
  const reportable = cases
    .filter((c) => c.severity)
    .sort((a, b) => {
      const sev =
        (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
      if (sev !== 0) return sev;
      return (b.created_at || "").localeCompare(a.created_at || "");
    });

  const resolvedCount = cases.filter((c) => c.status === "resolved").length;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card
        title={
          <Space>
            <SafetyCertificateOutlined />
            <span>合规报告 (等保 2.0 三级)</span>
          </Space>
        }
        extra={
          <Button loading={chainLoading} onClick={verifyChain}>
            重新校验审计链
          </Button>
        }
      >
        <Space size={24} wrap>
          <Statistic title="可出报告事件" value={reportable.length} />
          <Statistic title="已闭环事件" value={resolvedCount} valueStyle={{ color: "#3f8600" }} />
        </Space>
        {chain && (
          <Descriptions
            column={3}
            size="small"
            style={{ marginTop: 16 }}
            bordered
          >
            <Descriptions.Item label="审计链完整性">
              {chain.valid ? (
                <Tag color="success" icon={<SafetyCertificateOutlined />}>
                  校验通过
                </Tag>
              ) : (
                <Tag color="error">已断链 (seq {chain.broken_at_seq})</Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="验证记录数">
              {chain.verified_count}
            </Descriptions.Item>
            <Descriptions.Item label="链头哈希">
              <code style={{ fontSize: 11 }}>{chain.chain_head?.slice(0, 24)}…</code>
            </Descriptions.Item>
          </Descriptions>
        )}
        {chain && !chain.valid && (
          <Alert
            type="error"
            showIcon
            style={{ marginTop: 12 }}
            message={`审计日志疑似被篡改: ${chain.reason}`}
            description="链断裂说明日志被删除或修改,监管报告不可信,需排查数据库写入方。"
          />
        )}
      </Card>

      <Card title="可出报告事件" size="small">
        {loading ? (
          <Spin />
        ) : reportable.length === 0 ? (
          <Empty description="暂无已研判的事件 (完成研判后会自动出现在此处供生成报告)" />
        ) : (
          <Table
            rowKey="case_id"
            dataSource={reportable}
            size="small"
            pagination={{ pageSize: 15, showTotal: (t) => `共 ${t} 条` }}
            columns={[
              {
                title: "Case",
                dataIndex: "case_id",
                width: 110,
                render: (v: string) => <Link to={`/cases/${v}`}>{v.slice(0, 8)}</Link>,
              },
              {
                title: "严重性",
                dataIndex: "severity",
                width: 90,
                render: (v: string) => {
                  const color: Record<string, string> = {
                    critical: "red",
                    high: "volcano",
                    medium: "gold",
                    low: "green",
                  };
                  return <Tag color={color[v]}>{v}</Tag>;
                },
              },
              {
                title: "剧本",
                dataIndex: "playbook_id",
                width: 160,
                ellipsis: true,
              },
              {
                title: "告警",
                dataIndex: "alert_count",
                width: 70,
              },
              {
                title: "待审批",
                dataIndex: "pending_approvals",
                width: 80,
                render: (v: number) =>
                  v > 0 ? <Tag color="orange">{v}</Tag> : <Tag>0</Tag>,
              },
              {
                title: "状态",
                dataIndex: "status",
                width: 120,
                render: (v: string) => <Tag color={STATUS_COLORS[v]}>{v}</Tag>,
              },
              {
                title: "创建时间",
                dataIndex: "created_at",
                width: 150,
                render: (v: string) => v?.slice(0, 19).replace("T", " "),
              },
              {
                title: "报告",
                key: "report",
                width: 220,
                render: (_, r) => (
                  <Space>
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      loading={downloading === `${r.case_id}:html`}
                      onClick={() => download(r.case_id, "html")}
                    >
                      HTML
                    </Button>
                    <Button
                      size="small"
                      icon={<FileMarkdownOutlined />}
                      loading={downloading === `${r.case_id}:markdown`}
                      onClick={() => download(r.case_id, "markdown")}
                    >
                      MD
                    </Button>
                  </Space>
                ),
              },
            ]}
          />
        )}
      </Card>
    </Space>
  );
}