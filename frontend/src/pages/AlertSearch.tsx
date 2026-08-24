import { useState } from "react";
import { Card, Input, Table, Tag, Button, Space, Select, message, Empty } from "antd";
import { SearchOutlined, ReloadOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

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

interface Hit {
  case_id: string;
  case_status: string;
  playbook_id: string | null;
  alert: any;
  matched_at: string;
}

export default function AlertSearch() {
  const [query, setQuery] = useState("");
  const [hours, setHours] = useState(24);
  const [hits, setHits] = useState<Hit[]>([]);
  const [source, setSource] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const nav = useNavigate();

  const search = async () => {
    if (!query.trim()) {
      message.warning("请输入搜索关键词");
      return;
    }
    setLoading(true);
    setSearched(true);
    try {
      const data = await api.searchAlerts(query.trim(), 50, hours);
      setHits(data?.hits || []);
      setSource(data?.source || "");
    } catch (e: any) {
      message.error(e?.response?.data?.error || "搜索失败");
      setHits([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      title="告警搜索"
      extra={
        <Space>
          <Select
            value={hours}
            onChange={setHours}
            style={{ width: 140 }}
            options={[
              { value: 1, label: "近 1 小时" },
              { value: 6, label: "近 6 小时" },
              { value: 24, label: "近 24 小时" },
              { value: 72, label: "近 3 天" },
              { value: 168, label: "近 7 天" },
            ]}
          />
          {source && <Tag color="geekblue">来源: {source}</Tag>}
        </Space>
      }
    >
      <Space.Compact style={{ width: "100%", marginBottom: 16 }}>
        <Input
          placeholder="搜索进程名 / IP / 规则 ID / 消息内容 (如 xmrig, 10.0.1.15, 5710)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onPressEnter={search}
          prefix={<SearchOutlined />}
          size="large"
        />
        <Button type="primary" size="large" onClick={search} loading={loading} icon={<SearchOutlined />}>
          搜索
        </Button>
      </Space.Compact>

      {searched && hits.length === 0 && !loading && (
        <Empty description={`未匹配到告警 (关键词: ${query})`} />
      )}

      {hits.length > 0 && (
        <Table
          rowKey={(r) => r.case_id + r.alert.alert_id}
          dataSource={hits}
          pagination={{ pageSize: 20 }}
          columns={[
            {
              title: "Case",
              dataIndex: "case_id",
              render: (v, r) => (
                <Button type="link" size="small" onClick={() => nav(`/cases/${v}`)}>
                  {v.slice(0, 8)}...
                </Button>
              ),
            },
            {
              title: "Case 状态",
              dataIndex: "case_status",
              render: (v) => <Tag color={STATUS_COLORS[v]}>{v}</Tag>,
            },
            { title: "剧本", dataIndex: "playbook_id", render: (v) => v || "—" },
            {
              title: "来源",
              key: "source",
              render: (_, r) => r.alert?.source || "—",
            },
            {
              title: "严重性",
              key: "severity",
              render: (_, r) => {
                const s = (r.alert?.severity || "").toLowerCase();
                return s ? <Tag color={SEVERITY_COLORS[s]}>{s}</Tag> : "—";
              },
            },
            {
              title: "源 IP",
              key: "src_ip",
              render: (_, r) => r.alert?.src_ip || "—",
            },
            {
              title: "规则",
              key: "rule",
              render: (_, r) => r.alert?.rule_id || "—",
            },
            {
              title: "消息",
              key: "message",
              ellipsis: true,
              render: (_, r) => r.alert?.message || "—",
            },
            {
              title: "匹配时间",
              dataIndex: "matched_at",
              render: (v) => v?.slice(0, 19).replace("T", " "),
            },
          ]}
        />
      )}
    </Card>
  );
}
