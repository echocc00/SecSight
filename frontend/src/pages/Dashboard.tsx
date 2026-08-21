import { useEffect, useState } from "react";
import { Card, Col, Row, Statistic, Button, message, Table } from "antd";
import { api } from "../api/client";

export default function Dashboard() {
  const [cases, setCases] = useState<any[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [injecting, setInjecting] = useState(false);

  const load = async () => {
    const data = await api.listCases();
    setCases(data || []);
    const t = await api.listAlertTypes();
    setTypes(t.types || []);
  };

  useEffect(() => {
    load();
  }, []);

  const pendingCount = cases.filter((c) => c.status === "pending_approval").length;
  const resolvedCount = cases.filter((c) => c.status === "resolved").length;
  const investigatingCount = cases.filter(
    (c) => c.status === "investigating"
  ).length;

  const inject = async (alertType: string) => {
    setInjecting(true);
    try {
      const res = await api.injectAlert({ alert_type: alertType });
      message.success(`告警已注入 → Case ${res.case_id.slice(0, 8)}... 剧本: ${res.playbook_name}`);
      await load();
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "注入失败");
    } finally {
      setInjecting(false);
    }
  };

  return (
    <div>
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic title="总案件数" value={cases.length} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="调查中" value={investigatingCount} valueStyle={{ color: "#1677ff" }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="待审批" value={pendingCount} valueStyle={{ color: "#faad14" }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已处置" value={resolvedCount} valueStyle={{ color: "#52c41a" }} />
          </Card>
        </Col>
      </Row>

      <Card title="Mock 告警注入 (开发用)" style={{ marginBottom: 24 }}>
        {types.map((t) => (
          <Button
            key={t}
            type="primary"
            loading={injecting}
            onClick={() => inject(t)}
            style={{ marginRight: 12 }}
          >
            注入: {t}
          </Button>
        ))}
      </Card>

      <Card title="最近案件">
        <Table
          rowKey="case_id"
          dataSource={cases}
          pagination={{ pageSize: 10 }}
          columns={[
            { title: "Case ID", dataIndex: "case_id", render: (v) => v.slice(0, 8) + "..." },
            { title: "状态", dataIndex: "status" },
            { title: "剧本", dataIndex: "playbook_id" },
            { title: "严重性", dataIndex: "severity" },
            { title: "告警数", dataIndex: "alert_count" },
            { title: "待审批", dataIndex: "pending_approvals" },
            { title: "TTTR(秒)", dataIndex: "tttr_seconds" },
            { title: "创建时间", dataIndex: "created_at", render: (v) => v?.slice(0, 19) },
          ]}
          onRow={(r) => ({ onClick: () => (window.location.href = `/cases/${r.case_id}`) })}
        />
      </Card>
    </div>
  );
}
