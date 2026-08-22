import { useEffect, useState } from "react";
import { Card, Col, Row, Statistic, Button, message, Table, Tag, Progress } from "antd";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Legend,
} from "recharts";
import { api } from "../api/client";

const STATUS_COLORS: Record<string, string> = {
  open: "#bfbfbf",
  investigating: "#1677ff",
  pending_approval: "#faad14",
  contained: "#722ed1",
  resolved: "#52c41a",
  closed: "#8c8c8c",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#cf1322",
  high: "#d4380d",
  medium: "#d4b106",
  low: "#389e0d",
};

export default function Dashboard() {
  const [cases, setCases] = useState<any[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [injecting, setInjecting] = useState<string | null>(null);

  const load = async () => {
    try {
      const [data, t, h] = await Promise.all([
        api.listCases(),
        api.listAlertTypes(),
        api.health(),
      ]);
      setCases(data || []);
      setTypes(t?.types || []);
      setHealth(h);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000); // 15s 自动刷新
    return () => clearInterval(timer);
  }, []);

  const pendingCount = cases.filter((c) => c.status === "pending_approval").length;
  const resolvedCount = cases.filter((c) => c.status === "resolved").length;
  const investigatingCount = cases.filter((c) => c.status === "investigating").length;
  const avgTttr = cases.filter((c) => c.tttr_seconds).reduce((a, c, _i, arr) => a + c.tttr_seconds / arr.length, 0);

  // 状态分布饼图数据
  const statusData = Object.keys(STATUS_COLORS).map((k) => ({
    name: k,
    value: cases.filter((c) => c.status === k).length,
  })).filter((d) => d.value > 0);

  // 严重性分布柱状图
  const severityData = Object.keys(SEVERITY_COLORS).map((k) => ({
    name: k,
    count: cases.filter((c) => (c.severity || "").toLowerCase() === k).length,
  }));

  const inject = async (alertType: string) => {
    setInjecting(alertType);
    try {
      const res = await api.injectAlert({ alert_type: alertType });
      message.success(`告警已注入 → ${res.playbook_name || "无剧本"} (Case ${res.case_id.slice(0, 8)})`);
      await load();
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "注入失败");
    } finally {
      setInjecting(null);
    }
  };

  return (
    <div>
      {/* KPI 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={4}>
          <Card>
            <Statistic title="总案件" value={cases.length} />
          </Card>
        </Col>
        <Col span={4}>
          <Card>
            <Statistic title="调查中" value={investigatingCount} valueStyle={{ color: STATUS_COLORS.investigating }} />
          </Card>
        </Col>
        <Col span={4}>
          <Card>
            <Statistic title="待审批" value={pendingCount} valueStyle={{ color: STATUS_COLORS.pending_approval }} />
          </Card>
        </Col>
        <Col span={4}>
          <Card>
            <Statistic title="已处置" value={resolvedCount} valueStyle={{ color: STATUS_COLORS.resolved }} />
          </Card>
        </Col>
        <Col span={4}>
          <Card>
            <Statistic title="平均 TTTR" value={Math.round(avgTttr) || 0} suffix="秒" />
          </Card>
        </Col>
        <Col span={4}>
          <Card>
            <Statistic
              title="处置率"
              value={cases.length ? Math.round((resolvedCount / cases.length) * 100) : 0}
              suffix="%"
              valueStyle={{ color: STATUS_COLORS.resolved }}
            />
          </Card>
        </Col>
      </Row>

      {/* 图表区 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="案件状态分布">
            {statusData.length ? (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={statusData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={(e: any) => `${e.name}: ${e.value}`}
                  >
                    {statusData.map((d) => (
                      <Cell key={d.name} fill={STATUS_COLORS[d.name]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 240, textAlign: "center", lineHeight: "240px", color: "#999" }}>暂无数据</div>
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="严重性分布">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={severityData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count">
                  {severityData.map((d) => (
                    <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      {/* 告警注入 + 系统健康 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={16}>
          <Card title="告警注入 (测试用)" size="small">
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {types.map((t) => (
                <Button
                  key={t}
                  size="small"
                  loading={injecting === t}
                  onClick={() => inject(t)}
                >
                  {t}
                </Button>
              ))}
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="系统健康" size="small">
            {health?.components ? (
              Object.entries(health.components).map(([name, status]: [string, any]) => (
                <div key={name} style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span>{name}</span>
                  <Tag color={status === "ok" ? "green" : "orange"}>{status}</Tag>
                </div>
              ))
            ) : (
              <span>加载中...</span>
            )}
            <div style={{ marginTop: 8, fontSize: 12, color: "#999" }}>
              mock_mode: {health?.mock_mode ? "true" : "false"} | v{health?.version}
            </div>
          </Card>
        </Col>
      </Row>

      {/* 最近案件 */}
      <Card title="最近案件">
        <Table
          rowKey="case_id"
          dataSource={cases.slice(0, 10)}
          pagination={false}
          onRow={(r) => ({ onClick: () => (window.location.href = `/cases/${r.case_id}`) })}
          columns={[
            { title: "Case ID", dataIndex: "case_id", render: (v) => v.slice(0, 8) },
            {
              title: "状态",
              dataIndex: "status",
              render: (v) => <Tag color={STATUS_COLORS[v]}>{v}</Tag>,
            },
            { title: "剧本", dataIndex: "playbook_id", render: (v) => v || "—" },
            {
              title: "严重性",
              dataIndex: "severity",
              render: (v) => (v ? <Tag color={SEVERITY_COLORS[v.toLowerCase()]}>{v}</Tag> : "—"),
            },
            { title: "告警数", dataIndex: "alert_count" },
            { title: "待审批", dataIndex: "pending_approvals" },
            { title: "TTTR(秒)", dataIndex: "tttr_seconds", render: (v) => v ?? "—" },
            { title: "创建时间", dataIndex: "created_at", render: (v) => v?.slice(0, 19).replace("T", " ") },
          ]}
        />
      </Card>
    </div>
  );
}
