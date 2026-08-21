import { useEffect, useState } from "react";
import { Card, Table, Tag, Select } from "antd";
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

export default function Cases() {
  const [cases, setCases] = useState<any[]>([]);
  const [status, setStatus] = useState<string | undefined>();
  const nav = useNavigate();

  const load = async () => {
    const data = await api.listCases(status);
    setCases(data || []);
  };

  useEffect(() => {
    load();
  }, [status]);

  return (
    <Card
      title="案件列表"
      extra={
        <Select
          allowClear
          placeholder="按状态筛选"
          style={{ width: 180 }}
          onChange={(v) => setStatus(v)}
          options={[
            "open",
            "investigating",
            "pending_approval",
            "contained",
            "resolved",
            "closed",
          ].map((s) => ({ value: s, label: s }))}
        />
      }
    >
      <Table
        rowKey="case_id"
        dataSource={cases}
        pagination={{ pageSize: 20 }}
        onRow={(r) => ({ onClick: () => nav(`/cases/${r.case_id}`) })}
        columns={[
          { title: "Case ID", dataIndex: "case_id", render: (v) => v.slice(0, 8) + "..." },
          {
            title: "状态",
            dataIndex: "status",
            render: (v) => <Tag color={STATUS_COLORS[v]}>{v}</Tag>,
          },
          { title: "剧本", dataIndex: "playbook_id" },
          { title: "严重性", dataIndex: "severity" },
          { title: "告警数", dataIndex: "alert_count" },
          { title: "待审批", dataIndex: "pending_approvals" },
          { title: "TTTR(秒)", dataIndex: "tttr_seconds" },
          { title: "创建时间", dataIndex: "created_at", render: (v) => v?.slice(0, 19) },
        ]}
      />
    </Card>
  );
}
