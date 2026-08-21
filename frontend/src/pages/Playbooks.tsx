import { Table, Card, Tag } from "antd";
import { useEffect, useState } from "react";
import { api } from "../api/client";

export default function Playbooks() {
  const [pbs, setPbs] = useState<any[]>([]);

  useEffect(() => {
    api.listPlaybooks().then((d) => setPbs(d || []));
  }, []);

  const PRIO_COLORS: Record<string, string> = { P0: "red", P1: "orange", P2: "default" };

  return (
    <Card title="剧本库">
      <Table
        rowKey="id"
        dataSource={pbs}
        pagination={{ pageSize: 20 }}
        columns={[
          { title: "ID", dataIndex: "id" },
          { title: "名称", dataIndex: "name" },
          { title: "分类", dataIndex: "category" },
          {
            title: "优先级",
            dataIndex: "priority",
            render: (v) => <Tag color={PRIO_COLORS[v]}>{v}</Tag>,
          },
          { title: "阶段", dataIndex: "phase" },
          { title: "自主性默认", dataIndex: "autonomy_default" },
          { title: "动作数", dataIndex: "action_count" },
          {
            title: "MITRE",
            dataIndex: "mitre_techniques",
            render: (v: string[]) => v?.join(", "),
          },
        ]}
      />
    </Card>
  );
}
