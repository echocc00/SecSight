import { Card, Timeline as AntTimeline, Tag } from "antd";
import dayjs from "dayjs";

interface Props {
  steps: any[];
}

export default function Timeline({ steps }: Props) {
  if (!steps?.length) return <Card>暂无执行记录</Card>;

  const colorFor = (status: string) => {
    if (status === "success") return "green";
    if (status === "failed") return "red";
    if (status === "executing") return "blue";
    return "gray";
  };

  return (
    <Card title="执行时间线">
      <AntTimeline
        items={steps.map((s) => ({
          color: colorFor(s.status),
          children: (
            <div>
              <Tag color={colorFor(s.status)}>{s.status}</Tag>
              <span style={{ marginLeft: 8, fontWeight: 600 }}>{s.action_id?.slice(0, 8)}</span>
              {s.started_at && (
                <div style={{ fontSize: 12, color: "#999" }}>
                  {dayjs(s.started_at).format("YYYY-MM-DD HH:mm:ss")}
                  {s.finished_at && ` → ${dayjs(s.finished_at).format("HH:mm:ss")}`}
                </div>
              )}
              {s.result?.message && <div style={{ marginTop: 4 }}>{s.result.message}</div>}
            </div>
          ),
        }))}
      />
    </Card>
  );
}
