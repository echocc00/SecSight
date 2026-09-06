import { Card, Timeline as AntTimeline, Tag, Space, Tooltip, Empty, Statistic, Row, Col, Alert } from "antd";
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
  MinusCircleOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { parseUtc, formatDateTime, formatTime } from "../lib/datetime";

interface Props {
  steps: any[];
  actions?: any[];
}

const STATUS_META: Record<
  string,
  { color: string; label: string; icon: React.ReactNode }
> = {
  success: { color: "green", label: "成功", icon: <CheckCircleOutlined /> },
  failed: { color: "red", label: "失败", icon: <CloseCircleOutlined /> },
  executing: { color: "blue", label: "执行中", icon: <LoadingOutlined /> },
  skipped: { color: "gray", label: "已跳过", icon: <MinusCircleOutlined /> },
  pending: { color: "gray", label: "待执行", icon: <MinusCircleOutlined /> },
  rolled_back: { color: "orange", label: "已回滚", icon: <MinusCircleOutlined /> },
};

function meta(status: string) {
  return STATUS_META[status] || { color: "gray", label: status, icon: <MinusCircleOutlined /> };
}

function durationMs(step: any): number | null {
  if (!step.started_at || !step.finished_at) return null;
  const s = parseUtc(step.started_at);
  const e = parseUtc(step.finished_at);
  if (!s || !e) return null;
  return e.diff(s);
}

export default function Timeline({ steps, actions = [] }: Props) {
  if (!steps?.length) {
    return (
      <Card>
        <Empty description="暂无执行记录 (动作可能仍在等待审批)" />
      </Card>
    );
  }

  const byStatus = steps.reduce<Record<string, number>>((acc, s) => {
    acc[s.status] = (acc[s.status] || 0) + 1;
    return acc;
  }, {});

  const durations = steps.map(durationMs).filter((d): d is number => d !== null);
  const totalMs = durations.reduce((a, b) => a + b, 0);

  // 全部走 mock 时必须显式提示 —— 否则会误以为主机真的被隔离了
  const executors = new Set(steps.map((s) => s.result?.executor).filter(Boolean));
  const allMock = executors.size > 0 && [...executors].every((e) => e === "mock");

  const actionById = new Map(actions.map((a) => [a.action_id, a]));

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card size="small">
        <Row gutter={16}>
          <Col span={5}>
            <Statistic title="执行步骤" value={steps.length} />
          </Col>
          <Col span={5}>
            <Statistic
              title="成功"
              value={byStatus.success || 0}
              valueStyle={{ color: "#3f8600" }}
            />
          </Col>
          <Col span={5}>
            <Statistic
              title="失败"
              value={byStatus.failed || 0}
              valueStyle={{ color: (byStatus.failed || 0) > 0 ? "#cf1322" : undefined }}
            />
          </Col>
          <Col span={4}>
            <Statistic title="跳过" value={byStatus.skipped || 0} />
          </Col>
          <Col span={5}>
            <Statistic
              title="总耗时"
              value={totalMs < 1000 ? totalMs : (totalMs / 1000).toFixed(1)}
              suffix={totalMs < 1000 ? "ms" : "s"}
            />
          </Col>
        </Row>
      </Card>

      {allMock && (
        <Alert
          type="warning"
          showIcon
          message="全部动作由 MockExecutor 执行"
          description="仅写日志与审计,未真实隔离主机/封禁 IP。真实处置需 SECSIGHT_MOCK_MODE=false + ENABLE_SHUFFLE=true + 配置 SHUFFLE_WORKFLOW_<ACTION>。"
        />
      )}

      <Card title="执行时间线" size="small">
        <AntTimeline
          items={steps.map((s) => {
            const m = meta(s.status);
            const action = actionById.get(s.action_id);
            const actionType = s.result?.action_type || action?.action_type || "unknown";
            const target = s.result?.target ?? action?.target;
            const ms = durationMs(s);
            const executor = s.result?.executor;

            return {
              color: m.color,
              dot: m.icon,
              children: (
                <Space direction="vertical" size={2} style={{ width: "100%" }}>
                  <Space wrap size={6}>
                    <Tag color={m.color}>{m.label}</Tag>
                    <span style={{ fontWeight: 600 }}>{actionType}</span>
                    {executor && (
                      <Tooltip
                        title={
                          executor === "mock"
                            ? "MockExecutor: 仅日志+审计,未真实处置"
                            : "Shuffle SOAR 真实执行"
                        }
                      >
                        <Tag
                          color={executor === "mock" ? "default" : "cyan"}
                          icon={executor === "mock" ? undefined : <ThunderboltOutlined />}
                        >
                          {executor}
                        </Tag>
                      </Tooltip>
                    )}
                    {s.result?.autonomy_level && <Tag>{s.result.autonomy_level}</Tag>}
                    {ms !== null && <Tag color="blue">{ms} ms</Tag>}
                  </Space>

                  {target && Object.keys(target).length > 0 && (
                    <code style={{ fontSize: 12, color: "#555" }}>
                      {JSON.stringify(target)}
                    </code>
                  )}

                  {s.started_at && (
                    <span style={{ fontSize: 12, color: "#999" }}>
                      {formatDateTime(s.started_at)}
                      {s.finished_at && ` → ${formatTime(s.finished_at)}`}
                    </span>
                  )}

                  {s.result?.reason && (
                    <span style={{ fontSize: 12, color: "#d46b08" }}>{s.result.reason}</span>
                  )}
                  {s.result?.fallback_reason && (
                    <span style={{ fontSize: 12, color: "#d46b08" }}>
                      降级原因: {s.result.fallback_reason}
                    </span>
                  )}
                  {s.error && <span style={{ fontSize: 12, color: "#cf1322" }}>{s.error}</span>}
                  {s.result?.message && !s.result?.reason && (
                    <span style={{ fontSize: 12 }}>{s.result.message}</span>
                  )}
                  {s.result?.task_id && (
                    <span style={{ fontSize: 11, color: "#aaa" }}>
                      task: {s.result.task_id}
                    </span>
                  )}
                </Space>
              ),
            };
          })}
        />
      </Card>
    </Space>
  );
}
