import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  Card,
  Empty,
  Form,
  Input,
  Modal,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  message,
} from "antd";
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  ExclamationCircleOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import { parseUtc, fromNow, formatDateTime } from "../lib/datetime";
import { onEvent } from "../lib/ws";
import { api, auth } from "../api/client";

interface PendingItem {
  case_id: string;
  case_status: string;
  playbook_id: string | null;
  severity: string | null;
  incident_summary: string | null;
  created_at: string;
  action_id: string;
  action_type: string;
  target: Record<string, unknown>;
  autonomy_level: string;
  risk: string;
  requires_double_sign: boolean;
  required_roles: string[];
  approved_roles: string[];
  missing_roles: string[];
  rejected: boolean;
  records: any[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "red",
  high: "volcano",
  medium: "gold",
  low: "green",
};

const ROLE_LABELS: Record<string, string> = {
  incident_commander: "指挥官",
  approver: "审批人",
  ciso_or_delegate: "CISO",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export default function Approvals() {
  const [items, setItems] = useState<PendingItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [modal, setModal] = useState<PendingItem | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm();
  // 我的审批角色: 服务端从 JWT 映射 (analyst→指挥官 / approver→审批人 / admin→CISO)。
  // 前端不再提供角色下拉 —— 换角色刷签在后端已被身份绑定阻断,UI 如实呈现。
  const [myApprovalRole, setMyApprovalRole] = useState<string | null>(
    auth.getApprovalRole()
  );

  const userRole = auth.getRole() || "viewer";

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listAllPending();
      setItems(data.items || []);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "加载待审批列表失败");
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    if (!myApprovalRole) {
      auth
        .getMe()
        .then((me: any) => setMyApprovalRole(me?.approval_role ?? null))
        .catch(() => undefined);
    }
    // 审批是时效工作: WS 推送实时刷新,30s 轮询兜底 (WS 断线自动恢复)
    const cleanups = [
      onEvent("approval_submitted", () => load()),
      onEvent("approval_rejected", () => load()),
      onEvent("case_created", () => load()),
      onEvent("alert_deduped", () => load()),
    ];
    const timer = setInterval(load, 30_000);
    return () => {
      cleanups.forEach((unsub) => unsub());
      clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async () => {
    const values = await form.validateFields();
    setSubmitting(true);
    try {
      const res = await api.approveAction(modal!.case_id, modal!.action_id, values);
      if (res.rejected) {
        message.warning("已拒绝: Case 已关闭,处置动作不会执行");
      } else {
        message.success(
          res.all_approved ? "全部动作已批准,workflow 已恢复执行" : "审批已提交,等待其他角色确认"
        );
      }
      setModal(null);
      form.resetFields();
      await load();
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "审批失败");
    } finally {
      setSubmitting(false);
    }
  };

  const filtered = items.filter((it) => {
    if (filter === "all") return true;
    if (filter === "double_sign") return it.requires_double_sign;
    if (filter === "rejected") return it.rejected;
    return it.severity === filter;
  });

  const sorted = [...filtered].sort((a, b) => {
    const sev =
      (SEVERITY_ORDER[a.severity || "low"] ?? 9) - (SEVERITY_ORDER[b.severity || "low"] ?? 9);
    if (sev !== 0) return sev;
    const ta = parseUtc(a.created_at)?.valueOf() ?? 0;
    const tb = parseUtc(b.created_at)?.valueOf() ?? 0;
    return ta - tb;
  });

  const criticalCount = items.filter((i) => i.severity === "critical").length;

  const renderOpButton = (_: unknown, r: PendingItem) => {
    if (r.rejected) return <Tag color="red">已拒绝</Tag>;
    if (!myApprovalRole) {
      return (
        <Tooltip title="当前账号角色不参与审批签署">
          <Button size="small" disabled>
            审批
          </Button>
        </Tooltip>
      );
    }
    if (r.approved_roles.includes(myApprovalRole)) {
      return <Tag color="blue">我已签署</Tag>;
    }
    return (
      <Button
        type="primary"
        size="small"
        onClick={() => {
          form.setFieldsValue({ decision: "approved", comment: "" });
          setModal(r);
        }}
      >
        审批
      </Button>
    );
  };

  return (
    <div>
      <Card
        title={
          <Space>
            <span>待审批动作</span>
            <Badge count={items.length} showZero color="orange" />
            {criticalCount > 0 && <Tag color="red">{criticalCount} 个 critical</Tag>}
          </Space>
        }
        extra={
          <Space>
            <Segmented
              size="small"
              value={filter}
              onChange={(v) => setFilter(v as string)}
              options={[
                { label: "全部", value: "all" },
                { label: "critical", value: "critical" },
                { label: "high", value: "high" },
                { label: "需双签", value: "double_sign" },
                { label: "有拒绝", value: "rejected" },
              ]}
            />
            <Button icon={<ReloadOutlined />} size="small" onClick={load}>
              刷新
            </Button>
          </Space>
        }
      >
        {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
        {!myApprovalRole && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message={`当前角色 ${userRole} 无审批权限`}
            description="只能查看待审批列表。审批角色由系统按登录角色映射: analyst→指挥官,approver→审批人,admin→CISO。"
          />
        )}
        {!loading && sorted.length === 0 ? (
          <Empty description="没有待审批动作" />
        ) : (
          <Table<PendingItem>
            rowKey={(r) => `${r.case_id}:${r.action_id}`}
            dataSource={sorted}
            loading={loading}
            size="small"
            pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
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
                render: (v: string | null) =>
                  v ? <Tag color={SEVERITY_COLORS[v]}>{v}</Tag> : <Tag>未研判</Tag>,
              },
              {
                title: "事件摘要",
                dataIndex: "incident_summary",
                ellipsis: true,
                render: (v: string | null) => v || "—",
              },
              { title: "动作", dataIndex: "action_type", width: 130 },
              {
                title: "目标",
                dataIndex: "target",
                width: 160,
                ellipsis: true,
                render: (v) => (
                  <Tooltip title={JSON.stringify(v)}>
                    <code style={{ fontSize: 12 }}>{JSON.stringify(v)}</code>
                  </Tooltip>
                ),
              },
              {
                title: "签名进度",
                key: "progress",
                width: 260,
                render: (_, r) => (
                  <Space direction="vertical" size={2}>
                    <Space wrap size={4}>
                      {r.required_roles.map((role) => {
                        const ok = r.approved_roles.includes(role);
                        return (
                          <Tag
                            key={role}
                            color={ok ? "success" : "default"}
                            icon={ok ? <CheckCircleOutlined /> : <ClockCircleOutlined />}
                          >
                            {ROLE_LABELS[role] || role}
                          </Tag>
                        );
                      })}
                    </Space>
                    <Space size={4}>
                      <Tag color={r.requires_double_sign ? "red" : "default"}>
                        {r.approved_roles.length}/{r.required_roles.length} 已签
                      </Tag>
                      {r.rejected && (
                        <Tag color="red" icon={<ExclamationCircleOutlined />}>
                          有拒绝记录
                        </Tag>
                      )}
                    </Space>
                  </Space>
                ),
              },
              {
                title: "等待时长",
                dataIndex: "created_at",
                width: 100,
                render: (v: string) => (
                  <Tooltip title={formatDateTime(v)}>{fromNow(v)}</Tooltip>
                ),
              },
              {
                title: "操作",
                key: "op",
                width: 90,
                render: renderOpButton,
              },
            ]}
          />
        )}
      </Card>

      <Modal
        title={
          modal
            ? `审批 ${modal.action_type} — Case ${modal.case_id.slice(0, 8)}`
            : "提交审批"
        }
        open={!!modal}
        onOk={submit}
        onCancel={() => setModal(null)}
        confirmLoading={submitting}
      >
        {modal && (
          <>
            <Alert
              type={modal.requires_double_sign ? "warning" : "info"}
              showIcon
              style={{ marginBottom: 16 }}
              message={
                modal.requires_double_sign
                  ? `高危动作,需 ${modal.required_roles.length} 个角色共同签署`
                  : "L2 动作,需人工确认"
              }
              description={
                <Space direction="vertical" size={2}>
                  <span>目标: {JSON.stringify(modal.target)}</span>
                  <span>
                    仍缺角色:{" "}
                    {modal.missing_roles.map((r) => ROLE_LABELS[r] || r).join("、") || "无"}
                  </span>
                </Space>
              }
            />
            <Form form={form} layout="vertical">
              <Form.Item label="审批身份 (来自登录态,服务端校验)">
                <Input
                  disabled
                  value={`${ROLE_LABELS[myApprovalRole || ""] || myApprovalRole || "—"} · ${userRole}`}
                />
              </Form.Item>
              <Form.Item name="decision" label="决定" rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: "approved", label: "批准" },
                    { value: "rejected", label: "拒绝 (Case 将关闭,动作不执行)" },
                    { value: "deferred", label: "延后" },
                  ]}
                />
              </Form.Item>
              <Form.Item name="comment" label="备注">
                <Input.TextArea rows={2} placeholder="决策依据 (留痕用,合规报告会引用)" />
              </Form.Item>
            </Form>
          </>
        )}
      </Modal>
    </div>
  );
}
