import { Table, Tag, Button, Modal, Form, Select, Input, message, Space, Tooltip } from "antd";
import { CheckCircleOutlined, ClockCircleOutlined } from "@ant-design/icons";
import { useEffect, useState } from "react";
import { api } from "../api/client";

interface PendingAction {
  action_id: string;
  action_type: string;
  target: any;
  autonomy_level: string;
  risk: string;
  requires_double_sign: boolean;
  required_roles: string[];
  approved_roles: string[];
  missing_roles: string[];
  records: any[];
}

interface Props {
  caseId: string;
  actions: any[];
  onApproved: () => void;
}

const AUTONOMY_COLORS: Record<string, string> = {
  L1: "default",
  L2: "orange",
  L3: "blue",
  L4: "cyan",
  L5: "green",
};

const ROLE_LABELS: Record<string, string> = {
  incident_commander: "指挥官",
  approver: "审批人",
  ciso_or_delegate: "CISO",
};

const ROLE_COLORS: Record<string, string> = {
  incident_commander: "blue",
  approver: "geekblue",
  ciso_or_delegate: "purple",
};

export default function ApprovalPanel({ caseId, actions, onApproved }: Props) {
  const [modal, setModal] = useState<{ actionId: string } | null>(null);
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState<PendingAction[]>([]);
  const [loadingPending, setLoadingPending] = useState(false);

  const loadPending = async () => {
    setLoadingPending(true);
    try {
      const data = await api.listPending(caseId);
      setPending(data || []);
    } catch {
      setPending([]);
    } finally {
      setLoadingPending(false);
    }
  };

  useEffect(() => {
    loadPending();
  }, [caseId, actions]);

  // pending 按 action_id 索引,便于查双签进度
  const pendingMap = new Map(pending.map((p) => [p.action_id, p]));

  const submit = async () => {
    const values = await form.validateFields();
    setSubmitting(true);
    try {
      const res = await api.approveAction(caseId, modal!.actionId, values);
      if (res.all_approved) {
        message.success("全部动作已批准,workflow 已恢复执行");
      } else {
        message.success("审批已提交,等待其他角色确认");
      }
      setModal(null);
      form.resetFields();
      await loadPending();
      onApproved();
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "审批失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <Table
        rowKey="action_id"
        dataSource={actions}
        pagination={false}
        loading={loadingPending}
        columns={[
          { title: "动作类型", dataIndex: "action_type" },
          { title: "目标", dataIndex: "target", render: (v) => JSON.stringify(v) },
          {
            title: "自主性",
            dataIndex: "autonomy_level",
            render: (v) => <Tag color={AUTONOMY_COLORS[v]}>{v}</Tag>,
          },
          { title: "风险", dataIndex: "risk" },
          {
            title: "双签",
            dataIndex: "requires_double_sign",
            render: (v) => (v ? <Tag color="red">是</Tag> : "否"),
          },
          {
            title: "审批进度",
            key: "progress",
            render: (_, r) => {
              if (!r.approval_required) return <Tag>无需审批</Tag>;
              const p = pendingMap.get(r.action_id);
              if (!p) return <Tag>待加载</Tag>;
              const approved = p.approved_roles.length;
              const required = p.required_roles.length;
              const done = approved >= required;
              return (
                <Space direction="vertical" size={2} style={{ width: "100%" }}>
                  <Space wrap>
                    {p.required_roles.map((role) => {
                      const ok = p.approved_roles.includes(role);
                      return (
                        <Tooltip key={role} title={ok ? `${ROLE_LABELS[role] || role} 已批准` : `等待 ${ROLE_LABELS[role] || role} 批准`}>
                          <Tag
                            color={ok ? "success" : ROLE_COLORS[role] || "default"}
                            icon={ok ? <CheckCircleOutlined /> : <ClockCircleOutlined />}
                          >
                            {ROLE_LABELS[role] || role}
                          </Tag>
                        </Tooltip>
                      );
                    })}
                  </Space>
                  <Tag color={done ? "green" : "orange"}>
                    {approved}/{required} 已签 {done ? "· 通过" : "· 待签"}
                  </Tag>
                </Space>
              );
            },
          },
          {
            title: "操作",
            key: "op",
            render: (_, r) => {
              if (!r.approval_required) return "—";
              const p = pendingMap.get(r.action_id);
              const done = p ? p.approved_roles.length >= p.required_roles.length : false;
              if (done) return <Tag color="green">已通过</Tag>;
              return (
                <Button type="primary" size="small" onClick={() => setModal({ actionId: r.action_id })}>
                  审批
                </Button>
              );
            },
          },
        ]}
      />
      <Modal
        title="提交 L2 审批"
        open={!!modal}
        onOk={submit}
        onCancel={() => setModal(null)}
        confirmLoading={submitting}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="approver_role" label="审批角色" rules={[{ required: true }]}>
            <Select
              options={[
                { value: "incident_commander", label: "Incident Commander (指挥官)" },
                { value: "approver", label: "Approver (审批人)" },
                { value: "ciso_or_delegate", label: "CISO / Delegate" },
              ]}
            />
          </Form.Item>
          <Form.Item name="approver_user" label="审批人" rules={[{ required: true }]}>
            <Input placeholder="用户名" />
          </Form.Item>
          <Form.Item name="decision" label="决定" rules={[{ required: true }]}>
            <Select
              options={[
                { value: "approved", label: "批准" },
                { value: "rejected", label: "拒绝" },
                { value: "deferred", label: "延后" },
              ]}
            />
          </Form.Item>
          <Form.Item name="comment" label="备注">
            <Input.TextArea rows={2} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
