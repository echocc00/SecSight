import { Table, Tag, Button, Modal, Form, Select, Input, message } from "antd";
import { useState } from "react";
import { api } from "../api/client";

interface Props {
  caseId: string;
  actions: any[];
  approvals: Record<string, any>;
  onApproved: () => void;
}

const AUTONOMY_COLORS: Record<string, string> = {
  L1: "default",
  L2: "orange",
  L3: "blue",
  L4: "cyan",
  L5: "green",
};

export default function ApprovalPanel({ caseId, actions, approvals, onApproved }: Props) {
  const [modal, setModal] = useState<{ actionId: string } | null>(null);
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);

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
            title: "审批状态",
            key: "approval",
            render: (_, r) => {
              const a = approvals[r.action_id];
              return a ? <Tag color={a.decision === "approved" ? "green" : "red"}>{a.decision}</Tag> : <Tag>待审批</Tag>;
            },
          },
          {
            title: "操作",
            key: "op",
            render: (_, r) =>
              r.approval_required && (!approvals[r.action_id] || approvals[r.action_id].decision !== "approved") ? (
                <Button type="primary" size="small" onClick={() => setModal({ actionId: r.action_id })}>
                  审批
                </Button>
              ) : (
                "—"
              ),
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
                { value: "incident_commander", label: "Incident Commander" },
                { value: "approver", label: "Approver" },
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
