import { useState } from "react";
import { Card, Form, Input, Button, message, Typography, Tag } from "antd";
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { auth } from "../api/client";

const { Title, Text } = Typography;

const DEMO_USERS = [
  { username: "admin", role: "admin", perms: "全部权限" },
  { username: "analyst", role: "analyst", perms: "案件/告警/剧本" },
  { username: "approver", role: "approver", perms: "审批/执行" },
  { username: "viewer", role: "viewer", perms: "只读" },
];

export default function Login() {
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const onFinish = async (values: { username: string; password: string }) => {
    setLoading(true);
    try {
      const { role } = await auth.login(values.username, values.password);
      message.success(`登录成功 (${role})`);
      nav("/");
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "登录失败");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, #1677ff 0%, #0a2540 100%)",
      }}
    >
      <Card style={{ width: 420, boxShadow: "0 8px 24px rgba(0,0,0,0.2)" }}>
        <Title level={3} style={{ textAlign: "center", marginBottom: 8 }}>
          SecSight
        </Title>
        <Text type="secondary" style={{ display: "block", textAlign: "center", marginBottom: 24 }}>
          AI 安全运维平台
        </Text>
        <Form onFinish={onFinish} size="large" initialValues={{ username: "admin", password: "ChangeMe_123!" }}>
          <Form.Item name="username" rules={[{ required: true, message: "请输入用户名" }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: "请输入密码" }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              登录
            </Button>
          </Form.Item>
        </Form>
        <Card size="small" type="inner" title="演示账号" style={{ marginTop: 8 }}>
          {DEMO_USERS.map((u) => (
            <div key={u.username} style={{ marginBottom: 6, fontSize: 13 }}>
              <Tag color="blue">{u.username}</Tag>
              <Text type="secondary">{u.perms}</Text>
            </div>
          ))}
          <Text type="secondary" style={{ fontSize: 12 }}>
            密码均为 ChangeMe_123!
          </Text>
        </Card>
      </Card>
    </div>
  );
}
