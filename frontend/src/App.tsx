import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import { Layout, Menu, theme, Dropdown, Space, Tag } from "antd";
import {
  DashboardOutlined,
  AlertOutlined,
  BookOutlined,
  LogoutOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import Cases from "./pages/Cases";
import CaseDetail from "./pages/CaseDetail";
import Playbooks from "./pages/Playbooks";
import Login from "./pages/Login";
import { auth } from "./api/client";

const { Header, Sider, Content } = Layout;

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  if (!auth.isLoggedIn()) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  const { token } = theme.useToken();
  const [role, setRole] = useState<string | null>(auth.getRole());

  useEffect(() => {
    setRole(auth.getRole());
  }, []);

  const userMenu = {
    items: [
      {
        key: "logout",
        icon: <LogoutOutlined />,
        label: "退出登录",
        onClick: () => auth.logout(),
      },
    ],
  };

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout style={{ minHeight: "100vh" }}>
                <Sider collapsible style={{ background: token.colorBgContainer }}>
                  <div
                    style={{
                      height: 48,
                      margin: 16,
                      color: token.colorPrimary,
                      fontWeight: 700,
                      fontSize: 18,
                      textAlign: "center",
                      lineHeight: "48px",
                    }}
                  >
                    SecSight
                  </div>
                  <Menu
                    mode="inline"
                    defaultSelectedKeys={["dashboard"]}
                    items={[
                      {
                        key: "dashboard",
                        icon: <DashboardOutlined />,
                        label: <Link to="/">总览</Link>,
                      },
                      {
                        key: "cases",
                        icon: <AlertOutlined />,
                        label: <Link to="/cases">案件</Link>,
                      },
                      {
                        key: "playbooks",
                        icon: <BookOutlined />,
                        label: <Link to="/playbooks">剧本</Link>,
                      },
                    ]}
                  />
                </Sider>
                <Layout>
                  <Header
                    style={{
                      background: token.colorBgContainer,
                      padding: "0 24px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <span style={{ fontSize: 16, fontWeight: 600 }}>
                      AI 安全运维平台 — SecSight
                    </span>
                    <Dropdown menu={userMenu} placement="bottomRight">
                      <Space style={{ cursor: "pointer" }}>
                        <UserOutlined />
                        <span>{role || "user"}</span>
                        {role && <Tag color="blue">{role}</Tag>}
                      </Space>
                    </Dropdown>
                  </Header>
                  <Content style={{ margin: 24, padding: 24, background: token.colorBgContainer }}>
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/cases" element={<Cases />} />
                      <Route path="/cases/:caseId" element={<CaseDetail />} />
                      <Route path="/playbooks" element={<Playbooks />} />
                    </Routes>
                  </Content>
                </Layout>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
