import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import { Layout, Menu, theme, Dropdown, Space, Tag, Spin, Badge } from "antd";
import {
  DashboardOutlined,
  AlertOutlined,
  BookOutlined,
  LogoutOutlined,
  UserOutlined,
  RobotOutlined,
  SearchOutlined,
  SafetyCertificateOutlined,
  AuditOutlined,
} from "@ant-design/icons";
import { useState, useEffect, Suspense, lazy, useCallback } from "react";
import { auth, api } from "./api/client";
import { connect as connectWS, disconnect as disconnectWS, onEvent } from "./lib/ws";

const { Header, Sider, Content } = Layout;

// 路由懒加载 (按需加载各页面,减小首屏 bundle)
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Cases = lazy(() => import("./pages/Cases"));
const CaseDetail = lazy(() => import("./pages/CaseDetail"));
const Playbooks = lazy(() => import("./pages/Playbooks"));
const Agents = lazy(() => import("./pages/Agents"));
const AlertSearch = lazy(() => import("./pages/AlertSearch"));
const Approvals = lazy(() => import("./pages/Approvals"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Login = lazy(() => import("./pages/Login"));

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  if (!auth.isLoggedIn()) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  const { token } = theme.useToken();
  const [role, setRole] = useState<string | null>(auth.getRole());
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    setRole(auth.getRole());
  }, []);

  // 侧边栏待审批角标: WS 实时推送优先,30s 轮询兜底 (WS 断线也能恢复)
  const refreshBadge = useCallback((silent = true) => {
    if (!auth.isLoggedIn()) return;
    api
      .listAllPending()
      .then((d) => setPendingCount(d.count || 0))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!auth.isLoggedIn()) {
      disconnectWS();
      return;
    }
    connectWS();
    refreshBadge();

    // WS 事件驱动角标刷新 (新告警/审批提交/案例闭环都会变待办数)
    const cleanups = [
      onEvent("case_created", () => refreshBadge()),
      onEvent("approval_submitted", () => refreshBadge()),
      onEvent("case_resolved", () => refreshBadge()),
      onEvent("alert_deduped", () => refreshBadge()),
    ];
    const timer = setInterval(() => refreshBadge(), 30_000);
    return () => {
      cleanups.forEach((unsub) => unsub());
      clearInterval(timer);
    };
  }, [refreshBadge]);

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
                        key: "approvals",
                        icon: <SafetyCertificateOutlined />,
                        label: (
                          <Link to="/approvals">
                            <Space size={6}>
                              审批
                              {pendingCount > 0 && (
                                <Badge count={pendingCount} size="small" color="orange" />
                              )}
                            </Space>
                          </Link>
                        ),
                      },
                      {
                        key: "alert-search",
                        icon: <SearchOutlined />,
                        label: <Link to="/alerts/search">告警搜索</Link>,
                      },
                      {
                        key: "playbooks",
                        icon: <BookOutlined />,
                        label: <Link to="/playbooks">剧本</Link>,
                      },
                      {
                        key: "compliance",
                        icon: <AuditOutlined />,
                        label: <Link to="/compliance">合规</Link>,
                      },
                      {
                        key: "agents",
                        icon: <RobotOutlined />,
                        label: <Link to="/agents">Agent</Link>,
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
                    <Suspense fallback={<div style={{ textAlign: "center", padding: 100 }}><Spin size="large" /></div>}>
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/cases" element={<Cases />} />
                        <Route path="/cases/:caseId" element={<CaseDetail />} />
                        <Route path="/approvals" element={<Approvals />} />
                        <Route path="/compliance" element={<Compliance />} />
                        <Route path="/alerts/search" element={<AlertSearch />} />
                        <Route path="/playbooks" element={<Playbooks />} />
                        <Route path="/agents" element={<Agents />} />
                      </Routes>
                    </Suspense>
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
