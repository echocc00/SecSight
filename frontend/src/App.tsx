import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { Layout, Menu, theme } from "antd";
import {
  DashboardOutlined,
  AlertOutlined,
  BookOutlined,
} from "@ant-design/icons";
import Dashboard from "./pages/Dashboard";
import Cases from "./pages/Cases";
import CaseDetail from "./pages/CaseDetail";
import Playbooks from "./pages/Playbooks";

const { Header, Sider, Content } = Layout;

export default function App() {
  const { token } = theme.useToken();

  return (
    <BrowserRouter>
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
              fontSize: 16,
              fontWeight: 600,
            }}
          >
            AI 安全运维平台 — SecSight
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
    </BrowserRouter>
  );
}
