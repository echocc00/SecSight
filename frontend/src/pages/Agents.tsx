import { useEffect, useState } from "react";
import { Card, Col, Row, Tag, Table, Button, Modal, InputNumber, message, Tabs, Descriptions, Progress, Spin } from "antd";
import { ThunderboltOutlined, ReloadOutlined, TeamOutlined } from "@ant-design/icons";
import { api } from "../api/client";

interface AgentInfo {
  name: string;
  role: string;
  llm_tier: string;
  description: string;
}

interface ProactiveResult {
  agent: string;
  result: Record<string, any>;
}

export default function Agents() {
  const [reactive, setReactive] = useState<AgentInfo[]>([]);
  const [proactive, setProactive] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const [resultModal, setResultModal] = useState<ProactiveResult | null>(null);
  const [timeWindow, setTimeWindow] = useState(24);

  const load = async () => {
    setLoading(true);
    try {
      const [r, p] = await Promise.all([api.listAgents(), api.listProactiveAgents()]);
      setReactive(r || []);
      setProactive(p || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const runProactive = async (name: string) => {
    setRunning(name);
    try {
      const res = await api.runProactiveAgent(name, timeWindow);
      setResultModal({ agent: name, result: res });
      message.success(`${name} 执行完成`);
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "执行失败");
    } finally {
      setRunning(null);
    }
  };

  const tierColor: Record<string, string> = {
    tier1: "blue", tier2: "green", tier3: "purple",
  };

  return (
    <div>
      <Tabs
        items={[
          {
            key: "reactive",
            label: <span><TeamOutlined /> 响应 Agent ({reactive.length})</span>,
            children: (
              <Card
                title="Reactive Agent (7 个,响应告警触发)"
                extra={<Button icon={<ReloadOutlined />} onClick={load} size="small">刷新</Button>}
              >
                <Spin spinning={loading}>
                  <Row gutter={[16, 16]}>
                    {reactive.map((a) => (
                      <Col span={8} key={a.name}>
                        <Card size="small" hoverable>
                          <Card.Meta
                            title={
                              <span>
                                {a.role}
                                <Tag color={tierColor[a.llm_tier]} style={{ marginLeft: 8 }}>{a.llm_tier}</Tag>
                              </span>
                            }
                            description={a.description}
                          />
                          <div style={{ marginTop: 8, fontSize: 12, color: "#999" }}>{a.name}</div>
                        </Card>
                      </Col>
                    ))}
                  </Row>
                </Spin>
              </Card>
            ),
          },
          {
            key: "proactive",
            label: <span><ThunderboltOutlined /> 主动 Agent ({proactive.length})</span>,
            children: (
              <Card
                title="Proactive Agent (4 个,主动防御,可手动触发)"
                extra={
                  <span>
                    时间窗口:
                    <InputNumber
                      size="small"
                      style={{ width: 80, marginLeft: 8 }}
                      min={1}
                      max={168}
                      value={timeWindow}
                      onChange={(v) => setTimeWindow(v || 24)}
                      addonAfter="h"
                    />
                  </span>
                }
              >
                <Spin spinning={loading}>
                  <Row gutter={[16, 16]}>
                    {proactive.map((a) => (
                      <Col span={12} key={a.name}>
                        <Card size="small">
                          <Card.Meta
                            title={
                              <span>
                                {a.role}
                                <Tag color={tierColor[a.llm_tier]} style={{ marginLeft: 8 }}>{a.llm_tier}</Tag>
                              </span>
                            }
                            description={a.description}
                          />
                          <div style={{ marginTop: 12 }}>
                            <Button
                              type="primary"
                              size="small"
                              icon={<ThunderboltOutlined />}
                              loading={running === a.name}
                              onClick={() => runProactive(a.name)}
                            >
                              执行
                            </Button>
                          </div>
                        </Card>
                      </Col>
                    ))}
                  </Row>
                </Spin>
              </Card>
            ),
          },
        ]}
      />

      <Modal
        title={resultModal ? `Proactive Agent 执行结果 — ${resultModal.agent}` : ""}
        open={!!resultModal}
        onCancel={() => setResultModal(null)}
        footer={null}
        width={700}
      >
        {resultModal && (
          <pre style={{ maxHeight: 400, overflow: "auto", fontSize: 12, background: "#f6f8fa", padding: 12 }}>
            {JSON.stringify(resultModal.result, null, 2)}
          </pre>
        )}
      </Modal>
    </div>
  );
}
