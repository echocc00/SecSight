import axios from "axios";

const TOKEN_KEY = "secsight_token";
const ROLE_KEY = "secsight_role";

const client = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

// 请求拦截: 自动带 JWT
client.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截: 401 清 token 跳登录
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(ROLE_KEY);
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);

export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  error?: string;
}

export const auth = {
  login: async (username: string, password: string) => {
    const r = await client.post("/auth/login", { username, password });
    const { access_token, role } = r.data;
    localStorage.setItem(TOKEN_KEY, access_token);
    localStorage.setItem(ROLE_KEY, role);
    return r.data;
  },
  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLE_KEY);
    window.location.href = "/login";
  },
  getMe: () => client.get<ApiResponse>("/auth/me").then((r) => r.data.data),
  getRole: () => localStorage.getItem(ROLE_KEY),
  isLoggedIn: () => !!localStorage.getItem(TOKEN_KEY),
};

export const api = {
  // 告警
  injectAlert: (payload: {
    alert_type: string;
    hostname?: string;
    src_ip?: string;
    dst_ip?: string;
    pid?: number;
  }) => client.post<ApiResponse>("/alerts/inject", payload).then((r) => r.data.data),

  listAlertTypes: () =>
    client.get<ApiResponse<{ types: string[] }>>("/alerts/types").then((r) => r.data.data),

  wazuhWebhook: (alert: Record<string, any>) =>
    client.post<ApiResponse>("/alerts/wazuh-webhook", alert).then((r) => r.data.data),

  // Case
  listCases: (status?: string) =>
    client.get<ApiResponse<any[]>>("/cases", { params: { status } }).then((r) => r.data.data),

  getCase: (caseId: string) =>
    client.get<ApiResponse<any>>(`/cases/${caseId}`).then((r) => r.data.data),

  // 剧本
  listPlaybooks: () =>
    client.get<ApiResponse<any[]>>("/playbooks").then((r) => r.data.data),

  getPlaybook: (id: string) =>
    client.get<ApiResponse<any>>(`/playbooks/${id}`).then((r) => r.data.data),

  // 审批
  listPending: (caseId: string) =>
    client.get<ApiResponse<any[]>>(`/approvals/${caseId}/pending`).then((r) => r.data.data),

  approveAction: (
    caseId: string,
    actionId: string,
    payload: { approver_role: string; approver_user: string; decision: string; comment?: string }
  ) =>
    client
      .post<ApiResponse>(`/approvals/${caseId}/actions/${actionId}/approve`, payload)
      .then((r) => r.data.data),

  // Evidence
  getEvidence: (caseId: string) =>
    client.get<ApiResponse<any>>(`/evidence/${caseId}`).then((r) => r.data.data),

  // 合规报告
  generateReport: (caseId: string, format: "html" | "markdown" = "html") =>
    client.post<ApiResponse>(`/compliance/${caseId}/report`, null, { params: { format } }).then((r) => r.data.data),

  getReportHtml: (caseId: string) =>
    client.get<string>(`/compliance/${caseId}/report`, { responseType: "text" }).then((r) => r.data),

  // 健康与指标
  health: () => client.get("/health").then((r) => r.data),
};
