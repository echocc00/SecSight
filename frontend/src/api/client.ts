import axios from "axios";

const client = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  error?: string;
}

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

  // Case
  listCases: (status?: string) =>
    client
      .get<ApiResponse<any[]>>("/cases", { params: { status } })
      .then((r) => r.data.data),

  getCase: (caseId: string) =>
    client.get<ApiResponse<any>>(`/cases/${caseId}`).then((r) => r.data.data),

  // 剧本
  listPlaybooks: () =>
    client.get<ApiResponse<any[]>>("/playbooks").then((r) => r.data.data),

  // 审批
  listPending: (caseId: string) =>
    client
      .get<ApiResponse<any[]>>(`/approvals/${caseId}/pending`)
      .then((r) => r.data.data),

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

  // 健康
  health: () => client.get("/health").then((r) => r.data),
};
