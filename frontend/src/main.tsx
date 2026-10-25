import React from "react";
import ReactDOM from "react-dom/client";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import "dayjs/locale/zh-cn";
import { Alert, Button, Card } from "antd";
import App from "./App";

// 审批面板用 fromNow 显示等待时长,插件必须在渲染前注册
dayjs.extend(relativeTime);
dayjs.locale("zh-cn");

// 全局错误边界: 懒加载页面渲染异常不能整站白屏
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <Card style={{ margin: 48 }}>
          <Alert
            type="error"
            showIcon
            message="页面渲染出错"
            description={this.state.error.message || String(this.state.error)}
            action={
              <Button size="small" onClick={() => window.location.reload()}>
                刷新页面
              </Button>
            }
          />
        </Card>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
