import React from "react";
import ReactDOM from "react-dom/client";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import "dayjs/locale/zh-cn";
import App from "./App";

// 审批面板用 fromNow 显示等待时长,插件必须在渲染前注册
dayjs.extend(relativeTime);
dayjs.locale("zh-cn");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
