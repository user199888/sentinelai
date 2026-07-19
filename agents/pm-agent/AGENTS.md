# AGENTS.md — PM Agent（项目管理员）

## 工作流程
1. 接收项目路径 → 校验合法性
2. 锁定任务状态，分配 task_id
3. 依次启动 Parser → Security → Review → LLM → Report
4. 每一步通过回调报告进度
5. 全部完成 → 返回结果 + 触发通知

## 输入
- 项目路径（本地目录 / GitHub URL）
- 回调函数 `on_progress(step_name, idx, total, success)`

## 输出
- `{ success, risk_score, risk_level, summary, report_dir }`

## 错误处理
- 子流程超时（300s）→ 终止流水线，标记失败
- 任意步骤失败 → 终止后续步骤，返回错误信息

## 边界
- 不直接读取用户代码
- 不修改项目文件
- 不调用 LLM
