# 系统架构、前端交互逻辑与后端开发指南

本文档详细说明了本系统的**前端交互逻辑**以及**后端编辑与对接实施指南**，帮助前端与后端工程师快速理解系统设计并完成端到端开发。

---

## 一、 系统架构与前端交互逻辑

本系统是一个**网络拓扑智能诊断与 AI 集成管理平台**，集成了设备可视化拓扑、交互式故障诊断、知识库检索以及类似 **Dify** 的大模型 API Key 集成中心。

### 1. 核心视图与导航结构 (Layout & Navigation)
- **顶部 Header**：
  - **Dify API Key 集成**：快捷打开模型与插件集成中心。
  - **重新获取拓扑**：触发全网节点状态与链路的实时刷新。
  - **运行与审计日志状态**：实时显示网络连通性状态指示灯及审计日志摘要。
  - **中英文语言切换**：支持中文 (`zh`) / 英文 (`en`) 双语动态切换。
- **左侧 Collapsible 侧边栏 Sider**：
  - `1` **网络拓扑 (Topology)**：查看实时设备节点、链路流量状态与高亮分析。
  - `2` **Dify 集成中心 (Marketplace)**：全功能 API Key 载入器与模型供应商配置。
  - `3` **知识库 (Knowledge Base)**：管理运维文档、故障 SOP 与 RAG 索引。
  - `4` **诊断与报告 (Diagnostics)**：查看导出的诊断报告与系统健康度指标。
  - `5` **系统设置 (Settings)**：配置轮询间隔、AI 敏感度与代理网关。

---

### 2. Dify 集成中心 (Model Marketplace) 交互逻辑
针对大模型与第三方 API Key 的管理，实现了高度复刻 Dify 体验的插件/模型市场：
1. **居中与独立滚动 (Sticky Header + Scrollable Body)**：
   - 弹窗采用垂直居中尺寸 (`width: 1080px`, `max-h: 82vh`)。
   - **顶部蓝色 Banner 与分类 Tabs**（所有集成 / 模型 / 已配置 / 工具 / 数据源 / Agent 策略）**固定吸顶**，向下滚动时依然保持分类切换可用。
   - **卡片内容区域独立滚动**，不会导致页面整体拉长。
2. **多供应商覆盖**：
   - 内置 14+ 模组（DeepSeek、通义千问 DashScope、火山方舟 Ark、Ollama 本地引擎、OpenAI、硅基流动 SiliconFlow、腾讯混元、Google Gemini、智谱 AI、OpenRouter、Anthropic Claude、Azure OpenAI、MiniMax 等）。
3. **API Key 配置与测试 Drawer**：
   - 点击“配置并安装”或“重置 Key”打开配置对话框。
   - 用户可录入 `API Key`（支持密码显隐）、`Base URL`（自定义端点/代理）以及`默认模型名称`。
   - 点击**“测试 API 连通性”**触发后端或本地 Ping 校验，实时反馈延迟与响应状态。
   - 保存后自动持久化存储至 `localStorage` (`dify_model_configs`) 并同步至全局 AI Agent 上下文。

---

### 3. 设备拓扑与故障诊断交互
1. **设备节点点击**：点击拓扑图中的设备节点（核心交换机、路由器、防火墙、服务器等），从右侧滑出 **设备详情抽屉 (Device Drawer)**。
2. **设备诊断与控制**：
   - 查看 CPU、内存、温度、丢包率、网络延时等实时指标。
   - 发起**一键 AI 故障诊断**，自动调用已配置的 LLM 模型分析异常。
   - 执行**端口封堵 / 链路切断 / 抓包抓取**等模拟操作，实时写入审计日志 (Audit Log)。

---

### 4. AI Agent 智能助手交互
- 右下角浮动 Agent 对话框支持对话交互。
- 提问时自动注入当前选中的设备节点状态、告警日志及已配置的第三方 LLM 模型上下文，生成可执行的排障建议。

---

## 二、 后端编辑与对接开发指南

为了将目前前端的纯 Client/Mock 数据升级为真正的生产级 Full-Stack 全栈系统，后端开发请遵照以下规范进行扩展与编辑。

### 1. 推荐技术栈 (Backend Stack)
- **Node.js**: TypeScript + Express / Fastify (适合与 Vite 统一打包部署)
- **Python**: FastAPI / Flask (适合与 PyTorch/LangChain/Dify SDK 深度交互)
- **数据库**: PostgreSQL / MySQL / Firestore (存储设备节点、审计日志与 API Key 配置)

---

### 2. 必须实现的 API 接口契约 (RESTful API Contracts)

#### 2.1 拓扑与设备接口 (Topology & Device)
| HTTP Method | API Route | 说明 | 请求参数 | 返回格式示例 |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/topology` | 获取全网最新节点与链路 | 无 | `{ nodes: Node[], edges: Edge[] }` |
| `POST` | `/api/topology/fetch` | 重新扫描全网设备 | `{ forceRefresh: boolean }` | `{ success: true, timestamp: string }` |
| `GET` | `/api/device/:id` | 获取特定设备实时指标 | `id` (path) | `{ id: string, metrics: DeviceMetrics }` |
| `POST` | `/api/device/:id/diagnose` | 深度 AI 诊断特定设备 | `{ providerId?: string }` | `{ report: string, severity: 'high' \| 'low' }` |

#### 2.2 大模型 Provider & API Key 管理接口
| HTTP Method | API Route | 说明 | 请求参数 | 返回格式示例 |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/models/providers` | 获取所有支持的 Provider 列表及当前用户配置状态 | 无 | `ProviderConfig[]` |
| `POST` | `/api/models/config` | 保存或更新特定 Provider 的 API Key 与 Base URL | `{ providerId, apiKey, endpoint, model }` | `{ success: true }` |
| `POST` | `/api/models/test-connection` | 测试特定 API Key 和 Base URL 的联通性 | `{ providerId, apiKey, endpoint, model }` | `{ success: boolean, latencyMs: number, message: string }` |

#### 2.3 RAG 知识库与 Agent 对话接口
| HTTP Method | API Route | 说明 | 请求参数 | 返回格式示例 |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/agent/chat` | AI 排障助手对话 (带拓扑与模型上下文) | `{ message: string, contextDeviceId?: string, modelConfig?: object }` | `{ reply: string, suggestedActions?: string[] }` |
| `POST` | `/api/kb/upload` | 上传运维文档/SOP 文件并进行向量切块 | `FormData` (file, category) | `{ docId: string, chunks: number }` |

---

### 3. 后端编辑实施步骤 (Express + TypeScript 示例)

若使用 Node.js / Express，请直接编辑或新建根目录下的 `server.ts`：

#### 步骤 1：添加与修改 `server.ts`
```typescript
import express from 'express';
import path from 'path';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// 1. 获取全网拓扑数据
app.get('/api/topology', (req, res) => {
  // 从 PostgreSQL / Redis 中读取最新的设备节点与链路
  res.json({
    nodes: [/* ... 真实设备节点数据 ... */],
    edges: [/* ... 真实链路数据 ... */]
  });
});

// 2. 测试第三方大模型 API Key 连通性
app.post('/api/models/test-connection', async (req, res) => {
  const { providerId, apiKey, endpoint, model } = req.body;
  const startTime = Date.now();

  try {
    // 针对不同的 Provider 发起轻量级 Ping / models 列表请求
    let targetUrl = endpoint || 'https://api.openai.com/v1';
    if (providerId === 'deepseek') targetUrl = 'https://api.deepseek.com/v1/models';
    
    // 发起实际 HTTP 请求验证 API Key
    const response = await fetch(targetUrl, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });

    const latencyMs = Date.now() - startTime;
    if (response.ok || response.status === 404) {
      return res.json({ success: true, latencyMs, message: '连通成功！' });
    } else {
      return res.status(400).json({ success: false, message: `认证失败: HTTP ${response.status}` });
    }
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

// 3. 智能 Agent 诊断接口 (代理调用用户配置的 LLM)
app.post('/api/agent/chat', async (req, res) => {
  const { message, modelConfig } = req.body;
  // 此处根据用户选定的 Provider (如 DeepSeek / Gemini) 转发大模型请求，保证 API Key 不经过浏览器前端
  res.json({
    reply: `已收到您的排障指令: "${message}"。根据实时拓扑，交换机 SW-Core-01 端口 4 存在 8.2% 丢包率，建议检查光纤衰减。`
  });
});

// 生产环境静态资源托管与 Vite 开发中间件
if (process.env.NODE_ENV === 'production') {
  const distPath = path.join(process.cwd(), 'dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
```

#### 步骤 2：更新 `package.json` 启动脚本
如果新建或启用了 `server.ts` 后端，请确保 `package.json` 中的 `scripts` 配置如下：
```json
{
  "scripts": {
    "dev": "tsx server.ts",
    "build": "vite build && esbuild server.ts --bundle --platform=node --format=cjs --packages=external --outfile=dist/server.cjs",
    "start": "node dist/server.cjs"
  }
}
```

---

## 三、 总结与最佳实践

1. **API 密钥安全 (Security)**：前端在 Dify 集成中心录入的 API Key 在客户端发起连通性测试后，生产环境应推荐代理存入后端的加密存储（如 PostgreSQL `pgcrypto` 或 环境变量），不要在浏览器 HTML/JS 静态包中明文硬编码。
2. **模型兼容性 (Compatibility)**：由于采用了兼容 OpenAI / Dify 接口标准的形态，支持任意 OpenAI API 兼容的中转网关或 LM Studio / Ollama 本地推理服务。
3. **前端代码组件位置**：
   - 拓扑主界面：`/src/App.tsx`
   - Dify 集成中心：`/src/components/ModelMarketplaceModal.tsx`
   - 设备抽屉：`/src/components/DeviceDrawer.tsx`
   - 知识库弹窗：`/src/components/KnowledgeBaseModal.tsx`
