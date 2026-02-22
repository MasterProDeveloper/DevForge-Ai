/**********************************************************************
 * DEVFORGE AI - SINGLE FILE MONOLITH
 * Includes: Auth, RBAC, Multi-Tenant, AI Router, Projects, Workspaces,
 * Files, Deployments, Analytics, Billing, Plugins, Multi-Model AI,
 * Realtime Collaboration, WebSockets, Deployment, Stripe, GitHub.
 **********************************************************************/
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuid } from "uuid";
import http from "http";
import { WebSocketServer } from "ws";
import dotenv from "dotenv";

dotenv.config();

// ======================================================
// CONFIG
// ======================================================
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "devforge-secret";

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "10mb" }));
app.use(morgan("dev"));

// ======================================================
// IN-MEMORY DATABASE
// ======================================================
const db: any = {
  users: {},
  workspaces: {},
  projects: {},
  files: {},
  deployments: {},
  analytics: {},
  billing: {},
  integrations: {},
  api_keys: {},
  models: {},
  logs: {},
  templates: {},
  plugins: {},
  collaborators: {},
  environment_variables: {}
};

// ======================================================
// MIDDLEWARE
// ======================================================
function authenticate(req: any, res: any, next: any) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(role: string) {
  return (req: any, res: any, next: any) => {
    if (req.user.role !== role) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

function rateLimiter(req: any, res: any, next: any) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 min
  const limit = 100;
  if (!db.analytics.rateMap) db.analytics.rateMap = {};
  if (!db.analytics.rateMap[ip]) db.analytics.rateMap[ip] = [];
  db.analytics.rateMap[ip] = db.analytics.rateMap[ip].filter((t: number) => now - t < windowMs);
  if (db.analytics.rateMap[ip].length >= limit) return res.status(429).json({ error: "Too many requests" });
  db.analytics.rateMap[ip].push(now);
  next();
}

app.use(rateLimiter);

// ======================================================
// AUTH ROUTES
// ======================================================
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });
  const existing = Object.values(db.users).find((u: any) => u.email === email);
  if (existing) return res.status(400).json({ error: "User already exists" });
  const hashed = await bcrypt.hash(password, 10);
  const id = uuid();
  db.users[id] = { id, email, password: hashed, role: "owner" };
  res.json({ success: true, id });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = Object.values(db.users).find((u: any) => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// ======================================================
// USER & WORKSPACE CRUD
// ======================================================
app.post("/api/workspaces", authenticate, (req, res) => {
  const { name } = req.body;
  const id = uuid();
  db.workspaces[id] = { id, name, ownerId: req.user.id, members: [req.user.id] };
  res.json(db.workspaces[id]);
});

app.get("/api/workspaces", authenticate, (req, res) => {
  const workspaces = Object.values(db.workspaces).filter((w: any) => w.members.includes(req.user.id));
  res.json(workspaces);
});

// ======================================================
// PROJECT CRUD
// ======================================================
app.post("/api/projects", authenticate, (req, res) => {
  const { name, workspaceId } = req.body;
  if (!db.workspaces[workspaceId]) return res.status(400).json({ error: "Workspace not found" });
  const id = uuid();
  db.projects[id] = { id, name, workspaceId, files: {}, createdAt: Date.now() };
  res.json(db.projects[id]);
});

app.get("/api/projects/:workspaceId", authenticate, (req, res) => {
  const projects = Object.values(db.projects).filter((p: any) => p.workspaceId === req.params.workspaceId);
  res.json(projects);
});

// ======================================================
// FILES CRUD
// ======================================================
app.post("/api/files", authenticate, (req, res) => {
  const { projectId, path, content } = req.body;
  if (!db.projects[projectId]) return res.status(400).json({ error: "Project not found" });
  const id = uuid();
  db.projects[projectId].files[id] = { id, path, content, updatedAt: Date.now() };
  res.json(db.projects[projectId].files[id]);
});

app.get("/api/files/:projectId", authenticate, (req, res) => {
  const project = db.projects[req.params.projectId];
  if (!project) return res.status(400).json({ error: "Project not found" });
  res.json(Object.values(project.files));
});

// ======================================================
// AI MULTI-MODEL ROUTER (Instant Switching)
// ======================================================
async function openAIProvider(model: string, prompt: string) {
  return `OpenAI ${model} output: ${prompt}`;
}
async function anthropicProvider(model: string, prompt: string) {
  return `Anthropic ${model} output: ${prompt}`;
}
async function localProvider(model: string, prompt: string) {
  return `Local ${model} output: ${prompt}`;
}

async function routeModel(model: string, prompt: string) {
  if (model.startsWith("openai")) return openAIProvider(model, prompt);
  if (model.startsWith("anthropic")) return anthropicProvider(model, prompt);
  if (model.startsWith("local")) return localProvider(model, prompt);
  throw new Error("Unsupported model");
}

app.post("/api/ai/generate", authenticate, async (req, res) => {
  const { model, prompt } = req.body;
  if (!model || !prompt) return res.status(400).json({ error: "Model & prompt required" });
  const output = await routeModel(model, prompt);
  res.json({ model, output });
});

// ======================================================
// SERVER + WEBSOCKET FOR REALTIME COLLAB
// ======================================================
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on("connection", (ws: any) => {
  ws.on("message", (msg: any) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === "join") ws.projectId = data.projectId;
      else if (data.type === "file-update") {
        wss.clients.forEach(client => {
          if (client.readyState === 1 && client.projectId === ws.projectId) {
            client.send(JSON.stringify({ type: "file-update", path: data.path, content: data.content }));
          }
        });
      }
    } catch (err) {}
  });
});

server.listen(PORT, () => console.log(`🚀 DevForge AI running on port ${PORT}`));

/**********************************************************************
 * DEVFORGE AI - SINGLE FILE MONOLITH
 * CHUNK 2: Deployments, Billing, Analytics, Plugins, Templates,
 * Environment Variables, AI Generation History
 **********************************************************************/

// ======================================================
// DEPLOYMENTS CRUD + PLACEHOLDER
// ======================================================
app.post("/api/deployments", authenticate, (req, res) => {
  const { projectId, provider } = req.body;
  if (!db.projects[projectId]) return res.status(400).json({ error: "Project not found" });
  const id = uuid();
  const deployment = {
    id,
    projectId,
    provider: provider || "vercel",
    status: "pending",
    logs: [],
    createdAt: Date.now()
  };
  db.deployments[id] = deployment;

  // Simulate deployment log streaming
  let count = 0;
  const interval = setInterval(() => {
    if (count >= 5) {
      deployment.status = "success";
      clearInterval(interval);
    } else {
      deployment.logs.push(`Step ${count + 1}: deploying...`);
      count++;
    }
  }, 500);

  res.json(deployment);
});

app.get("/api/deployments/:projectId", authenticate, (req, res) => {
  const deployments = Object.values(db.deployments).filter((d: any) => d.projectId === req.params.projectId);
  res.json(deployments);
});

// ======================================================
// STRIPE BILLING PLACEHOLDER
// ======================================================
app.post("/api/billing/create-customer", authenticate, (req, res) => {
  const { plan } = req.body;
  const id = uuid();
  db.billing[id] = { id, userId: req.user.id, plan: plan || "free", createdAt: Date.now(), usage: 0 };
  res.json(db.billing[id]);
});

app.post("/api/billing/record-usage", authenticate, (req, res) => {
  const { billingId, amount } = req.body;
  if (!db.billing[billingId]) return res.status(400).json({ error: "Billing record not found" });
  db.billing[billingId].usage += amount;
  res.json({ success: true, usage: db.billing[billingId].usage });
});

// ======================================================
// ANALYTICS + USAGE TRACKING
// ======================================================
app.post("/api/analytics/event", authenticate, (req, res) => {
  const { type, projectId } = req.body;
  const id = uuid();
  db.analytics[id] = { id, userId: req.user.id, type, projectId, timestamp: Date.now() };
  res.json({ success: true });
});

app.get("/api/analytics/project/:projectId", authenticate, (req, res) => {
  const events = Object.values(db.analytics).filter((e: any) => e.projectId === req.params.projectId);
  res.json(events);
});

// ======================================================
// PLUGINS + TEMPLATES
// ======================================================
app.post("/api/plugins", authenticate, (req, res) => {
  const { name, code } = req.body;
  const id = uuid();
  db.plugins[id] = { id, name, code, createdBy: req.user.id, createdAt: Date.now() };
  res.json(db.plugins[id]);
});

app.get("/api/plugins", authenticate, (req, res) => {
  res.json(Object.values(db.plugins));
});

app.post("/api/templates", authenticate, (req, res) => {
  const { name, structure } = req.body;
  const id = uuid();
  db.templates[id] = { id, name, structure, createdBy: req.user.id, createdAt: Date.now() };
  res.json(db.templates[id]);
});

app.get("/api/templates", authenticate, (req, res) => {
  res.json(Object.values(db.templates));
});

// ======================================================
// ENVIRONMENT VARIABLES
// ======================================================
app.post("/api/env", authenticate, (req, res) => {
  const { projectId, key, value } = req.body;
  if (!db.projects[projectId]) return res.status(400).json({ error: "Project not found" });
  const id = uuid();
  db.environment_variables[id] = { id, projectId, key, value, createdBy: req.user.id };
  res.json(db.environment_variables[id]);
});

app.get("/api/env/:projectId", authenticate, (req, res) => {
  const envs = Object.values(db.environment_variables).filter((e: any) => e.projectId === req.params.projectId);
  res.json(envs);
});

// ======================================================
// AI GENERATION HISTORY
// ======================================================
app.get("/api/ai/history/:projectId", authenticate, (req, res) => {
  if (!db.projects[req.params.projectId]) return res.status(400).json({ error: "Project not found" });
  if (!db.projects[req.params.projectId].aiHistory) db.projects[req.params.projectId].aiHistory = [];
  res.json(db.projects[req.params.projectId].aiHistory);
});

app.post("/api/ai/history", authenticate, async (req, res) => {
  const { projectId, model, prompt, output } = req.body;
  if (!db.projects[projectId]) return res.status(400).json({ error: "Project not found" });
  if (!db.projects[projectId].aiHistory) db.projects[projectId].aiHistory = [];
  const entry = { id: uuid(), model, prompt, output, createdAt: Date.now() };
  db.projects[projectId].aiHistory.push(entry);
  res.json(entry);
});

// ======================================================
// REAL-TIME DEPLOYMENT LOGS (WEBSOCKET INTEGRATION)
// ======================================================
function broadcastDeploymentUpdate(deploymentId: string, message: string) {
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId && db.deployments[deploymentId].projectId === client.projectId) {
      client.send(JSON.stringify({ type: "deployment-log", deploymentId, message }));
    }
  });
}

// Simulate logs for all deployments every 1s
setInterval(() => {
  Object.values(db.deployments).forEach((d: any) => {
    if (d.status === "pending") {
      const log = `Deploy step at ${new Date().toISOString()}`;
      d.logs.push(log);
      broadcastDeploymentUpdate(d.id, log);
      if (d.logs.length >= 5) d.status = "success";
    }
  });
}, 1000);

/**********************************************************************
 * DEVFORGE AI - SINGLE FILE MONOLITH
 * CHUNK 3: Real-Time Collaboration, File Sync, Multi-Tenant, Frontend Builder
 **********************************************************************/

// ======================================================
// MULTI-TENANT PROJECT ISOLATION HELPER
// ======================================================
function checkProjectAccess(req: any, projectId: string) {
  const project = db.projects[projectId];
  if (!project) throw new Error("Project not found");
  const workspace = db.workspaces[project.workspaceId];
  if (!workspace.members.includes(req.user.id)) throw new Error("Access denied");
  return project;
}

// ======================================================
// REAL-TIME FILE COLLABORATION (WebSocket)
// ======================================================
interface WSClient extends WebSocket {
  userId?: string;
  projectId?: string;
  cursor?: { x: number; y: number };
}

// Enhance WebSocket connection for multi-user file editing
wss.on("connection", (ws: WSClient) => {
  ws.on("message", (msg: any) => {
    try {
      const data = JSON.parse(msg);

      // JOIN PROJECT
      if (data.type === "join") {
        ws.projectId = data.projectId;
        ws.userId = data.userId;
        // broadcast presence
        broadcastPresence(ws.projectId);
      }

      // CURSOR MOVEMENT
      else if (data.type === "cursor-move") {
        ws.cursor = data.cursor;
        broadcastCursor(ws.projectId, ws.userId, data.cursor);
      }

      // FILE UPDATE
      else if (data.type === "file-update") {
        const project = db.projects[data.projectId];
        if (!project) return;
        if (!project.files[data.path]) project.files[data.path] = {};
        project.files[data.path].content = data.content;
        project.files[data.path].updatedAt = Date.now();

        // broadcast to all other clients in same project
        wss.clients.forEach(client => {
          if (client !== ws && client.readyState === 1 && client.projectId === ws.projectId) {
            client.send(JSON.stringify({ type: "file-update", path: data.path, content: data.content }));
          }
        });
      }

    } catch (err) {
      console.error("WS error:", err);
    }
  });

  ws.on("close", () => {
    broadcastPresence(ws.projectId);
  });
});

// ======================================================
// BROADCAST FUNCTIONS
// ======================================================
function broadcastPresence(projectId: string) {
  const users: any[] = [];
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId === projectId) {
      users.push({ userId: client.userId, cursor: client.cursor });
    }
  });
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId === projectId) {
      client.send(JSON.stringify({ type: "presence-update", users }));
    }
  });
}

function broadcastCursor(projectId: string, userId: string, cursor: any) {
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId === projectId && client.userId !== userId) {
      client.send(JSON.stringify({ type: "cursor-update", userId, cursor }));
    }
  });
}

// ======================================================
// FRONTEND BUILDER PLACEHOLDER (Drag & Drop + Split Code/Preview)
// ======================================================
app.get("/api/builder/preview/:projectId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  const files = Object.values(project.files).map((f: any) => ({ path: f.path, content: f.content }));
  // return "rendered" preview HTML as placeholder
  const html = `<html><head><title>${project.name}</title></head><body>${files.map(f => `<pre>${f.content}</pre>`).join("")}</body></html>`;
  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

// Endpoint to simulate live file saving from builder
app.post("/api/builder/save", authenticate, (req, res) => {
  const { projectId, path, content } = req.body;
  const project = checkProjectAccess(req, projectId);
  if (!project.files[path]) project.files[path] = {};
  project.files[path].content = content;
  project.files[path].updatedAt = Date.now();

  // broadcast update to all real-time clients
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId === projectId) {
      client.send(JSON.stringify({ type: "file-update", path, content }));
    }
  });

  res.json({ success: true, path, content });
});

// ======================================================
// SIMULATED MONACO EDITOR + FILE EXPLORER API
// ======================================================
app.get("/api/builder/files/:projectId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  res.json(Object.values(project.files));
});

// ======================================================
// END OF CHUNK 3
// ======================================================
console.log("✅ Chunk 3 loaded: Real-time collaboration & builder logic");

/**********************************************************************
 * DEVFORGE AI - SINGLE FILE MONOLITH
 * CHUNK 4: Frontend Builder, AI Content Generator, Dashboard, SEO/Accessibility, Export
 **********************************************************************/

// ======================================================
// SIMULATED COMPONENT TREE FOR BUILDER
// ======================================================
app.get("/api/builder/components/:projectId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  if (!project.componentTree) project.componentTree = [];
  res.json(project.componentTree);
});

app.post("/api/builder/components/:projectId", authenticate, (req, res) => {
  const { component } = req.body;
  const project = checkProjectAccess(req, req.params.projectId);
  if (!project.componentTree) project.componentTree = [];
  project.componentTree.push({ id: uuid(), ...component, createdAt: Date.now() });

  // Broadcast to real-time clients
  wss.clients.forEach(client => {
    if (client.readyState === 1 && client.projectId === req.params.projectId) {
      client.send(JSON.stringify({ type: "component-update", component }));
    }
  });

  res.json({ success: true });
});

// ======================================================
// SPLIT-SCREEN CODE + LIVE PREVIEW
// ======================================================
app.get("/api/builder/split/:projectId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  const codeView = Object.values(project.files).map((f: any) => `<pre>${f.path}\n${f.content}</pre>`).join("\n");
  const previewHTML = `<html><body>${Object.values(project.files).map((f: any) => `<div>${f.content}</div>`).join("")}</body></html>`;
  res.json({ codeView, previewHTML });
});

// ======================================================
// AI CONTENT GENERATION ENDPOINTS
// ======================================================
app.post("/api/ai/generate-content", authenticate, async (req, res) => {
  const { projectId, model, type, prompt, language } = req.body;
  const project = checkProjectAccess(req, projectId);
  const output = await routeModel(model, `${type}:${prompt}:${language || "en"}`);

  // Save history
  if (!project.aiHistory) project.aiHistory = [];
  const entry = { id: uuid(), model, type, prompt, language, output, createdAt: Date.now() };
  project.aiHistory.push(entry);

  res.json(entry);
});

// ======================================================
// SEO & ACCESSIBILITY CHECKER PLACEHOLDERS
// ======================================================
app.post("/api/ai/seo-check", authenticate, (req, res) => {
  const { projectId } = req.body;
  checkProjectAccess(req, projectId);
  res.json({ score: Math.floor(Math.random() * 100), issues: ["Missing meta description", "Images missing alt text"] });
});

app.post("/api/ai/accessibility-check", authenticate, (req, res) => {
  const { projectId } = req.body;
  checkProjectAccess(req, projectId);
  res.json({ score: Math.floor(Math.random() * 100), issues: ["Low contrast text", "Missing ARIA labels"] });
});

// ======================================================
// DASHBOARD ENDPOINTS
// ======================================================
app.get("/api/dashboard/projects", authenticate, (req, res) => {
  const projects = Object.values(db.projects).filter((p: any) => {
    const workspace = db.workspaces[p.workspaceId];
    return workspace && workspace.members.includes(req.user.id);
  });
  res.json(projects);
});

app.get("/api/dashboard/analytics/:projectId", authenticate, (req, res) => {
  checkProjectAccess(req, req.params.projectId);
  const analytics = Object.values(db.analytics).filter((a: any) => a.projectId === req.params.projectId);
  res.json({ totalEvents: analytics.length, breakdown: analytics.reduce((acc: any, ev: any) => {
    acc[ev.type] = (acc[ev.type] || 0) + 1; return acc;
  }, {}) });
});

// ======================================================
// ZIP EXPORT PLACEHOLDER
// ======================================================
app.get("/api/project/export-zip/:projectId", authenticate, (req, res) => {
  checkProjectAccess(req, req.params.projectId);
  // Just return JSON simulating zip
  const project = db.projects[req.params.projectId];
  res.json({ zipFileName: `${project.name}.zip`, files: Object.values(project.files) });
});

// ======================================================
// A/B TESTING SIMULATION
// ======================================================
app.post("/api/abtest/create/:projectId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  if (!project.abTests) project.abTests = [];
  const { variantA, variantB } = req.body;
  const test = { id: uuid(), variantA, variantB, createdAt: Date.now(), results: [] };
  project.abTests.push(test);
  res.json(test);
});

app.post("/api/abtest/record/:projectId/:testId", authenticate, (req, res) => {
  const project = checkProjectAccess(req, req.params.projectId);
  const test = project.abTests.find((t: any) => t.id === req.params.testId);
  if (!test) return res.status(400).json({ error: "Test not found" });
  test.results.push({ userId: req.user.id, variant: req.body.variant, timestamp: Date.now() });
  res.json({ success: true });
});

// ======================================================
// LIGHTHOUSE PERFORMANCE SCORE SIMULATION
// ======================================================
app.get("/api/performance/lighthouse/:projectId", authenticate, (req, res) => {
  checkProjectAccess(req, req.params.projectId);
  res.json({
    performance: Math.floor(Math.random() * 100),
    accessibility: Math.floor(Math.random() * 100),
    bestPractices: Math.floor(Math.random() * 100),
    seo: Math.floor(Math.random() * 100)
  });
});

// ======================================================
// END OF CHUNK 4
// ======================================================
console.log("✅ Chunk 4 loaded: Frontend builder, AI generator, dashboard, SEO/accessibility, export, A/B testing, Lighthouse");

/**********************************************************************
 * DEVFORGE AI - SINGLE FILE MONOLITH
 * CHUNK 5: Edge Functions, Background Jobs, Plugins, Multi-model Switching, Security
 **********************************************************************/

// ======================================================
// EDGE FUNCTION PLACEHOLDER
// ======================================================
app.post("/api/edge/run/:projectId", authenticate, (req, res) => {
  const { functionName, payload } = req.body;
  checkProjectAccess(req, req.params.projectId);
  // Simulate running edge function
  const result = { output: `Executed ${functionName} with payload ${JSON.stringify(payload)}` };
  res.json(result);
});

// ======================================================
// BACKGROUND JOB QUEUE SIMULATION (BullMQ placeholder)
// ======================================================
interface Job { id: string; task: string; status: string; createdAt: number; }
const jobQueue: Job[] = [];

app.post("/api/jobs/add", authenticate, (req, res) => {
  const { task } = req.body;
  const job: Job = { id: uuid(), task, status: "queued", createdAt: Date.now() };
  jobQueue.push(job);
  res.json(job);
});

// Simulate background job processing every 2s
setInterval(() => {
  const job = jobQueue.find(j => j.status === "queued");
  if (job) job.status = "completed";
}, 2000);

// ======================================================
// PLUGIN SYSTEM FINALIZATION
// ======================================================
app.post("/api/plugins/run/:pluginId", authenticate, (req, res) => {
  const plugin = db.plugins[req.params.pluginId];
  if (!plugin) return res.status(400).json({ error: "Plugin not found" });
  // Execute plugin code placeholder
  res.json({ result: `Executed plugin ${plugin.name}` });
});

// ======================================================
// MULTI-MODEL USER SWITCHING
// ======================================================
app.post("/api/ai/switch-model", authenticate, (req, res) => {
  const { userId, model } = req.body;
  const user = db.users[userId];
  if (!user) return res.status(400).json({ error: "User not found" });
  user.activeModel = model;
  res.json({ success: true, userId, activeModel: model });
});

// ======================================================
// LIVE SYSTEM STATUS + ERROR TRACKING
// ======================================================
app.get("/api/system/status", authenticate, (req, res) => {
  const status = {
    uptime: process.uptime(),
    users: Object.keys(db.users).length,
    projects: Object.keys(db.projects).length,
    deployments: Object.keys(db.deployments).length,
    backgroundJobs: jobQueue.length,
    memoryUsage: process.memoryUsage()
  };
  res.json(status);
});

app.post("/api/system/error", authenticate, (req, res) => {
  const { message, projectId } = req.body;
  const logId = uuid();
  db.logs[logId] = { id: logId, message, projectId, createdAt: Date.now() };
  console.error(`Project ${projectId} Error: ${message}`);
  res.json({ success: true, logId });
});

// ======================================================
// FINAL MULTI-TENANT + SECURITY POLISH
// ======================================================
app.use((req, res, next) => {
  // add CSP headers
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});

app.use((err: any, req: any, res: any, next: any) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// ======================================================
// FINAL SERVER START
// ======================================================
server.listen(PORT, () => console.log(`🚀 DevForge AI Monolith running on port ${PORT}`));

console.log("✅ Chunk 5 loaded: Edge functions, background jobs, plugins, multi-model switching, system status, error tracking");
