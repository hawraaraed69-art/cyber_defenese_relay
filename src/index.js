import { DurableObject } from "cloudflare:workers";

const LAB_CONFIG = {
  version: "2.0",
  nmap_options: [
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4"
  ],
  max_capture_packets: 100,
  default_capture_packets: 20,
  command_timeout: 120000,
  enabled_actions: ["scan", "interfaces", "capture", "banner"]
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "online",
        service: "Cyber Defense Relay"
      });
    }

    if (url.pathname === "/config" && request.method === "GET") {
      return Response.json(LAB_CONFIG);
    }

    // تسجيل الجهاز تلقائياً لأول مرة
    if (url.pathname === "/register" && request.method === "POST") {
      const body = await request.json();

      if (!validId(body.student_id) ||
          !validToken(body.agent_token) ||
          !validToken(body.pair_code)) {
        return new Response("Invalid registration", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(body.student_id);
      return env.SESSIONS.get(id).fetch("https://internal/register", {
        method: "POST",
        body: JSON.stringify(body)
      });
    }

    // ربط المتصفح بجهاز الطالب
    if (url.pathname === "/pair" && request.method === "POST") {
      const body = await request.json();

      if (!validId(body.student_id) || !validToken(body.pair_code)) {
        return new Response("Invalid pairing", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(body.student_id);
      return env.SESSIONS.get(id).fetch("https://internal/pair", {
        method: "POST",
        body: JSON.stringify(body)
      });
    }

    // تسجيل قديم للمشرف
    if (url.pathname === "/admin/enroll" && request.method === "POST") {
      const received = request.headers.get("Authorization") || "";

      if (!env.ADMIN_SECRET ||
          received !== `Bearer ${env.ADMIN_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const body = await request.json();

      if (!validId(body.student_id) || !validToken(body.token)) {
        return new Response("Invalid credentials", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(body.student_id);
      return env.SESSIONS.get(id).fetch("https://internal/enroll", {
        method: "POST",
        body: JSON.stringify({ token: body.token })
      });
    }

    // اتصال Agent
    if (url.pathname === "/agent" &&
        request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const student = url.searchParams.get("student_id");

      if (!validId(student)) {
        return new Response("Invalid student ID", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(student);
      return env.SESSIONS.get(id).fetch(
        new Request("https://internal/agent", request)
      );
    }

    // إرسال أمر من واجهة المختبر
    if (url.pathname === "/command" && request.method === "POST") {
      if (!env.APP_SECRET ||
          request.headers.get("Authorization") !== `Bearer ${env.APP_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const body = await request.json();

      if (!validId(body.student_id) || !validToken(body.session_token)) {
        return new Response("Invalid session", { status: 401 });
      }

      const id = env.SESSIONS.idFromName(body.student_id);
      return env.SESSIONS.get(id).fetch("https://internal/command", {
        method: "POST",
        body: JSON.stringify(body)
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};

function validId(value) {
  return typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value);
}

function validToken(value) {
  return typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value);
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" ||
      a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export class StudentSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.socket = null;
    this.pending = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);

    // إنشاء جلسة جهاز جديدة
    if (url.pathname === "/register" && request.method === "POST") {
      const body = await request.json();

      if (!validToken(body.agent_token) ||
          !validToken(body.pair_code)) {
        return new Response("Invalid credentials", { status: 400 });
      }

      await this.ctx.storage.put("agentHash", await hashToken(body.agent_token));
      await this.ctx.storage.put("pairHash", await hashToken(body.pair_code));
      await this.ctx.storage.put("pairExpiry", Date.now() + 300000);

      return Response.json({ registered: true });
    }

    // ربط المتصفح مرة واحدة
    if (url.pathname === "/pair" && request.method === "POST") {
      const body = await request.json();
      const savedHash = await this.ctx.storage.get("pairHash");
      const expiry = await this.ctx.storage.get("pairExpiry");

      if (!savedHash || !expiry || Date.now() > expiry ||
          !validToken(body.pair_code) ||
          !safeEqual(await hashToken(body.pair_code), savedHash)) {
        return new Response("Pairing code invalid or expired", { status: 401 });
      }

      const sessionToken = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      await this.ctx.storage.put("sessionHash", await hashToken(sessionToken));
      await this.ctx.storage.delete("pairHash");
      await this.ctx.storage.delete("pairExpiry");

      return Response.json({
        paired: true,
        student_id: body.student_id,
        session_token: sessionToken
      });
    }

    // تسجيل قديم
    if (url.pathname === "/enroll" && request.method === "POST") {
      const { token } = await request.json();

      if (!validToken(token)) {
        return new Response("Invalid token", { status: 400 });
      }

      await this.ctx.storage.put("tokenHash", await hashToken(token));
      return Response.json({ enrolled: true });
    }

    // اتصال Agent والتحقق من هويته
    if (url.pathname === "/agent") {
      const authorization = request.headers.get("Authorization") || "";
      const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7) : "";

      const agentHash = await this.ctx.storage.get("agentHash");
      const oldHash = await this.ctx.storage.get("tokenHash");
      const receivedHash = validToken(token) ? await hashToken(token) : "";

      if ((!agentHash || !safeEqual(receivedHash, agentHash)) &&
          (!oldHash || !safeEqual(receivedHash, oldHash))) {
        return new Response("Unauthorized", { status: 401 });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      if (this.socket?.readyState === 1) {
        this.socket.close(4000, "Reconnected");
      }

      server.accept();
      this.socket = server;

      server.addEventListener("message", event => this.handleMessage(event.data));
      server.addEventListener("close", () => {
        if (this.socket === server) this.socket = null;
      });
      server.addEventListener("error", () => {
        if (this.socket === server) this.socket = null;
      });

      return new Response(null, { status: 101, webSocket: client });
    }

    // تنفيذ الأوامر بجلسة الطالب
    if (url.pathname === "/command" && request.method === "POST") {
      const body = await request.json();
      const sessionHash = await this.ctx.storage.get("sessionHash");
      const oldHash = await this.ctx.storage.get("tokenHash");

      const receivedHash = validToken(body.session_token)
        ? await hashToken(body.session_token) : "";

      if ((!sessionHash || !safeEqual(receivedHash, sessionHash)) &&
          (!oldHash || !safeEqual(receivedHash, oldHash))) {
        return new Response("Unauthorized", { status: 401 });
      }

      if (!this.socket || this.socket.readyState !== 1) {
        return Response.json({ error: "Student agent is offline" }, { status: 503 });
      }

      if (!LAB_CONFIG.enabled_actions.includes(body.action)) {
        return Response.json({ error: "Invalid action" }, { status: 400 });
      }

      const requestId = crypto.randomUUID();

      const result = new Promise(resolve => {
        const timer = setTimeout(() => {
          this.pending.delete(requestId);
          resolve({ error: "Agent response timed out" });
        }, LAB_CONFIG.command_timeout);

        this.pending.set(requestId, data => {
          clearTimeout(timer);
          resolve(data);
        });
      });

      this.socket.send(JSON.stringify({
        type: "command",
        id: requestId,
        action: body.action,
        payload: body.payload || {}
      }));

      return Response.json(await result);
    }

    return new Response("Not Found", { status: 404 });
  }

  handleMessage(message) {
    try {
      const data = JSON.parse(message);
      if (data.type !== "result" || !data.id) return;

      const resolve = this.pending.get(data.id);
      if (resolve) {
        this.pending.delete(data.id);
        resolve(data);
      }
    } catch {
      // تجاهل الرسائل غير الصالحة
    }
  }
}
