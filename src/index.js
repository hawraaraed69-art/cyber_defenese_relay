import { DurableObject } from "cloudflare:workers";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        status: "online",
        service: "Cyber Defense Relay"
      });
    }

    if (url.pathname === "/admin/enroll" && request.method === "POST") {
      if (request.headers.get("Authorization") !== `Bearer ${env.ADMIN_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const body = await request.json();
      const { student_id, token } = body;

      if (!validId(student_id) || !validToken(token)) {
        return new Response("Invalid student credentials", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(student_id);
      const stub = env.SESSIONS.get(id);

      return stub.fetch("https://internal/enroll", {
        method: "POST",
        body: JSON.stringify({ token })
      });
    }

    if (url.pathname === "/agent" && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const student = url.searchParams.get("student_id");

      if (!validId(student)) {
        return new Response("Invalid student ID", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(student);
      return env.SESSIONS.get(id).fetch(
        new Request("https://internal/agent", request)
      );
    }

    if (url.pathname === "/command" && request.method === "POST") {
      if (request.headers.get("Authorization") !== `Bearer ${env.APP_SECRET}`) {
        return new Response("Unauthorized", { status: 401 });
      }

      const body = await request.json();

      if (!validId(body.student_id)) {
        return new Response("Invalid student ID", { status: 400 });
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
    /^[a-zA-Z0-9_-]{1,32}$/.test(value);
}

function validToken(value) {
  return typeof value === "string" &&
    value.length >= 32 && value.length <= 128;
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
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

    if (url.pathname === "/enroll" && request.method === "POST") {
      const { token } = await request.json();
      await this.ctx.storage.put("tokenHash", await hashToken(token));
      return Response.json({ enrolled: true });
    }

    if (url.pathname === "/agent") {
      const authorization = request.headers.get("Authorization") || "";
      const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";

      const savedHash = await this.ctx.storage.get("tokenHash");

      if (!savedHash || !safeEqual(await hashToken(token), savedHash)) {
        return new Response("Unauthorized", { status: 401 });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      if (this.socket?.readyState === 1) {
        this.socket.close(4000, "Reconnected");
      }

      server.accept();
      this.socket = server;

      server.addEventListener("message", event => {
        this.handleMessage(event.data);
      });

      server.addEventListener("close", () => {
        if (this.socket === server) this.socket = null;
      });

      server.addEventListener("error", () => {
        if (this.socket === server) this.socket = null;
      });

      return new Response(null, {
        status: 101,
        webSocket: client
      });
    }

    if (url.pathname === "/command" && request.method === "POST") {
      if (!this.socket || this.socket.readyState !== 1) {
        return Response.json(
          { error: "Student agent is offline" },
          { status: 503 }
        );
      }

      const body = await request.json();
      const allowed = ["scan", "interfaces", "capture", "banner"];

      if (!allowed.includes(body.action)) {
        return Response.json({ error: "Invalid action" }, { status: 400 });
      }

      const requestId = crypto.randomUUID();

      const result = new Promise(resolve => {
        const timer = setTimeout(() => {
          this.pending.delete(requestId);
          resolve({
            error: "Agent response timed out"
          });
        }, 120000);

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
      // Ignore invalid messages
    }
  }
}
