import { DurableObject } from "cloudflare:workers";

// الإعدادات العامة للمختبر
const LAB_CONFIG = {
  version: "1.0",

  nmap_options: [
    "-sS", "-sT", "-sV", "-sC",
    "-O", "-A", "-Pn", "-sn",
    "-sU", "-F", "-T2", "-T3", "-T4"
  ],

  max_capture_packets: 100,
  default_capture_packets: 20,
  command_timeout: 120000,

  // الأوامر المتاحة حالياً
  enabled_actions: ["scan", "interfaces", "capture"]
};


export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // فحص حالة الاتصال
    if (url.pathname === "/health") {
      return Response.json({
        status: "online",
        service: "Cyber Defense Relay"
      });
    }

    // عرض إعدادات المختبر
    if (
      url.pathname === "/config" &&
      request.method === "GET"
    ) {
      return Response.json(LAB_CONFIG);
    }

    // تسجيل طالب جديد
    if (
      url.pathname === "/admin/enroll" &&
      request.method === "POST"
    ) {
      const received = request.headers.get("Authorization") || "";

      if (
        !env.ADMIN_SECRET ||
        !safeEqual(received, `Bearer ${env.ADMIN_SECRET}`)
      ) {
        return new Response("Unauthorized", { status: 401 });
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      const { student_id, token } = body || {};

      if (!validId(student_id) || !validToken(token)) {
        return new Response(
          "Invalid student credentials",
          { status: 400 }
        );
      }

      const id = env.SESSIONS.idFromName(student_id);
      const stub = env.SESSIONS.get(id);

      return stub.fetch("https://internal/enroll", {
        method: "POST",
        body: JSON.stringify({ token })
      });
    }

    // اتصال برنامج الطالب
    if (
      url.pathname === "/agent" &&
      request.headers.get("Upgrade")?.toLowerCase() === "websocket"
    ) {
      const student = url.searchParams.get("student_id");

      if (!validId(student)) {
        return new Response("Invalid student ID", { status: 400 });
      }

      const id = env.SESSIONS.idFromName(student);

      return env.SESSIONS.get(id).fetch(
        new Request("https://internal/agent", request)
      );
    }

    // إرسال أمر إلى جهاز الطالب
    if (
      url.pathname === "/command" &&
      request.method === "POST"
    ) {
      // التحقق من سر التطبيق
      const received = request.headers.get("Authorization") || "";

      if (
        !env.APP_SECRET ||
        !safeEqual(received, `Bearer ${env.APP_SECRET}`)
      ) {
        return new Response("Unauthorized", { status: 401 });
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      // التحقق من بيانات الطالب
      if (!body || !validId(body.student_id)) {
        return new Response("Invalid student ID", { status: 400 });
      }

      if (!validToken(body.student_token)) {
        return new Response(
          "Student authentication required",
          { status: 401 }
        );
      }

      const id = env.SESSIONS.idFromName(body.student_id);

      // إرسال الأمر إلى جلسة الطالب
      return env.SESSIONS.get(id).fetch(
        "https://internal/command",
        {
          method: "POST",
          body: JSON.stringify(body)
        }
      );
    }

    return new Response("Not Found", { status: 404 });
  }
};


// التحقق من صيغة هوية الطالب
function validId(value) {
  return typeof value === "string" &&
    /^[a-zA-Z0-9_-]{1,32}$/.test(value);
}


// التحقق من طول رمز الطالب
function validToken(value) {
  return typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 128;
}


// تشفير رمز الطالب باستخدام SHA-256
async function hashToken(token) {
  const data = new TextEncoder().encode(token);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}


// مقارنة آمنة للقيم النصية
function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}


// =====================================================
// جلسة مستقلة لكل طالب
// =====================================================

export class StudentSession extends DurableObject {

  constructor(ctx, env) {
    super(ctx, env);

    this.ctx = ctx;
    this.env = env;

    this.socket = null;
    this.pending = new Map();
  }


  // معالجة الطلبات داخل جلسة الطالب
  async fetch(request) {
    const url = new URL(request.url);

    // تسجيل رمز الطالب وتخزين بصمته
    if (
      url.pathname === "/enroll" &&
      request.method === "POST"
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      const { token } = body || {};

      if (!validToken(token)) {
        return new Response("Invalid token", { status: 400 });
      }

      // إغلاق الاتصال السابق عند تغيير الرمز
      this.disconnectAgent("Student token updated");

      // تخزين بصمة الرمز بدلاً من الرمز الأصلي
      await this.ctx.storage.put(
        "tokenHash",
        await hashToken(token)
      );

      return Response.json({ enrolled: true });
    }


    // استقبال اتصال Agent والتحقق من الرمز
    if (url.pathname === "/agent") {

      const authorization =
        request.headers.get("Authorization") || "";

      const token = authorization.startsWith("Bearer ")
        ? authorization.slice(7)
        : "";

      const savedHash =
        await this.ctx.storage.get("tokenHash");

      if (
        !savedHash ||
        !validToken(token) ||
        !safeEqual(await hashToken(token), savedHash)
      ) {
        return new Response("Unauthorized", { status: 401 });
      }

      // إنشاء اتصال WebSocket
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      // استبدال الاتصال السابق إن وجد
      this.disconnectAgent("Agent reconnected");

      server.accept();
      this.socket = server;

      server.addEventListener("message", event => {
        this.handleMessage(event.data);
      });

      server.addEventListener("close", () => {
        this.disconnectAgent(
          "Student agent disconnected",
          server
        );
      });

      server.addEventListener("error", () => {
        this.disconnectAgent(
          "Student agent connection error",
          server
        );
      });

      return new Response(null, {
        status: 101,
        webSocket: client
      });
    }


    // تنفيذ أوامر المختبر
    if (
      url.pathname === "/command" &&
      request.method === "POST"
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      if (!body || typeof body !== "object") {
        return new Response("Invalid request", { status: 400 });
      }

      // التحقق من رمز الطالب المخزن
      const savedHash =
        await this.ctx.storage.get("tokenHash");

      if (
        !savedHash ||
        !validToken(body.student_token) ||
        !safeEqual(
          await hashToken(body.student_token),
          savedHash
        )
      ) {
        return new Response("Unauthorized", { status: 401 });
      }

      // التأكد من اتصال Agent
      if (!this.socket || this.socket.readyState !== 1) {
        return Response.json(
          { error: "Student agent is offline" },
          { status: 503 }
        );
      }

      // التحقق من نوع الأمر
      if (!LAB_CONFIG.enabled_actions.includes(body.action)) {
        return Response.json(
          { error: "Invalid action" },
          { status: 400 }
        );
      }

      // التحقق من محتوى الأمر
      if (
        body.payload !== undefined &&
        (
          body.payload === null ||
          typeof body.payload !== "object" ||
          Array.isArray(body.payload)
        )
      ) {
        return Response.json(
          { error: "Invalid command payload" },
          { status: 400 }
        );
      }

      const requestId = crypto.randomUUID();
      console.log("DEBUG: Command received", body.action);
     console.log("DEBUG: Agent socket state", this.socket.readyState);

      // انتظار نتيجة الأمر من جهاز الطالب
      let resolveResult;

      const result = new Promise(resolve => {
        resolveResult = resolve;

        const timer = setTimeout(() => {
          this.pending.delete(requestId);

          resolve({
            error: "Agent response timed out"
          });
        }, LAB_CONFIG.command_timeout);

        this.pending.set(requestId, {
          resolve,
          timer
        });
      });

      // إرسال الأمر إلى Agent
      try {
        this.socket.send(JSON.stringify({
          type: "command",
          id: requestId,
          action: body.action,
          payload: body.payload || {}
        }));
      } catch {
        const pending = this.pending.get(requestId);

        if (pending) {
          clearTimeout(pending.timer);
          this.pending.delete(requestId);
        }

        resolveResult({
          error: "Failed to send command to student agent"
        });
      }

      return Response.json(await result);
    }

    return new Response("Not Found", { status: 404 });
  }


  // استقبال نتائج الأوامر من جهاز الطالب
  handleMessage(message) {
    try {
      const data = JSON.parse(message);

      if (data.type !== "result" || !data.id) {
        return;
      }

      const pending = this.pending.get(data.id);

      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(data.id);

        pending.resolve(data);
      }

    } catch {
      // تجاهل الرسائل غير الصالحة
    }
  }


  // إغلاق اتصال الطالب وإنهاء الأوامر المعلقة
  disconnectAgent(reason, expectedSocket = null) {

    // منع حدث اتصال قديم من إغلاق اتصال أحدث
    if (
      expectedSocket &&
      this.socket !== expectedSocket
    ) {
      return;
    }

    const oldSocket = this.socket;
    this.socket = null;

    if (oldSocket) {
      try {
        if (oldSocket.readyState === 1) {
          oldSocket.close(4000, reason);
        }
      } catch {
        // تجاهل خطأ إغلاق الاتصال
      }
    }

    // إنهاء جميع الأوامر المعلقة
    for (const [requestId, pending] of this.pending) {
      clearTimeout(pending.timer);

      pending.resolve({
        error: reason
      });

      this.pending.delete(requestId);
    }
  }
}
