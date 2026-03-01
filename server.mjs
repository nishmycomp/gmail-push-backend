#!/usr/bin/env node
import { createServer } from "http";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";

const env = loadEnv();
const cfg = {
  port: Number(env.PORT || 8788),
  baseUrl: requireEnv("BASE_URL"),
  appSharedSecret: requireEnv("APP_SHARED_SECRET"),
  webhookSecret: requireEnv("GMAIL_PUSH_WEBHOOK_SECRET"),
  googleClientId: requireEnv("GOOGLE_CLIENT_ID"),
  googleClientSecret: requireEnv("GOOGLE_CLIENT_SECRET"),
  googlePubsubTopic: requireEnv("GOOGLE_PUBSUB_TOPIC"),
  encryptionKeyB64: requireEnv("ENCRYPTION_KEY_B64"),
  storePath: env.STORE_PATH || "./data/store.json",
};

const scopes = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/gmail.modify",
].join(" ");

const redirectUri = new URL("/oauth/google/callback", cfg.baseUrl).toString();
const encryptionKey = Buffer.from(cfg.encryptionKeyB64, "base64");
if (encryptionKey.length !== 32) {
  throw new Error("ENCRYPTION_KEY_B64 must decode to exactly 32 bytes");
}

const store = createStore(cfg.storePath);

function requireEnv(name) {
  const v = env[name];
  if (!v || !String(v).trim()) {throw new Error(`Missing required env: ${name}`);}
  return String(v).trim();
}

function loadEnv() {
  const values = { ...process.env };
  if (!existsSync(".env")) {return values;}
  const raw = readFileSync(".env", "utf8");
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) {continue;}
    const i = t.indexOf("=");
    if (i < 1) {continue;}
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim().replace(/^['"]|['"]$/g, "");
    if (!(k in values)) {values[k] = v;}
  }
  return values;
}

function createStore(path) {
  const initial = {
    users: {},
    oauthStates: {},
    notifications: [],
  };
  const dir = dirname(path);
  if (!existsSync(dir)) {mkdirSync(dir, { recursive: true });}
  if (!existsSync(path)) {writeFileSync(path, JSON.stringify(initial, null, 2));}

  function read() {
    try {
      return JSON.parse(readFileSync(path, "utf8"));
    } catch {
      return structuredClone(initial);
    }
  }

  function write(v) {
    writeFileSync(path, JSON.stringify(v, null, 2));
  }

  return { read, write, path };
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

function parseQuery(reqUrl) {
  return new URL(reqUrl, "http://127.0.0.1");
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => { raw += chunk; });
    req.on("end", () => resolve(raw));
    req.on("error", reject);
  });
}

function ensureAppAuth(req) {
  const got = String(req.headers["x-nextbot-secret"] || "");
  return got && got === cfg.appSharedSecret;
}

function encrypt(text) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${encrypted.toString("base64")}`;
}

function decrypt(payload) {
  const [ivB64, tagB64, dataB64] = String(payload).split(".");
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const data = Buffer.from(dataB64, "base64");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString("utf8");
}

function upsertUser(storeData, userId, patch) {
  const existing = storeData.users[userId] || {};
  storeData.users[userId] = {
    userId,
    ...existing,
    ...patch,
    updatedAt: new Date().toISOString(),
  };
}

function findUserByEmail(storeData, emailAddress) {
  const target = String(emailAddress || "").toLowerCase();
  return Object.values(storeData.users).find(u => String(u.email || "").toLowerCase() === target) || null;
}

async function googleTokenExchange(code) {
  const body = new URLSearchParams({
    code,
    client_id: cfg.googleClientId,
    client_secret: cfg.googleClientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const data = await res.json();
  if (!res.ok) {throw new Error(`Token exchange failed: ${JSON.stringify(data)}`);}
  return data;
}

async function googleRefreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: cfg.googleClientId,
    client_secret: cfg.googleClientSecret,
    grant_type: "refresh_token",
  });
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const data = await res.json();
  if (!res.ok) {throw new Error(`Token refresh failed: ${JSON.stringify(data)}`);}
  return data;
}

async function gmailGet(accessToken, path, params = {}) {
  const url = new URL(`https://gmail.googleapis.com/gmail/v1/users/me${path}`);
  for (const [k, v] of Object.entries(params)) {
    if (k === "metadataHeaders") {
      for (const h of String(v).split(",")) {url.searchParams.append(k, h.trim());}
    } else {
      url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`Gmail GET ${path} failed: ${JSON.stringify(data)}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function gmailPost(accessToken, path, bodyObj) {
  const url = `https://gmail.googleapis.com/gmail/v1/users/me${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(bodyObj),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {throw new Error(`Gmail POST ${path} failed: ${JSON.stringify(data)}`);}
  return data;
}

async function ensureFreshAccessForUser(user) {
  const refreshToken = decrypt(user.refreshTokenEncrypted);
  const refreshed = await googleRefreshAccessToken(refreshToken);
  return {
    accessToken: refreshed.access_token,
    expiresIn: refreshed.expires_in || 3600,
    refreshToken,
  };
}

async function startWatchForUser(userId) {
  const s = store.read();
  const user = s.users[userId];
  if (!user?.refreshTokenEncrypted) {
    throw new Error(`User '${userId}' is not connected to Gmail`);
  }
  const fresh = await ensureFreshAccessForUser(user);
  const watch = await gmailPost(fresh.accessToken, "/watch", {
    topicName: cfg.googlePubsubTopic,
    labelIds: ["INBOX"],
    labelFilterAction: "include",
  });

  upsertUser(s, userId, {
    historyId: watch.historyId ? String(watch.historyId) : user.historyId || null,
    watchExpiration: watch.expiration ? String(watch.expiration) : null,
    lastWatchAt: new Date().toISOString(),
  });
  store.write(s);
  return watch;
}

function parseHeader(headers, name) {
  return headers?.find(h => String(h.name || "").toLowerCase() === name.toLowerCase())?.value || "";
}

async function processGmailPush(pubsubMessage) {
  const payload = pubsubMessage?.message?.data
    ? JSON.parse(Buffer.from(pubsubMessage.message.data, "base64").toString("utf8"))
    : {};

  const emailAddress = payload.emailAddress || "";
  const incomingHistoryId = payload.historyId ? String(payload.historyId) : null;
  if (!emailAddress || !incomingHistoryId) {
    return { ok: true, ignored: "missing emailAddress or historyId" };
  }

  const s = store.read();
  const user = findUserByEmail(s, emailAddress);
  if (!user) {
    return { ok: true, ignored: `no user mapped for ${emailAddress}` };
  }

  const previousHistoryId = user.historyId ? String(user.historyId) : null;
  if (!previousHistoryId) {
    upsertUser(s, user.userId, {
      historyId: incomingHistoryId,
      lastPushAt: new Date().toISOString(),
    });
    store.write(s);
    return { ok: true, initialized: true, userId: user.userId, historyId: incomingHistoryId };
  }

  let accessToken;
  try {
    const fresh = await ensureFreshAccessForUser(user);
    accessToken = fresh.accessToken;
  } catch (err) {
    return { ok: false, userId: user.userId, error: `token refresh failed: ${err.message}` };
  }

  let history;
  try {
    history = await gmailGet(accessToken, "/history", {
      startHistoryId: previousHistoryId,
      historyTypes: "messageAdded",
      maxResults: 100,
    });
  } catch (err) {
    if (String(err.status) === "404") {
      upsertUser(s, user.userId, {
        historyId: incomingHistoryId,
        lastPushAt: new Date().toISOString(),
        lastPushRebasedAt: new Date().toISOString(),
      });
      store.write(s);
      return { ok: true, rebased: true, userId: user.userId };
    }
    return { ok: false, userId: user.userId, error: err.message };
  }

  const ids = new Set();
  for (const h of history.history || []) {
    for (const added of h.messagesAdded || []) {
      const id = added?.message?.id;
      if (id) {ids.add(id);}
    }
  }

  const inserted = [];
  for (const messageId of ids) {
    const id = String(messageId);
    const msg = await gmailGet(accessToken, `/messages/${id}`, {
      format: "metadata",
      metadataHeaders: "From,To,Subject,Date",
    });
    const headers = msg.payload?.headers || [];
    const notification = {
      id: randomBytes(8).toString("hex"),
      userId: user.userId,
      messageId: id,
      from: parseHeader(headers, "From"),
      to: parseHeader(headers, "To"),
      subject: parseHeader(headers, "Subject"),
      date: parseHeader(headers, "Date"),
      snippet: msg.snippet || "",
      receivedAt: new Date().toISOString(),
    };
    s.notifications.push(notification);
    inserted.push(notification);
  }

  upsertUser(s, user.userId, {
    historyId: String(history.historyId || incomingHistoryId),
    lastPushAt: new Date().toISOString(),
  });
  store.write(s);

  return {
    ok: true,
    userId: user.userId,
    delivered: inserted.length,
  };
}

function compactNotifications(notifications, maxItems = 2000) {
  if (notifications.length <= maxItems) {return notifications;}
  return notifications.slice(notifications.length - maxItems);
}

async function handleRequest(req, res) {
  const url = parseQuery(req.url || "/");

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { ok: true, service: "nextbot-gmail-push-backend" });
  }

  if (req.method === "GET" && url.pathname === "/oauth/google/start") {
    const userId = (url.searchParams.get("userId") || "").trim();
    if (!userId) {return json(res, 400, { error: "userId query param is required" });}

    const state = randomBytes(18).toString("hex");
    const s = store.read();
    s.oauthStates[state] = { userId, createdAt: new Date().toISOString() };
    store.write(s);

    const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    auth.searchParams.set("client_id", cfg.googleClientId);
    auth.searchParams.set("redirect_uri", redirectUri);
    auth.searchParams.set("response_type", "code");
    auth.searchParams.set("scope", scopes);
    auth.searchParams.set("access_type", "offline");
    auth.searchParams.set("prompt", "consent");
    auth.searchParams.set("state", state);

    res.statusCode = 302;
    res.setHeader("Location", auth.toString());
    res.end();
    return;
  }

  if (req.method === "GET" && url.pathname === "/oauth/google/callback") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const err = url.searchParams.get("error");
    if (err) {return json(res, 400, { error: `oauth failed: ${err}` });}
    if (!code || !state) {return json(res, 400, { error: "missing code/state" });}

    const s = store.read();
    const stateRow = s.oauthStates[state];
    if (!stateRow?.userId) {return json(res, 400, { error: "invalid or expired oauth state" });}
    const userId = stateRow.userId;
    delete s.oauthStates[state];

    let tokens;
    try {
      tokens = await googleTokenExchange(code);
    } catch (e) {
      store.write(s);
      return json(res, 500, { error: e.message });
    }

    const refreshToken = tokens.refresh_token
      || (s.users[userId]?.refreshTokenEncrypted ? decrypt(s.users[userId].refreshTokenEncrypted) : null);
    if (!refreshToken) {
      store.write(s);
      return json(res, 400, {
        error: "No refresh_token returned. Re-consent may be required.",
      });
    }

    let profile = {};
    try {
      profile = await gmailGet(tokens.access_token, "/profile");
    } catch {}

    upsertUser(s, userId, {
      email: profile.emailAddress || s.users[userId]?.email || "",
      refreshTokenEncrypted: encrypt(refreshToken),
      connectedAt: s.users[userId]?.connectedAt || new Date().toISOString(),
      lastOAuthAt: new Date().toISOString(),
    });
    store.write(s);

    // Best effort: start watch immediately.
    let watchError = null;
    try {
      await startWatchForUser(userId);
    } catch (e) {
      watchError = e.message;
    }

    const html = `<!doctype html><html><body style="font-family:sans-serif;padding:24px">
      <h2>${watchError ? "Gmail connected (watch pending)" : "Gmail connected successfully"}</h2>
      <p>User: <b>${userId}</b></p>
      <p>Email: <b>${profile.emailAddress || "unknown"}</b></p>
      ${watchError ? `<p style="color:#b00">Watch error: ${watchError}</p>` : "<p>Push watch is active.</p>"}
      <p>You can close this tab and return to the app.</p>
    </body></html>`;
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(html);
    return;
  }

  if (req.method === "POST" && url.pathname === "/gmail/push") {
    const secret = url.searchParams.get("secret") || "";
    if (secret !== cfg.webhookSecret) {return json(res, 401, { error: "invalid webhook secret" });}

    let payload = {};
    try {
      const raw = await readBody(req);
      payload = raw ? JSON.parse(raw) : {};
    } catch {
      return json(res, 400, { error: "invalid json body" });
    }

    const result = await processGmailPush(payload);

    const s = store.read();
    s.notifications = compactNotifications(s.notifications);
    store.write(s);
    return json(res, 200, result);
  }

  // App authenticated endpoints
  if (url.pathname.startsWith("/users/")) {
    if (!ensureAppAuth(req)) {return json(res, 401, { error: "unauthorized" });}
    const parts = url.pathname.split("/").filter(Boolean);
    const userId = parts[1];
    const action = parts[2] || "";
    if (!userId) {return json(res, 400, { error: "userId missing in path" });}

    if (req.method === "GET" && action === "status") {
      const s = store.read();
      const user = s.users[userId] || null;
      return json(res, 200, {
        userId,
        connected: Boolean(user?.refreshTokenEncrypted),
        email: user?.email || null,
        watchExpiration: user?.watchExpiration || null,
        historyId: user?.historyId || null,
      });
    }

    if (req.method === "GET" && action === "notifications") {
      const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit") || 25)));
      const since = url.searchParams.get("since");
      const s = store.read();
      let rows = s.notifications.filter(n => n.userId === userId);
      if (since) {rows = rows.filter(n => String(n.receivedAt) > since);}
      rows = rows.slice(rows.length - limit);
      return json(res, 200, { userId, notifications: rows });
    }

    if (req.method === "POST" && action === "watch-start") {
      try {
        const watch = await startWatchForUser(userId);
        return json(res, 200, { ok: true, watch });
      } catch (e) {
        return json(res, 500, { error: e.message });
      }
    }

    if (req.method === "POST" && action === "disconnect") {
      const s = store.read();
      const existing = s.users[userId] || {};
      s.users[userId] = {
        ...existing,
        refreshTokenEncrypted: null,
        watchExpiration: null,
        historyId: null,
        disconnectedAt: new Date().toISOString(),
      };
      store.write(s);
      return json(res, 200, { ok: true });
    }
  }

  if (req.method === "POST" && url.pathname === "/internal/renew-watches") {
    if (!ensureAppAuth(req)) {return json(res, 401, { error: "unauthorized" });}
    const s = store.read();
    const users = Object.values(s.users);
    const now = Date.now();
    const renewed = [];
    const failed = [];
    for (const u of users) {
      if (!u?.userId || !u?.refreshTokenEncrypted) {continue;}
      const exp = Number(u.watchExpiration || 0);
      const needsRenew = !exp || exp - now < 24 * 60 * 60 * 1000;
      if (!needsRenew) {continue;}
      try {
        await startWatchForUser(u.userId);
        renewed.push(u.userId);
      } catch (e) {
        failed.push({ userId: u.userId, error: e.message });
      }
    }
    return json(res, 200, { ok: true, renewed, failed });
  }

  return json(res, 404, { error: "not found" });
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch(err => {
    json(res, 500, { error: err.message || String(err) });
  });
});

server.listen(cfg.port, "0.0.0.0", () => {
  console.log(
    JSON.stringify(
      {
        ok: true,
        service: "nextbot-gmail-push-backend",
        port: cfg.port,
        health: "/health",
        oauthStartExample: `${cfg.baseUrl}/oauth/google/start?userId=USER_ID`,
        webhook: "/gmail/push?secret=***",
        storePath: store.path,
      },
      null,
      2
    )
  );
});
