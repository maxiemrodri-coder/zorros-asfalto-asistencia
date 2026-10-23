const LOGIN_PATH = "/login";
const LOGOUT_PATH = "/logout";
const COOKIE_NAME = "zda_session";
const SESSION_SECONDS = 8 * 60 * 60;

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
async function signature(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
}
async function makeToken(expiry, secret) {
  const payload = String(expiry);
  return `${payload}.${base64Url(await signature(payload, secret))}`;
}
async function validToken(token, secret) {
  if (!token || !secret) return false;
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const expiryText = token.slice(0, dot);
  const expiry = Number(expiryText);
  if (!Number.isInteger(expiry) || expiry <= Math.floor(Date.now() / 1000)) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    return await crypto.subtle.verify("HMAC", key, fromBase64Url(token.slice(dot + 1)), new TextEncoder().encode(expiryText));
  } catch (_) { return false; }
}
function cookieValue(request, name) {
  const cookies = request.headers.get("cookie") || "";
  for (const item of cookies.split(";")) {
    const part = item.trim();
    const equals = part.indexOf("=");
    if (equals > -1 && part.slice(0, equals) === name) return part.slice(equals + 1);
  }
  return "";
}
function redirect(url, headers = {}) {
  return new Response(null, { status: 303, headers: { Location: url, "Cache-Control": "no-store", ...headers } });
}
function expiredCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export default async (request, context) => {
  const url = new URL(request.url);
  const path = url.pathname;
  const userExpected = Deno.env.get("APP_LOGIN_USER");
  const passwordExpected = Deno.env.get("APP_LOGIN_PASSWORD");
  const secret = Deno.env.get("APP_SESSION_SECRET");

  // La página de ingreso siempre queda visible.
  if (path === "/" || path === "/index.html" || path === "/logo-zorros.png") return context.next();

  // Inicio de sesión: valida las credenciales en el servidor y emite una cookie firmada.
  if (path === LOGIN_PATH && request.method === "POST") {
    if (!userExpected || !passwordExpected || !secret) {
      return redirect("/?error=config");
    }
    try {
      const form = await request.formData();
      const user = String(form.get("username") || "");
      const password = String(form.get("password") || "");
      if (user !== userExpected || password !== passwordExpected) {
        return redirect("/?error=1", { "Set-Cookie": expiredCookie() });
      }
      const expiry = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
      const token = await makeToken(expiry, secret);
      return redirect("/app.html", {
        "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`
      });
    } catch (_) {
      return redirect("/?error=1", { "Set-Cookie": expiredCookie() });
    }
  }

  // Cerrar sesión: invalida la cookie en el navegador.
  if (path === LOGOUT_PATH && request.method === "POST") {
    return redirect("/", { "Set-Cookie": expiredCookie() });
  }

  // Todas las demás rutas, incluida la aplicación original, requieren una sesión válida.
  if (!userExpected || !passwordExpected || !secret) {
    return new Response("Falta configurar APP_LOGIN_USER, APP_LOGIN_PASSWORD y APP_SESSION_SECRET en Netlify.", {
      status: 503, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  const token = cookieValue(request, COOKIE_NAME);
  if (await validToken(token, secret)) return context.next();

  if (path === "/app.html" || path === "/") return redirect("/");
  return new Response("Acceso restringido. Iniciá sesión para continuar.", {
    status: 401,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Set-Cookie": expiredCookie() }
  });
};
