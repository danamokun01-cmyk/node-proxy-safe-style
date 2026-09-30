"use strict";

// 内部ネットワーク(localhost / プライベートIP / クラウドのメタデータ等)への接続を遮断する。
// 1) ssrfGuard: リクエスト送信前にホスト名・リテラルIP・ポートを検査(proxy.jsと同じURL.parseを使用)
// 2) safeLookup + Agent: DNS解決後の実IPを接続直前に検査(DNS rebinding / 内部IPを指すドメイン対策)

const net = require("net");
const dns = require("dns");
const http = require("http");
const https = require("https");
const URL = require("url");

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (クラウドのメタデータ 169.254.169.254 を含む)
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved / broadcast
].map(([base, bits]) => ({
  base: ipv4ToInt(base),
  mask: (~0 << (32 - bits)) >>> 0,
}));

function isPrivateV4(ip) {
  const n = ipv4ToInt(ip);
  return V4_BLOCKS.some((b) => ((n & b.mask) >>> 0) === b.base);
}

function isPrivateV6(ip) {
  const s = ip.toLowerCase().split("%")[0];
  if (s === "::" || s === "::1") return true;
  const dotted = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return isPrivateV4(dotted[1]);
  const hex = s.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const a = parseInt(hex[1], 16);
    const b = parseInt(hex[2], 16);
    return isPrivateV4([a >> 8, a & 255, b >> 8, b & 255].join("."));
  }
  const first = parseInt(s.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xff00) === 0xff00) return true; // multicast
  return false;
}

function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return isPrivateV4(ip);
  if (v === 6) return isPrivateV6(ip);
  return true; // IPとして解釈できないものは安全側で拒否
}

// DNS解決結果が1つでも内部IPなら接続しない
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    if (list.some((a) => isPrivateIp(a.address))) {
      const e = new Error("blocked_private_ip");
      e.code = "EBLOCKED";
      return callback(e);
    }
    callback(null, address, family);
  });
}

const httpAgent = new http.Agent({ lookup: safeLookup, keepAlive: true });
const httpsAgent = new https.Agent({ lookup: safeLookup, keepAlive: true });

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home.arpa"];

function createSsrfGuard() {
  const allowedPorts = new Set(
    (process.env.ALLOWED_PORTS || "80,443,8080,8443").split(",").map((s) => s.trim())
  );

  // unblocker の requestMiddleware として使う
  return function ssrfGuard(data) {
    const res = data.clientResponse;
    if (!res || res.headersSent) return;
    const uri = URL.parse(data.url);
    const host = (uri.hostname || "").toLowerCase().replace(/\.$/, "");
    const ownHost = String(data.clientRequest.headers.host || "")
      .toLowerCase()
      .replace(/:\d+$/, "");

    let reason = null;
    if (uri.protocol !== "http:" && uri.protocol !== "https:") reason = "bad_protocol";
    else if (!host) reason = "no_host";
    else if (host === "localhost" || BLOCKED_SUFFIXES.some((s) => host.endsWith(s)))
      reason = "blocked_host";
    else if (net.isIP(host) && isPrivateIp(host)) reason = "private_ip";
    else if (host === ownHost) reason = "own_host"; // 自分自身への再帰アクセス
    else if (uri.port && !allowedPorts.has(uri.port)) reason = "blocked_port";

    if (reason) {
      res.locals.blockedReason = reason;
      res.status(403).type("text/plain; charset=utf-8").send("このアドレスにはアクセスできません。");
    }
  };
}

module.exports = { isPrivateIp, safeLookup, httpAgent, httpsAgent, createSsrfGuard };
