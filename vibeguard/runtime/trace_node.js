"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const Module = require("module");
const { AsyncLocalStorage } = require("async_hooks");

const tracePath = process.env.VIBEGUARD_TRACE || "";
const storage = new AsyncLocalStorage();

function append(record) {
  if (!tracePath) {
    return;
  }
  try {
    fs.appendFileSync(tracePath, JSON.stringify(record) + "\n");
  } catch (error) {
    return;
  }
}

function noteQuery(sql) {
  const record = storage.getStore();
  if (!record || typeof sql !== "string" || !sql.trim()) {
    return;
  }
  record.queries.push(sql.trim().slice(0, 2000));
}

function wrapServer(proto) {
  if (!proto || typeof proto.emit !== "function" || proto.emit._vibeguard) {
    return;
  }
  const original = proto.emit;
  function wrapped(event) {
    if (event !== "request" || arguments.length < 3) {
      return original.apply(this, arguments);
    }
    const req = arguments[1];
    const res = arguments[2];
    if (!req || !res || typeof res.writeHead !== "function") {
      return original.apply(this, arguments);
    }
    const record = {
      method: String(req.method || "").toUpperCase(),
      path: String(req.url || "/").split("?")[0],
      status: 0,
      duration_ms: 0,
      queries: [],
      exceptions: [],
    };
    const started = process.hrtime.bigint();
    const originalWriteHead = res.writeHead;
    res.writeHead = function (statusCode) {
      const code = Number(statusCode);
      if (code) {
        record.status = code;
      }
      return originalWriteHead.apply(this, arguments);
    };
    res.on("finish", () => {
      if (!record.status) {
        record.status = res.statusCode || 0;
      }
      record.duration_ms = Math.round(Number(process.hrtime.bigint() - started) / 1e4) / 100;
      append(record);
    });
    return storage.run(record, () => original.apply(this, arguments));
  }
  wrapped._vibeguard = true;
  proto.emit = wrapped;
}

wrapServer(http.Server && http.Server.prototype);
wrapServer(https.Server && https.Server.prototype);

const originalError = console.error;
console.error = function () {
  const record = storage.getStore();
  if (record) {
    const text = Array.prototype.map.call(arguments, String).join(" ").slice(0, 500);
    if (text) {
      record.exceptions.push(text);
    }
  }
  return originalError.apply(console, arguments);
};

function wrapStatement(statement, sql) {
  ["run", "get", "all", "iterate"].forEach((name) => {
    const original = statement[name];
    if (typeof original !== "function" || original._vibeguard) {
      return;
    }
    statement[name] = function () {
      noteQuery(String(sql));
      return original.apply(this, arguments);
    };
    statement[name]._vibeguard = true;
  });
  return statement;
}

function wrapBetter(exported) {
  const proto = exported && exported.prototype;
  if (!proto || typeof proto.prepare !== "function" || proto.prepare._vibeguard) {
    return exported;
  }
  const originalPrepare = proto.prepare;
  proto.prepare = function (sql) {
    return wrapStatement(originalPrepare.call(this, sql), sql);
  };
  proto.prepare._vibeguard = true;
  if (typeof proto.exec === "function" && !proto.exec._vibeguard) {
    const originalExec = proto.exec;
    proto.exec = function (sql) {
      noteQuery(String(sql));
      return originalExec.apply(this, arguments);
    };
    proto.exec._vibeguard = true;
  }
  return exported;
}

function wrapQuery(proto) {
  if (!proto || typeof proto.query !== "function" || proto.query._vibeguard) {
    return;
  }
  const original = proto.query;
  proto.query = function (text) {
    if (typeof text === "string") {
      noteQuery(text);
    } else if (text && typeof text.text === "string") {
      noteQuery(text.text);
    }
    return original.apply(this, arguments);
  };
  proto.query._vibeguard = true;
}

function wrapPg(exported) {
  if (!exported) {
    return exported;
  }
  wrapQuery(exported.Client && exported.Client.prototype);
  wrapQuery(exported.Pool && exported.Pool.prototype);
  return exported;
}

const originalRequire = Module.prototype.require;
Module.prototype.require = function (id) {
  const exported = originalRequire.apply(this, arguments);
  if (id === "better-sqlite3") {
    return wrapBetter(exported);
  }
  if (id === "pg") {
    return wrapPg(exported);
  }
  return exported;
};
