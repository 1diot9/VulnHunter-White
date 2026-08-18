import http from "node:http";
import { URL } from "node:url";
import { exec } from "node:child_process";

const PORT = 3456;

function greet(name) {
  const message = `Hello, ${name}!`;
  return message;
}

function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

function processQuery(query) {
  const cmd = `echo "${query}"`;
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout.trim());
    });
  });
}

const users = new Map();
users.set(1, { id: 1, name: "Alice", role: "admin" });
users.set(2, { id: 2, name: "Bob", role: "user" });

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  res.setHeader("Content-Type", "application/json");

  try {
    if (path === "/greet") {
      const name = url.searchParams.get("name") || "World";
      const result = greet(name);
      res.end(JSON.stringify({ result }));
    } else if (path === "/fib") {
      const n = parseInt(url.searchParams.get("n") || "10", 10);
      const result = fibonacci(n);
      res.end(JSON.stringify({ n, result }));
    } else if (path === "/users") {
      const id = parseInt(url.searchParams.get("id") || "0", 10);
      if (id > 0) {
        const user = users.get(id);
        res.end(JSON.stringify({ user: user || null }));
      } else {
        res.end(JSON.stringify({ users: Array.from(users.values()) }));
      }
    } else if (path === "/exec") {
      const query = url.searchParams.get("q") || "hello";
      const result = await processQuery(query);
      res.end(JSON.stringify({ result }));
    } else if (path === "/error") {
      throw new Error("Intentional test error");
    } else {
      res.end(
        JSON.stringify({
          status: "ok",
          endpoints: ["/greet?name=X", "/fib?n=N", "/users?id=N", "/exec?q=X", "/error"],
        }),
      );
    }
  } catch (err) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => {
  console.log(`Target app running at http://localhost:${PORT}`);
  console.log("Start with: node --inspect test/target-app.mjs");
});
