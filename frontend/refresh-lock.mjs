import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TEMPLATE = path.join(HERE, "package-lock.template.json");
const OUTPUT = path.join(HERE, "package-lock.json");
const TARGET = "16.3.3";

const packages = {
  "@next/env": "sha512-U2eYQRwXj+dsqxV79zFqExDdatnNY/ZWc2nsJU1p/OgT7fd3dXwlF6OjYaFQCfMoeTA19PWq+wVmYgimVA+V+g==",
  "@next/swc-darwin-arm64": "sha512-8Hiv32QJPwdV6KYJ8meR9SBA061tQqnIKTJDocvOXlEQqib0xMFpzArosuffFUUc0sslbh7QQ8a3Yey1QV8EIw==",
  "@next/swc-darwin-x64": "sha512-A1lgKgwVchRYmSe467zdwhxT9040dd8lH+o65sL5Jet8fjB4kegw/rDyPIpYVRb6jAqwXFOJpjIXJLxQKLiE3A==",
  "@next/swc-linux-arm64-gnu": "sha512-bf0FIssMFueU2dm7vQEWWxk0c8UjKTdW0yzuh0sQsD8pf1+KCLDdaqhYZNMYGmXwEOiHAUzgBKudovIlcvvBjg==",
  "@next/swc-linux-arm64-musl": "sha512-W7viwCk9JY/cAkdz/A273rd5bb3RgT/IHwR7Upv90tunjBWNtAAhGhoecHh+teRNRSinuAFmE+l7fwZ4YKkrXg==",
  "@next/swc-linux-x64-gnu": "sha512-0W46zw1N3ODpI6n0GeivHvvob1pooozgZVqy65k0mh4/7vr+FbY9+WpHzNVXjHipJf/A3FDheBG19H1s5A25rA==",
  "@next/swc-linux-x64-musl": "sha512-H4mBso8ZTMBPtdT0PN0pBx2ayTvQuTuvS6qT13d77yVFJXAPCxkyIhLTmdMaGTJs0krQYI/qpzdHijCeihXhbg==",
  "@next/swc-win32-arm64-msvc": "sha512-cTMUJpcEGmeywofCUfhR+rSsoE33+rVPnPEYNTNdLNlsOeEg/vktOsKUSTb28vUGqD2jkm4Zaskcwn7OCI6FQg==",
  "@next/swc-win32-x64-msvc": "sha512-2VR4cTBzHXaBjnGsuH6GyJjENzQOmHeAh11uY1iUhjm3j5dEUrVJuUj+VL78jaGi/Dik8xS76zEj18BsFhlVZQ==",
  next: "sha512-tuRTx1nQ/yVw83cwJBo9F+njGUgMn3UHQycreWHB8XsStvvAh1AthbI8/4IpKnFaF58F+iSiHejYOlMQ/eq83g==",
};

const lock = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
if (lock.lockfileVersion !== 3 || !lock.packages?.[""]) {
  throw new Error("unexpected frontend lock template format");
}

lock.packages[""].dependencies.next = TARGET;

for (const [name, integrity] of Object.entries(packages)) {
  const key = `node_modules/${name}`;
  const entry = lock.packages[key];
  if (!entry) throw new Error(`lock template is missing ${key}`);
  entry.version = TARGET;
  const base = name.startsWith("@next/") ? name.slice("@next/".length) : name;
  entry.resolved = `https://registry.npmjs.org/${name}/-/${base}-${TARGET}.tgz`;
  entry.integrity = integrity;
}

const next = lock.packages["node_modules/next"];
next.dependencies["@next/env"] = TARGET;
for (const name of Object.keys(next.optionalDependencies ?? {})) {
  if (name.startsWith("@next/swc-")) next.optionalDependencies[name] = TARGET;
}

fs.writeFileSync(OUTPUT, `${JSON.stringify(lock, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
console.log(`Generated ${path.basename(OUTPUT)} with Next.js ${TARGET}`);
