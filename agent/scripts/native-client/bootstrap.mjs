// Setup-only entry. An ordinary terminal has no native conversation identity.
import {currentBinding} from "./vigil-project.mjs"
import {fileURLToPath} from "node:url"
import {dirname} from "node:path"
import {spawnSync} from "node:child_process"
try {
  const args = process.argv.slice(2)
  if (args[0] !== "engagement" || !["mode", "client-check"].includes(args[1]))
    throw new Error("This helper inspects NEW-task setup only. Use the absolute snapshot helper supplied by your task's native hook for workflow commands.")
  const binding = currentBinding(dirname(fileURLToPath(import.meta.url)))
  process.stderr.write("Inspecting the project's NEW-task selection; this is not an existing conversation binding.\n")
  const result = spawnSync(binding.vigil_cli, args, {stdio: "inherit"})
  if (result.error) throw result.error
  process.exitCode = result.status ?? 1
} catch (error) { process.stderr.write(`[vigil] ${error.message}\n`); process.exitCode = 1 }
