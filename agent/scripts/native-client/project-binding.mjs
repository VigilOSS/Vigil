// Frozen project dispatcher protocol v1. A project selects NEW tasks only.
import {fstatSync, readSync, realpathSync, mkdirSync, openSync, closeSync,
  writeFileSync, linkSync, unlinkSync, constants} from "node:fs"
import {join, dirname, isAbsolute, relative, resolve} from "node:path"
import {createHash, randomUUID} from "node:crypto"

export const digest = value => createHash("sha256").update(value).digest("hex")
export const regular = path => {
  if (!isAbsolute(path) || realpathSync(dirname(path)) !== dirname(path)) throw new Error("Noncanonical managed path")
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const before = fstatSync(fd)
    if (!before.isFile() || before.size > 8 * 1024 * 1024) throw new Error("Invalid managed file")
    const bytes = Buffer.alloc(before.size + 1)
    let length = 0
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null)
      if (!count) break
      length += count
    }
    const after = fstatSync(fd)
    if (length !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) throw new Error("Managed file changed during read")
    return bytes.subarray(0, length)
  } finally { closeSync(fd) }
}
const object = path => {
  const value = JSON.parse(regular(path))
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid managed object")
  return value
}
export const attest = root => {
  const files = object(join(root, ".vigil-managed-files.json"))
  if (!Object.keys(files).length || Object.keys(files).length > 1024) throw new Error("Invalid manifest inventory")
  for (const [name, expected] of Object.entries(files)) {
    if (!name || isAbsolute(name) || relative(root, resolve(root, name)) !== name
        || !/^[a-f0-9]{64}$/.test(expected) || digest(regular(join(root, name))) !== expected)
      throw new Error("Managed assets differ from their recorded content digests")
  }
  return files
}
export const projectInfo = project => {
  if (realpathSync(project) !== project) throw new Error("Noncanonical project")
  const info = object(join(project, ".vigil-client-project.json"))
  if (info.schema_version !== 1 || info.protocol !== 1 || info.project !== project
      || !["zcode", "opencode"].includes(info.client) || !["web", "code"].includes(info.mode)
      || typeof info.engagement_key !== "string" || !info.engagement_key
      || info.engagement_key === "." || info.engagement_key === ".." || info.engagement_key.includes("/")
      || project !== join(info.engagement_dir, "clients", info.client, info.mode)
      || typeof info.engagements_root !== "string" || !isAbsolute(info.engagements_root)
      || info.engagement_dir !== join(info.engagements_root, info.engagement_key))
    throw new Error("Project identity mismatch")
  const files = attest(project)
  for (const name of [".vigil-client-project.json", "AGENTS.md", "bin/vigil", "vigil-project.mjs", "bootstrap.mjs"])
    if (!files[name]) throw new Error("Project manifest omits required assets")
  return info
}
export const bindingInfo = (path, project, expectedDigest) => {
  const info = projectInfo(project)
  const bytes = regular(path)
  if (expectedDigest && digest(bytes) !== expectedDigest) throw new Error("Task binding digest mismatch")
  const binding = JSON.parse(bytes)
  if (binding.schema_version !== 1 || binding.project !== project
      || path !== join(binding.workspace, ".vigil-client-context.json")
      || dirname(dirname(binding.workspace)) !== join(info.engagement_dir, "client-context")
      || !/^[a-f0-9]{24}$/.test(dirname(binding.workspace).split("/").at(-1))
      || binding.workspace.split("/").at(-1) !== info.client
      || !/^[a-f0-9]{64}$/.test(binding.release_id)
      || binding.vigil_cli !== join(binding.workspace, "bin/vigil")
      || binding.agent_root !== join(binding.application?.root || "", "agent"))
    throw new Error("Invalid task context")
  for (const key of ["client", "mode", "install_root", "engagement_dir", "engagement_key"])
    if (binding[key] !== info[key]) throw new Error("Task and project identities differ")
  const files = attest(binding.workspace)
  for (const name of [".vigil-client-context.json", "AGENTS.md", "bin/vigil"])
    if (!files[name]) throw new Error("Context manifest omits required assets")
  return {...binding, binding_path: path, binding_sha256: digest(bytes)}
}
export const currentBinding = project => {
  const row = object(join(project, ".vigil-current-context.json"))
  if (row.schema_version !== 1 || !/^[a-f0-9]{64}$/.test(row.binding_sha256)) throw new Error("Invalid new-task selection")
  return bindingInfo(row.binding_path, project, row.binding_sha256)
}
export const receiptPath = (project, client, session) =>
  join(project, ".vigil-sessions", client, digest(session) + ".json")
export const readSession = (project, client, session, path = receiptPath(project, client, session)) => {
  let row
  try { row = object(path) } catch (error) { if (error.code === "ENOENT") return null; throw error }
  if (row.schema_version !== 1 || row.client !== client || row.session_id !== session || row.project !== project
      || typeof row.binding_path !== "string" || !isAbsolute(row.binding_path)
      || typeof row.binding_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(row.binding_sha256))
    throw new Error("Native session project mismatch")
  return bindingInfo(row.binding_path, project, row.binding_sha256)
}
export const bindSession = (project, client, session, binding, path = receiptPath(project, client, session)) => {
  const previous = readSession(project, client, session, path)
  if (previous) return previous
  const parent = dirname(path)
  mkdirSync(parent, {recursive: true, mode: 0o700})
  if (realpathSync(parent) !== parent) throw new Error("Unsafe native receipt directory")
  const temporary = path + "." + randomUUID() + ".tmp"
  let created = false
  try {
    const fd = openSync(temporary, "wx", 0o600)
    created = true
    try {
      writeFileSync(fd, JSON.stringify({schema_version: 1, client, session_id: session, project,
        binding_path: binding.binding_path, binding_sha256: binding.binding_sha256}))
    } finally { closeSync(fd) }
    try { linkSync(temporary, path) } catch (error) { if (error.code !== "EEXIST") throw error }
  } finally {
    if (created) {
      try { unlinkSync(temporary) } catch (error) { if (error.code !== "ENOENT") throw error }
    }
  }
  return readSession(project, client, session, path)
}
export const findProject = cwd => {
  if (typeof cwd !== "string" || !isAbsolute(cwd)) return null
  let path = realpathSync(cwd)
  while (true) {
    try { regular(join(path, ".vigil-client-project.json")); return path }
    catch (error) { if (error.code !== "ENOENT") throw error }
    if (dirname(path) === path) return null
    path = dirname(path)
  }
}
