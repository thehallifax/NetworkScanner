import fs from "fs";
import { Client, type Algorithms } from "ssh2";
import { CredentialSet, Logger } from "../types.js";
import net from "net";

function loadPrivateKey(sshKeyPath?: string) {
  if (!sshKeyPath) return undefined;
  return fs.readFileSync(sshKeyPath, "utf8");
}

function buildAuthOptions(credential: CredentialSet) {
  if (credential.useAgent) {
    const agent = process.env.SSH_AUTH_SOCK;
    if (!agent) {
      throw new Error("SSH agent requested but SSH_AUTH_SOCK is not set");
    }
    return {
      username: credential.username,
      agent,
      agentForward: false
    };
  }

  return {
    username: credential.username,
    password: credential.password,
    privateKey: credential.privateKey ?? loadPrivateKey(credential.sshKeyPath),
    passphrase: credential.passphrase
  };
}

function buildAuthHandler(credential: CredentialSet) {
  if (!credential.password) return undefined;
  return (methodsLeft: string[] | null, _partialSuccess: boolean, callback: (methods: string[]) => void) => {
    const available = methodsLeft ?? [];
    const ordered = ["keyboard-interactive", "password"].filter((method) => available.includes(method));
    callback(ordered.length ? ordered : available);
  };
}

export type SshProfile = "modern" | "legacy" | "legacy-cisco";
export type SshMode = "auto" | "force-modern" | "force-legacy" | "force-legacy-cisco";

const profileCache = new Map<string, SshProfile>();

function stripAnsi(output: string) {
  const ansi = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;
  return output.replace(ansi, "");
}

function stripShellOutput(output: string, command: string) {
  let cleaned = stripAnsi(output);
  cleaned = cleaned.replace(/--\s*MORE\s*--[^\r\n]*/gi, "");
  cleaned = cleaned.replace(/Press any key to continue/gi, "");
  const commands = command
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  let lines = cleaned.split(/\r?\n/);
  lines = lines.filter((line) => !/--\s*MORE\s*--/i.test(line));
  lines = lines.filter((line) => !/Press any key to continue/i.test(line));
  lines = lines.filter((line) => !/^\S+[>#]\s*$/.test(line.trim()));
  lines = lines.filter((line) => {
    if (!/^\S+[>#]\s+/.test(line)) return true;
    return !commands.some((cmd) => cmd && line.toLowerCase().includes(cmd.toLowerCase()));
  });
  const bannerLine = lines.find((line) => /Aruba\s+\S+.+\s+Switch/i.test(line));
  const commandIndex = lines.findIndex((line) =>
    commands.some((cmd) => cmd && line.toLowerCase().includes(cmd.toLowerCase()))
  );
  if (commandIndex >= 0) {
    lines = lines.slice(commandIndex + 1);
  }
  lines = lines.filter((line) => !commands.includes(line.trim()));
  while (lines.length > 0 && /[>#]\s*$/.test(lines[lines.length - 1].trim())) {
    lines.pop();
  }
  if (bannerLine && !lines.includes(bannerLine)) {
    lines.unshift(bannerLine.trim());
  }
  return lines.join("\n").trim();
}

function shellHasPrompt(output: string) {
  const lines = output.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (!lines.length) return false;
  return /[>#]\s*$/.test(lines[lines.length - 1].trim());
}

function buildAlgorithms(profile?: SshProfile): Algorithms | undefined {
  if (!profile || profile === "modern") return undefined;
  if (profile === "legacy-cisco") {
    return {
      kex: [
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1"
      ] as Algorithms["kex"],
      serverHostKey: ["ssh-rsa", "ssh-dss"] as Algorithms["serverHostKey"],
      cipher: ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"] as Algorithms["cipher"],
      hmac: ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "hmac-sha2-256", "hmac-sha2-512"] as Algorithms["hmac"]
    };
  }

  return {
    kex: ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"] as Algorithms["kex"],
    serverHostKey: ["ssh-rsa"] as Algorithms["serverHostKey"],
    cipher: ["aes128-cbc", "aes192-cbc", "aes256-cbc"] as Algorithms["cipher"],
    hmac: ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "hmac-sha2-256", "hmac-sha2-512"] as Algorithms["hmac"]
  };
}

function isMismatchError(message: string) {
  const lower = message.toLowerCase();
  return (
    lower.includes("no matching key exchange algorithm")
    || lower.includes("handshake failed")
    || lower.includes("timed out while waiting for handshake")
    || lower.includes("no matching cipher")
    || lower.includes("no matching mac")
  );
}

function profilesForMode(mode?: SshMode): SshProfile[] {
  switch (mode) {
    case "force-modern":
      return ["modern"];
    case "force-legacy":
      return ["legacy"];
    case "force-legacy-cisco":
      return ["legacy-cisco"];
    default:
      return ["modern", "legacy-cisco", "legacy"];
  }
}

function enhanceError(err: Error) {
  if (err.message.includes("no matching key exchange algorithm")) {
    return new Error(`${err.message}. Try sshMode=force-legacy-cisco`);
  }
  return err;
}

function isNonRetryableNetworkError(message: string) {
  const lower = message.toLowerCase();
  return (
    lower.includes("eneturreach")
    || lower.includes("ehostunreach")
    || lower.includes("enetdown")
    || lower.includes("eaddrnotavail")
    || lower.includes("no route to host")
    || lower.includes("econnreset")
  );
}

export async function tcpProbe(host: string, timeoutMs: number) {
  return new Promise<void>((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };

    socket.setTimeout(timeoutMs);
    socket.once("error", onError);
    socket.once("timeout", () => onError(new Error("ETIMEDOUT")));
    socket.connect(22, host, () => {
      if (settled) return;
      settled = true;
      socket.end();
      resolve();
    });
  });
}

export function execSSH(
  host: string,
  command: string,
  credential: CredentialSet,
  timeoutMs: number,
  sshProfile?: SshProfile,
  debugSsh?: boolean,
  logger?: Logger,
  connectTimeoutMs?: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      conn.end();
      if (debugSsh) {
        logger?.({
          ts: new Date().toISOString(),
          level: "warn",
          scope: "ssh",
          message: `SSH error: ${enhanceError(err).message}`,
          meta: { host, profile: sshProfile || "modern" }
        });
      }
      reject(enhanceError(err));
    };

    conn
      .on("connect", () => {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "ssh",
          message: "SSH connect attempt",
          meta: { host, profile: sshProfile || "modern" }
        });
      })
      .on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
        if (debugSsh) {
          logger?.({
            ts: new Date().toISOString(),
            level: "debug",
            scope: "ssh",
            message: "Keyboard-interactive prompts received",
            meta: { host, promptCount: prompts.length }
          });
        }
        const reply = prompts.map((prompt) => {
          if (/user(name)?/i.test(prompt.prompt)) return credential.username ?? "";
          return credential.password ?? "";
        });
        finish(reply);
      })
      .on("ready", () => {
        conn.exec(command, { pty: true }, (err, stream) => {
          if (err) return onError(err);
          let output = "";
          stream
            .on("close", () => {
              if (settled) return;
              settled = true;
              conn.end();
              resolve(output);
            })
            .on("data", (data: Buffer) => {
              output += data.toString("utf8");
            })
            .stderr.on("data", (data: Buffer) => {
              output += data.toString("utf8");
            });
        });
      })
      .on("error", onError)
      .connect({
        host,
        ...buildAuthOptions(credential),
        tryKeyboard: Boolean(credential.password),
        authHandler: buildAuthHandler(credential) as any,
        algorithms: buildAlgorithms(sshProfile),
        readyTimeout: connectTimeoutMs ?? timeoutMs
      });

    setTimeout(() => onError(new Error("SSH command timeout")), timeoutMs + 1000);
  });
}

export function execShell(
  host: string,
  command: string,
  credential: CredentialSet,
  timeoutMs: number,
  sshProfile?: SshProfile,
  debugSsh?: boolean,
  logger?: Logger,
  connectTimeoutMs?: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    let sent = false;
    let gotPrompt = false;
    let idleTimer: NodeJS.Timeout | null = null;
    let sawData = false;
    let moreCount = 0;
    let handledContinue = false;

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      conn.end();
      if (debugSsh) {
        logger?.({
          ts: new Date().toISOString(),
          level: "warn",
          scope: "ssh",
          message: `SSH error: ${enhanceError(err).message}`,
          meta: { host, profile: sshProfile || "modern" }
        });
      }
      reject(enhanceError(err));
    };

    conn
      .on("connect", () => {
        logger?.({
          ts: new Date().toISOString(),
          level: "debug",
          scope: "ssh",
          message: "SSH connect attempt",
          meta: { host, profile: sshProfile || "modern" }
        });
      })
      .on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
        const reply = prompts.map(() => credential.password ?? "");
        finish(reply);
      })
      .on("ready", () => {
        conn.shell({ term: "xterm", rows: 24, cols: 80 }, (err, stream) => {
          if (err) return onError(err);
          let output = "";
          const commands = command
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);

          const closeAndResolve = () => {
            if (settled) return;
            settled = true;
            conn.end();
            resolve(stripShellOutput(output, command));
          };

          const sendCommand = () => {
            if (sent) return;
            const payload = command.endsWith("\n") ? command : `${command}\n`;
            stream.write(payload.replace(/\n/g, "\r\n"));
            sent = true;
          };

          const scheduleIdleClose = () => {
            if (idleTimer) clearTimeout(idleTimer);
            idleTimer = setTimeout(() => {
              closeAndResolve();
            }, 800);
          };

          stream
            .on("close", () => {
              closeAndResolve();
            })
            .on("data", (data: Buffer) => {
              output += data.toString("utf8");
              sawData = true;
              if (/--\s*MORE\s*--/i.test(output) && moreCount < 50) {
                moreCount += 1;
                stream.write(" ");
              }
              if (/Press any key to continue/i.test(output) && !handledContinue) {
                handledContinue = true;
                stream.write("\r\n");
              }
              if (!gotPrompt && shellHasPrompt(output)) {
                gotPrompt = true;
                sendCommand();
              }
              if (sent && shellHasPrompt(output) && !/--\s*MORE\s*--/i.test(output) && !/Press any key to continue/i.test(output)) {
                closeAndResolve();
                return;
              }
              if (!/--\s*MORE\s*--/i.test(output)) {
                scheduleIdleClose();
              }
            })
            .stderr.on("data", (data: Buffer) => {
              output += data.toString("utf8");
              sawData = true;
              if (!/--\s*MORE\s*--/i.test(output)) {
                scheduleIdleClose();
              }
            });

          stream.write("\r\n");
          setTimeout(() => {
            if (!sent) sendCommand();
          }, 500);
        });
      })
      .on("error", onError)
      .connect({
        host,
        ...buildAuthOptions(credential),
        tryKeyboard: Boolean(credential.password),
        authHandler: buildAuthHandler(credential) as any,
        algorithms: buildAlgorithms(sshProfile),
        readyTimeout: connectTimeoutMs ?? timeoutMs
      });

    setTimeout(() => onError(new Error("SSH command timeout")), timeoutMs + 1000);
  });
}

export async function execSSHWithProfileFallback(
  host: string,
  command: string,
  credential: CredentialSet,
  timeoutMs: number,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
) {
  if (tcpProbeTimeoutMs) {
    await tcpProbe(host, tcpProbeTimeoutMs);
  }
  const cached = sshMode === "auto" ? profileCache.get(host) : undefined;
  const profiles = cached ? [cached] : profilesForMode(sshMode);
  let lastError: Error | undefined;

  for (let i = 0; i < profiles.length; i += 1) {
    const profile = profiles[i];
    try {
      const result = await execSSH(host, command, credential, timeoutMs, profile, debugSsh, logger, connectTimeoutMs);
      if (sshMode === "auto") profileCache.set(host, profile);
      return result;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      const message = lastError.message;
      if (sshMode !== "auto") break;
      if (!isMismatchError(message)) break;
      const nextProfile = profiles[i + 1];
      if (nextProfile) {
        logger?.({
          ts: new Date().toISOString(),
          level: "warn",
          scope: "ssh",
          message: "SSH handshake mismatch, retrying with legacy",
          meta: { host, fromProfile: profile, toProfile: nextProfile }
        });
        continue;
      }
      break;
    }
  }

  if (lastError) throw lastError;
  throw new Error("SSH command failed");
}

export async function execShellWithProfileFallback(
  host: string,
  command: string,
  credential: CredentialSet,
  timeoutMs: number,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number
) {
  if (tcpProbeTimeoutMs) {
    await tcpProbe(host, tcpProbeTimeoutMs);
  }
  const profiles = profilesForMode(sshMode);
  let lastError: Error | undefined;

  for (let i = 0; i < profiles.length; i += 1) {
    const profile = profiles[i];
    try {
      return await execShell(host, command, credential, timeoutMs, profile, debugSsh, logger, connectTimeoutMs);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      const message = lastError.message;
      if (sshMode !== "auto") break;
      if (!isMismatchError(message)) break;
      const nextProfile = profiles[i + 1];
      if (nextProfile) {
        logger?.({
          ts: new Date().toISOString(),
          level: "warn",
          scope: "ssh",
          message: "SSH handshake mismatch, retrying with legacy",
          meta: { host, fromProfile: profile, toProfile: nextProfile }
        });
        continue;
      }
      break;
    }
  }

  if (lastError) throw lastError;
  throw new Error("SSH command failed");
}

export async function connectWithFallback(
  host: string,
  commands: string[],
  credentials: CredentialSet[],
  timeoutMs: number,
  sshMode?: SshMode,
  debugSsh?: boolean,
  logger?: Logger,
  tcpProbeTimeoutMs?: number,
  connectTimeoutMs?: number,
  useShell?: boolean
) {
  const failures = new Map<string, string>();
  const cached = sshMode === "auto" ? profileCache.get(host) : undefined;
  const profiles = cached ? [cached] : profilesForMode(sshMode);
  const exec = useShell ? execShell : execSSH;

  for (const credential of credentials) {
    for (let i = 0; i < profiles.length; i += 1) {
      const profile = profiles[i];
      try {
        if (tcpProbeTimeoutMs) {
          await tcpProbe(host, tcpProbeTimeoutMs);
        }
        const outputs: string[] = [];
        for (const command of commands) {
          outputs.push(
            await exec(host, command, credential, timeoutMs, profile as SshProfile, debugSsh, logger, connectTimeoutMs)
          );
        }
        if (sshMode === "auto") profileCache.set(host, profile as SshProfile);
        return { outputs, credentialId: credential.id };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (debugSsh) {
          logger?.({
            ts: new Date().toISOString(),
            level: "warn",
            scope: "ssh",
            message: `Credential failed: ${message}`,
            meta: { host, credId: credential.id, profile }
          });
        }
        if (isNonRetryableNetworkError(message)) {
          throw new Error(`Unreachable: ${message}`);
        }
        if (sshMode === "auto") {
          const mismatch = isMismatchError(message);
          if (!mismatch) break;
          if (mismatch) {
            const nextProfile = profiles[i + 1];
            if (nextProfile) {
              logger?.({
                ts: new Date().toISOString(),
                level: "warn",
                scope: "ssh",
                message: "SSH handshake mismatch, retrying with legacy",
                meta: { host, fromProfile: profile, toProfile: nextProfile }
              });
              continue;
            }
          }
        }
        failures.set(credential.id, message);
      }
    }
  }

  const summary = Array.from(failures.entries())
    .map(([id, message]) => `${id}: '${message}'`)
    .join(", ");
  throw new Error(`All credentials failed: {${summary}}`);
}
