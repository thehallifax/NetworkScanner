import { CredentialSet } from "../types.js";

export function redactCredentials(creds: CredentialSet[]) {
  return creds.map((cred) => ({
    id: cred.id,
    username: cred.username,
    password: cred.password ? "***" : undefined,
    sshKeyPath: cred.sshKeyPath ? "***" : undefined,
    privateKey: cred.privateKey ? "***" : undefined,
    passphrase: cred.passphrase ? "***" : undefined,
    useAgent: cred.useAgent ? true : undefined,
    description: cred.description
  }));
}
