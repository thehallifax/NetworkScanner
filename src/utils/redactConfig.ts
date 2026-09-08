export function redactConfig(text: string) {
  const patterns = [
    /(password\s+)(\S+)/gi,
    /(secret\s+)(\S+)/gi,
    /(key\s+)(\S+)/gi,
    /(community\s+)(\S+)/gi,
    /(snmp-server\s+community\s+)(\S+)/gi,
    /(tacacs\s+)(\S+)/gi,
    /(radius\s+)(\S+)/gi,
    /(wpa\s+)(\S+)/gi,
    /(psk\s+)(\S+)/gi,
    /(pre-shared\s+)(\S+)/gi,
    /(enable\s+secret\s+)(\S+)/gi,
    /(username\s+\S+\s+(?:secret|password)\s+)(\S+)/gi
  ];

  let redacted = text;
  for (const pattern of patterns) {
    redacted = redacted.replace(pattern, (_match, prefix, value) => {
      if (!value) return prefix;
      return `${prefix}***REDACTED***`;
    });
  }
  return redacted;
}
