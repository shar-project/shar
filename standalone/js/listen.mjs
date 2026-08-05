export function parseListenAddress(value) {
  if (typeof value !== "string" || value.length === 0)
    throw new Error("SHAR_LISTEN must be a host:port address");

  let host;
  let portText;
  if (value.startsWith("[")) {
    const closing = value.indexOf("]");
    if (closing < 2 || value[closing + 1] !== ":")
      throw new Error("SHAR_LISTEN must be a host:port address");
    host = value.slice(1, closing);
    portText = value.slice(closing + 2);
  } else {
    const separator = value.lastIndexOf(":");
    if (separator < 1)
      throw new Error("SHAR_LISTEN must be a host:port address");
    host = value.slice(0, separator);
    portText = value.slice(separator + 1);
    if (host.includes(":"))
      throw new Error("IPv6 SHAR_LISTEN addresses must use brackets");
  }

  if (!/^[1-9][0-9]{0,4}$/.test(portText))
    throw new Error("SHAR_LISTEN port must be an integer from 1 through 65535");
  const port = Number(portText);
  if (port > 65_535)
    throw new Error("SHAR_LISTEN port must be an integer from 1 through 65535");
  return { host, port };
}

export function listenHealthcheckUrl(value) {
  const { host, port } = parseListenAddress(value);
  const target =
    host === "0.0.0.0" ? "127.0.0.1" : host === "::" ? "::1" : host;
  const authorityHost = target.includes(":") ? `[${target}]` : target;
  return `http://${authorityHost}:${port}/readyz`;
}
