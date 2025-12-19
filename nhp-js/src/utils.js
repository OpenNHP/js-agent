
export function stringToBytes(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

export function bytesToString(bytes) {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

export function bytesToBase64(bytes) {
    const bin = "";
    bytes.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin);
}

export function base64ToBytes(base64) {
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
}

export function getUnixNano() {
  const ms = Date.now(); // milliseconds since Unix epoch
  const subMs = performance.now() % 1; // fractional milliseconds
  return BigInt(ms) * 1_000_000n + BigInt(Math.floor(subMs * 1_000_000));
}
