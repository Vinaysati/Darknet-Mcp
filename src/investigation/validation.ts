import { createHash } from "node:crypto";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** Mainnet Bitcoin Base58Check and SegWit Bech32/Bech32m addresses only. */
export function normalizeBitcoin(value: string): string | null {
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(value)) {
    let decoded = 0n;
    for (const char of value) decoded = decoded * 58n + BigInt(BASE58.indexOf(char));
    const hex = decoded.toString(16).padStart(Math.ceil(decoded.toString(16).length / 2) * 2, "0");
    const bytes = Buffer.concat([Buffer.alloc(value.match(/^1*/)?.[0].length ?? 0), Buffer.from(hex, "hex")]);
    if (bytes.length !== 25 || ![0, 5].includes(bytes[0]!)) return null;
    const checksum = createHash("sha256").update(createHash("sha256").update(bytes.subarray(0, 21)).digest()).digest().subarray(0, 4);
    return checksum.equals(bytes.subarray(21)) ? value : null;
  }
  if (value !== value.toLowerCase() && value !== value.toUpperCase()) return null;
  const address = value.toLowerCase();
  if (!/^bc1[023456789acdefghjklmnpqrstuvwxyz]{11,87}$/.test(address) || address.length > 90) return null;
  const data = [...address.slice(3)].map((char) => BECH32.indexOf(char));
  if (data.some((v) => v < 0)) return null;
  // BIP-173 HRP expansion for 'bc', followed by the witness data and checksum.
  let polymod = 1;
  for (const item of [3, 3, 0, 2, 3, ...data]) {
    const top = polymod >>> 25;
    polymod = ((polymod & 0x1ffffff) << 5) ^ item;
    for (const [index, generator] of [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3].entries()) if ((top >>> index) & 1) polymod ^= generator;
  }
  const version = data[0]!;
  if (version > 16 || (polymod >>> 0) !== (version === 0 ? 1 : 0x2bc830a3)) return null;
  let accumulator = 0;
  let bits = 0;
  const program: number[] = [];
  for (const item of data.slice(1, -6)) {
    accumulator = ((accumulator << 5) | item) & 0xffffff;
    bits += 5;
    while (bits >= 8) { bits -= 8; program.push((accumulator >>> bits) & 255); }
  }
  if (bits >= 5 || ((accumulator << (8 - bits)) & 255) !== 0 || program.length < 2 || program.length > 40 || (version === 0 && ![20, 32].includes(program.length))) return null;
  return address;
}

/** Verify the v3 onion public key, checksum and version (Tor address spec). */
export function normalizeOnion(hostname: string): string | null {
  const normalized = hostname.toLowerCase();
  if (!/^[a-z2-7]{56}\.onion$/.test(normalized)) return null;
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let accumulator = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const char of normalized.slice(0, 56)) {
    accumulator = ((accumulator << 5) | alphabet.indexOf(char)) & 0xffffff;
    bits += 5;
    while (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  const address = Buffer.from(bytes);
  if (address[34] !== 3) return null;
  const checksum = createHash("sha3-256").update(Buffer.concat([Buffer.from(".onion checksum"), address.subarray(0, 32), Buffer.from([3])])).digest().subarray(0, 2);
  return checksum.equals(address.subarray(32, 34)) ? normalized : null;
}
