const PASS_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** 12 characters from an alphabet without look-alikes, without modulo bias. */
export function generatePassphrase(length = 12): string {
  const limit = 256 - (256 % PASS_ALPHABET.length);
  const out: string[] = [];
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < length) out.push(PASS_ALPHABET[b % PASS_ALPHABET.length] ?? "");
    }
  }
  return out.join("");
}
