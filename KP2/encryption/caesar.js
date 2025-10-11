import { alphabets, MAX_ALPHABET } from "./utils.js";

export class CaesarCipher {
  constructor(key) {
    this.key = this.normalizeKey(key);
  }

  normalizeKey(k) {
    if (!Number.isInteger(k)) throw new Error("Ключ має бути цілим числом");
    const n = ((k % MAX_ALPHABET) + MAX_ALPHABET) % MAX_ALPHABET;
    if (n === 0) throw new Error("Ключ не може бути 0");
    return n;
  }

  static #shift(str, shift, decrypt = false) {
    return [...str]
      .map((ch) => {
        for (let alpha of alphabets) {
          const idx = alpha.indexOf(ch);
          if (idx !== -1) {
            const n = decrypt ? -shift : shift;
            return alpha[(idx + n + alpha.length) % alpha.length];
          }
        }
        return ch;
      })
      .join("");
  }

  encrypt(str) {
    if (!str) throw new Error("Порожній рядок");
    return { text: CaesarCipher.#shift(str, this.key), key: this.key };
  }

  decrypt(str) {
    if (!str) throw new Error("Порожній рядок");
    return { text: CaesarCipher.#shift(str, this.key, true), key: this.key };
  }

  static bruteForce(str) {
    const results = [];
    for (let k = 1; k < MAX_ALPHABET; k++) {
      results.push({ key: k, text: CaesarCipher.#shift(str, k, true) });
    }
    return results;
  }
}
