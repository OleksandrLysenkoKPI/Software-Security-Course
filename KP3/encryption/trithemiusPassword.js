import { alphabets } from "./utils.js";

export class TrithemiusPasswordCipher {
  constructor(password) {
    if (typeof password !== "string" || password.length === 0)
      throw new Error("Гасло не може бути порожнім");
    this.password = password;
  }

  #getShift(pos, alphaLength) {
    const ch = this.password[pos % this.password.length];
    return ch.charCodeAt(0) % alphaLength;
  }

  encrypt(text) {
    return this.#process(text, false);
  }

  decrypt(text) {
    return this.#process(text, true);
  }

  #process(text, decrypt = false) {
    return [...text]
      .map((ch, i) => {
        for (let alpha of alphabets) {
          const idx = alpha.indexOf(ch);
          if (idx !== -1) {
            const k = this.#getShift(i, alpha.length);
            return alpha[
              (idx + (decrypt ? alpha.length - (k % alpha.length) : k)) %
                alpha.length
            ];
          }
        }
        return ch;
      })
      .join("");
  }
}
