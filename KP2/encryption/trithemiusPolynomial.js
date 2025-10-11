import { alphabets } from "./utils.js";

export class TrithemiusPolynomialCipher {
  constructor([A, B, C]) {
    if (![A, B, C].every((n) => Number.isInteger(n)))
      throw new Error(
        "Ключ поліноміального шифру повинен бути трьома числами [A,B,C]"
      );
    this.A = A;
    this.B = B;
    this.C = C;
  }

  #getShift(pos) {
    return this.A * pos * pos + this.B * pos + this.C;
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
            const k = this.#getShift(i);
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
