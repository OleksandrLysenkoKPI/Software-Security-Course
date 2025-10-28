import { alphabets } from "./utils.js";

export class TrithemiusLinearCipher {
  constructor([A, B]) {
    if (![A, B].every((n) => Number.isInteger(n)))
      throw new Error(
        "Ключ лінійного шифру повинен бути двома цілими числами [A,B]"
      );
    this.A = A;
    this.B = B;
  }

  #getShift(pos) {
    return this.A * pos + this.B;
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
