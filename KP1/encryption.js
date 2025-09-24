class CaesarCipher {
  static #alphabets = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split(""),
    "abcdefghijklmnopqrstuvwxyz".split(""),
    "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ".split(""),
    "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя".split(""),
    ".,!?;:()[]{}<>/\\|+-=_*^%$#@&~`'\"".split(""),
    "0123456789",
  ];

  static #MAX_ALPHABET = Math.max(
    ...CaesarCipher.#alphabets.map((a) => a.length)
  );

  constructor(key) {
    this.key = this.normalizeKey(key);
  }

  static #caesarCipher(str, shift, decrypt = false) {
    return [...str]
      .map((ch) => {
        for (let alpha of CaesarCipher.#alphabets) {
          let idx = alpha.indexOf(ch);
          if (idx !== -1) {
            let n = decrypt ? -shift : shift;
            return alpha[(idx + n + alpha.length) % alpha.length];
          }
        }
        return ch;
      })
      .join("");
  }

  normalizeKey(shift) {
    if (typeof shift !== "number" || !Number.isInteger(shift)) {
      throw new Error("Ключ має бути цілим числом");
    }
    let normalized =
      ((shift % CaesarCipher.#MAX_ALPHABET) + CaesarCipher.#MAX_ALPHABET) %
      CaesarCipher.#MAX_ALPHABET;
    if (normalized === 0)
      throw new Error("Ключ після нормалізації не може бути 0");
    return normalized;
  }

  validateText(str) {
    if (typeof str !== "string") throw new Error("Дані повинні бути рядком");
    if (str.length === 0) throw new Error("Рядок не може бути порожнім");
    return true;
  }

  encrypt(str) {
    this.validateText(str);
    return {
      text: CaesarCipher.#caesarCipher(str, this.key, false),
      key: this.key,
    };
  }

  decrypt(str) {
    this.validateText(str);
    return {
      text: CaesarCipher.#caesarCipher(str, this.key, true),
      key: this.key,
    };
  }

  static bruteForce(str) {
    if (typeof str !== "string" || str.length === 0)
      throw new Error("Дані повинні бути непорожнім рядком");
    const results = [];
    for (let k = 1; k < CaesarCipher.#MAX_ALPHABET; k++) {
      try {
        const decrypted = CaesarCipher.#caesarCipher(str, k, true);
        results.push({ key: k, text: decrypted });
      } catch {}
    }
    return results;
  }
}
