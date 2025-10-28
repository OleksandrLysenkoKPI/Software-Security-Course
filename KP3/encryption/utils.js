export const alphabets = [
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split(""),
  "abcdefghijklmnopqrstuvwxyz".split(""),
  "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ".split(""),
  "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя".split(""),
  ".,!?;:()[]{}<>/\\|+-=_*^%$#@&~`'\"".split(""),
  "0123456789".split(""),
];

export const MAX_ALPHABET = Math.max(...alphabets.map((a) => a.length));

export const Util = {
  egcd(a, b) {
    if (b === 0) return { g: a, x: 1, y: 0 };
    const { g, x: x1, y: y1 } = Util.egcd(b, a % b);
    return { g, x: y1, y: x1 - Math.floor(a / b) * y1 };
  },
  modInv(a, m) {
    const { g, x } = Util.egcd(((a % m) + m) % m, m);
    if (g !== 1) return null;
    return ((x % m) + m) % m;
  },
  clamp(n, m) {
    return ((n % m) + m) % m;
  },
  findAlpha(ch) {
    for (let i = 0; i < alphabets.length; i++) {
      const idx = alphabets[i].indexOf(ch);
      if (idx !== -1) return { alphabet: alphabets[i], idx, alphaIndex: i };
    }
    return null;
  },
};
