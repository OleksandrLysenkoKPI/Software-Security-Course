import { CaesarCipher } from "../encryption/caesar.js";
import { AffineCipher } from "../encryption/affine.js";
import { PolynomialTrithemius } from "../encryption/trithemiusPolynomial.js";
import { PasswordTrithemius } from "../encryption/trithemiusPassword.js";

console.log("=== Encryption System Test ===");

const sample = "Hello, Світ! 123";

// Caesar
const c = new CaesarCipher(3);
const encC = c.encrypt(sample).text;
console.log("Caesar enc:", encC);
console.log("Caesar dec:", c.decrypt(encC).text);

// Affine
const a = new AffineCipher([5, 8]);
const encA = a.encrypt("abcXYZ").text;
console.log("Affine enc:", encA);
console.log("Affine dec:", a.decrypt(encA).text);

// Polynomial Trithemius
const p = new PolynomialTrithemius([1, 2, 3]);
const encP = p.encrypt("abcdefАБВГ").text;
console.log("Poly enc:", encP);
console.log("Poly dec:", p.decrypt(encP).text);

// Password Trithemius
const pass = new PasswordTrithemius("KeyКлюч1");
const encT = pass.encrypt("Hello Привіт!").text;
console.log("Pwd enc:", encT);
console.log("Pwd dec:", pass.decrypt(encT).text);

console.log("=== End Tests ===");
