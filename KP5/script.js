/*
  Реалізація Merkle–Hellman:
  - W: суперзростаюча послідовність (закритий)
  - q: модуль > sum(W)
  - r: множник, gcd(r,q)=1
  - A: публічний ключ A[i] = (r * W[i]) mod q
  - r_inv: обернений множник modulo q (обчислюється через розширений Евклід)
  Шифрування: для кожного n-бітного блоку: c = sum(bit_i * A[i])
  Розшифрування: c' = c * r_inv mod q; потім жадібно розбити c' по W.
*/

let W = [], q = 0, r = 0, r_inv = 0, A = [], n = 8;

const log = (s) => {
  const la = document.getElementById('logArea');
  la.textContent = s + "\n\n" + la.textContent;
}

/* ---------- math helpers ---------- */

function gcd(a,b){
  a = Math.abs(a); b = Math.abs(b);
  while(b) { [a,b] = [b, a % b]; }
  return a;
}

// розширений Евклід: повертає {g, x, y} для ax + by = g
function egcd(a,b){
  if (b === 0) return {g: a, x: 1, y: 0};
  let {g, x: x1, y: y1} = egcd(b, a % b);
  return { g, x: y1, y: x1 - Math.floor(a/b) * y1 };
}

// modular inverse
function modInv(a, m) {
  const {g, x} = egcd(a, m);
  if (g !== 1) return null;
  let inv = x % m;
  if (inv < 0) inv += m;
  return inv;
}

/* ---------- generate superincreasing W ---------- */

function generateSuperincreasing(n) {
  // простий генератор: береться випадкове поступове зростання
  let w = [];
  let s = 0;
  for (let i=0;i<n;i++){
    // вибирається число > s; беремо s + 1..s + rand
    let add = Math.floor(Math.random() * (s+5)) + 1;
    let val = s + add;
    w.push(val);
    s += val;
  }
  return w;
}

/* ---------- key creation ---------- */

function buildPublicKeyFrom(W_local, q_local, r_local) {
  return W_local.map(wi => ( (BigInt(wi) * BigInt(r_local)) % BigInt(q_local) ) * 1n).map(x => Number(x));
}

function setKeys(W_local, q_local, r_local) {
  W = W_local.slice();
  q = q_local;
  r = r_local;
  r_inv = modInv(r, q);
  if (r_inv === null) {
    log("Помилка: r не має оберненого елемента modulo q (не взаємно прості).");
    return false;
  }
  A = buildPublicKeyFrom(W, q, r);
  document.getElementById('privateKey').value = `W = [${W.join(', ')}]\nq = ${q}\nr = ${r}\nr_inv = ${r_inv}`;
  document.getElementById('publicKey').value = A.join(', ');
  log("Ключі згенеровано.");
  return true;
}

/* ---------- UI actions ---------- */

function generateRandomKeys() {
  n = parseInt(document.getElementById('nInput').value) || 8;
  // генерується W
  let Wcand = generateSuperincreasing(n);
  // виберається q > sum(W)
  let sumW = Wcand.reduce((a,b)=>a+b, 0);
  // q: трохи більше суми
  let qcand = sumW + Math.floor(Math.random() * (sumW)) + 1;
  // виберемо r випадково, gcd(r,q)=1
  let rcand = 2 + Math.floor(Math.random() * (qcand - 2));
  // поки gcd !=1 — змінюємо
  let tries = 0;
  while (gcd(rcand, qcand) !== 1 && tries < 1000) {
    rcand = 2 + Math.floor(Math.random() * (qcand - 2));
    tries++;
  }
  if (tries >= 1000) {
    log("Не вдалося підібрати r, спробуйте знову.");
    return;
  }
  setKeys(Wcand, qcand, rcand);
  log(`Згенеровано випадкові ключі (n=${n}). sum(W)=${sumW}, q=${qcand}, r=${rcand}, r_inv=${r_inv}`);
}

function useClassicExample() {
  // чисельний приклад (взято з опису Merkle–Hellman, wiki)
  // W = (2,7,11,21,42,89,180,354), q=881, r=588, r_inv=442
  let W_ex = [2,7,11,21,42,89,180,354];
  let q_ex = 881, r_ex = 588;
  document.getElementById('nInput').value = W_ex.length;
  setKeys(W_ex, q_ex, r_ex);
  log("Завантажено класичний чисельний приклад (Wikipedia).");
}

function createFromManualW() {
  const txt = document.getElementById('manualW').value.trim();
  if (!txt) { alert("Введіть W"); return; }
  const arr = txt.split(',').map(x => parseInt(x.trim())).filter(x=>!isNaN(x) && x>0);
  if (arr.length < 2) { alert("Потрібна принаймні довжина 2"); return; }
  // перевіряється суперзростаюча властивість
  let s = 0, ok = true;
  for (let i=0;i<arr.length;i++){
    if (arr[i] <= s) { ok = false; break; }
    s += arr[i];
  }
  if (!ok) { alert("Послідовність не є суперзростаючою. Перевірте."); return; }
  // обирається q > sum(W)
  let qcand = s + 1 + Math.floor(Math.random() * 50);
  // обирається r coprime
  let rcand = 2 + Math.floor(Math.random() * (qcand - 2));
  while (gcd(rcand, qcand) !== 1) rcand++;
  document.getElementById('nInput').value = arr.length;
  setKeys(arr, qcand, rcand);
  log("Створено ключі з введеної W.");
}

/* ---------- encryption / decryption ---------- */

function textToBinary(str) {
  // повертає бітову строку (ASCII 8-bit per char)
  let bits = [];
  for (let i=0;i<str.length;i++){
    let code = str.charCodeAt(i);
    let s = code.toString(2).padStart(8,'0');
    bits.push(s);
  }
  return bits.join('');
}

function binaryToText(bitStr) {
  // припускається, що bitStr довжина кратна 8
  let res = '';
  for (let i=0;i+7<bitStr.length;i+=8) {
    let byte = bitStr.slice(i, i+8);
    let code = parseInt(byte, 2);
    res += String.fromCharCode(code);
  }
  return res;
}

function chunkString(s, size) {
  let res = [];
  for (let i=0;i<s.length;i+=size) res.push(s.slice(i, i+size));
  return res;
}

function encryptMessage() {
  if (!A || A.length === 0) { alert("Спочатку згенеруйте ключі."); return; }
  n = A.length;
  const mode = document.getElementById('inputMode').value;
  let input = document.getElementById('plainText').value || '';
  let bits = '';
  if (mode === 'text') {
    bits = textToBinary(input);
  } else {
    // binary mode: тільки 0/1
    bits = input.replace(/[^01]/g, '');
  }
  if (bits.length === 0) { alert("Порожнє повідомлення."); return; }
  // pad bits, щоб довжина була кратна n (доповнюється нулями)
  const padLen = (n - (bits.length % n)) % n;
  bits = bits + '0'.repeat(padLen);
  const blocks = chunkString(bits, n);
  const cipherBlocks = blocks.map(block => {
    let sum = 0;
    for (let i=0;i<n;i++){
      if (block[i] === '1') sum += A[i];
    }
    return sum;
  });
  document.getElementById('cipherText').value = cipherBlocks.join(' ');
  log(`Зашифровано ${blocks.length} блок(ів).`);
}

function decryptMessage() {
  if (!W || W.length === 0) { alert("Спочатку згенеруйте ключі."); return; }
  const input = document.getElementById('cipherInput').value.trim();
  if (!input) { alert("Введіть шифротекст"); return; }
  // парсинг чисел
  const parts = input.split(/[\s,;]+/).map(x => x.trim()).filter(x=>x!=='');
  const nums = parts.map(x => parseInt(x,10)).filter(x=>!isNaN(x));
  if (nums.length === 0) { alert("Немає чисел у шифротексті"); return; }
  const nloc = W.length;
  const bitsBlocks = nums.map(c => {
    // c' = c * r_inv mod q
    const cprime = ((BigInt(c) * BigInt(r_inv)) % BigInt(q)) * 1n;
    let S = Number(cprime < 0 ? (cprime + BigInt(q)) : cprime);
    // greedy по W (останній елемент найголовніший)
    let x = new Array(nloc).fill(0);
    for (let i = nloc - 1; i >= 0; i--) {
      if (W[i] <= S) {
        x[i] = 1;
        S -= W[i];
      }
    }
    return x.join('');
  });
  const allBits = bitsBlocks.join('');
  document.getElementById('decryptedBits').value = allBits;
  // перетворення на текст (припускаємо, що бітова довжина кратна 8)
  let text = '';
  if (allBits.length % 8 === 0) text = binaryToText(allBits);
  document.getElementById('decryptedText').value = text;
  log(`Розшифровано ${nums.length} блок(ів).`);
}

function decryptToBinary() {
  decryptMessage();
}

/* ---------- page init ---------- */
document.addEventListener('DOMContentLoaded', () => {
  log("Ви можете згенерувати ключі або завантажити чисельний приклад.");
});