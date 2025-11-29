/* ------------- Числовий (малий) RSA приклад з використанням BigInt ------------- */
function modPow(base, exp, mod) {
  base = BigInt(base);
  exp = BigInt(exp);
  mod = BigInt(mod);
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}
document.getElementById("run-numeric").addEventListener("click", () => {
  // невеликий класичний приклад RSA: p=61, q=53
  const p = 61n,
    q = 53n;
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = 17n;

  // Розширений алгоритм Евкліда
  function egcd(a, b) {
    if (b === 0n) return { g: a, x: 1n, y: 0n };
    const r = egcd(b, a % b);
    return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
  }
  const eg = egcd(e, phi);
  let d = eg.x;
  if (d < 0n) d = ((d % phi) + phi) % phi;
  const m = 65n; // повідомлення
  const c = modPow(m, e, n);
  const m2 = modPow(c, d, n);
  const out = [];
  out.push(`p = ${p}`);
  out.push(`q = ${q}`);
  out.push(`n = p * q = ${n}`);
  out.push(`φ(n) = (p-1)*(q-1) = ${phi}`);
  out.push(`Вибрано e = ${e}`);
  out.push(`Знайдено d = ${d}  (перевірка: (d*e) mod φ(n) = ${(d * e) % phi})`);
  out.push("");
  out.push(`Нехай m = ${m}`);
  out.push(`Шифротекст c = m^e mod n = ${c}`);
  out.push(`Розшифроване m' = c^d mod n = ${m2}`);
  out.push("");
  out.push(`Висновок: m' == m ? ${m2 === m ? "Так" : "Ні"}`);
  document.getElementById("numeric-example").textContent = out.join("\n");
});

/* ------------- Реалізація WebCrypto RSA-OAEP ------------- */

let cryptoKeyPair = null; // містить { publicKey, privateKey } у форматі CryptoKey
let importedPublicKey = null;
let importedPrivateKey = null;

function ab2str(buf) {
  return new TextDecoder().decode(buf);
}
function str2ab(str) {
  return new TextEncoder().encode(str);
}
function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// PEM helpers
function exportPublicKeyToPEM(key) {
  return window.crypto.subtle.exportKey("spki", key).then((spki) => {
    const b64 = arrayBufferToBase64(spki);
    return (
      "-----BEGIN PUBLIC KEY-----\n" +
      b64.match(/.{1,64}/g).join("\n") +
      "\n-----END PUBLIC KEY-----"
    );
  });
}

function exportPrivateKeyToPEM(key) {
  return window.crypto.subtle.exportKey("pkcs8", key).then((pkcs8) => {
    const b64 = arrayBufferToBase64(pkcs8);
    return (
      "-----BEGIN PRIVATE KEY-----\n" +
      b64.match(/.{1,64}/g).join("\n") +
      "\n-----END PRIVATE KEY-----"
    );
  });
}

function importPublicKeyFromPEM(pem) {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\\s+/g, "");
  const der = base64ToArrayBuffer(b64);
  return window.crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}
function importPrivateKeyFromPEM(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\\s+/g, "");
  const der = base64ToArrayBuffer(b64);
  return window.crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

// UI елементи
const btnGenerate = document.getElementById("generate");
const btnExportPub = document.getElementById("export-pub");
const btnExportPriv = document.getElementById("export-priv");
const pubPemArea = document.getElementById("pub-pem");
const privPemArea = document.getElementById("priv-pem");
const btnImportPub = document.getElementById("import-pub");
const inputImportPub = document.getElementById("import-pub-pem");
const btnCopyPubToImport = document.getElementById("copy-pub-to-import");
const btnEncrypt = document.getElementById("encrypt");
const plaintextArea = document.getElementById("plaintext");
const ciphertextArea = document.getElementById("ciphertext");
const btnDecrypt = document.getElementById("decrypt");
const ctToDecrypt = document.getElementById("ct-to-decrypt");
const decryptedArea = document.getElementById("decrypted");
const btnImportPriv = document.getElementById("import-priv");
const inputImportPriv = document.getElementById("import-priv-pem");
const btnClearKeys = document.getElementById("clear-keys");
const btnClearCt = document.getElementById("clear-ct");
const btnDownloadPub = document.getElementById("download-pub");
const btnDownloadPriv = document.getElementById("download-priv");

btnGenerate.addEventListener("click", async () => {
  btnGenerate.disabled = true;
  btnGenerate.textContent = "Генерую...";
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    cryptoKeyPair = keyPair;
    // експортувати в PEM і показати
    const pubPem = await exportPublicKeyToPEM(keyPair.publicKey);
    const privPem = await exportPrivateKeyToPEM(keyPair.privateKey);
    pubPemArea.value = pubPem.replace(/-----.*-----/g, "");
    privPemArea.value = privPem.replace(/-----.*-----/g, "");
    btnExportPub.disabled = false;
    btnExportPriv.disabled = false;
    btnDownloadPub.disabled = false;
    btnDownloadPriv.disabled = false;
    btnImportPub.disabled = false;
    btnEncrypt.disabled = false;
    btnDecrypt.disabled = false;
    alert("Генерація завершена. Публічний і приватний ключі доступні в полях.");
  } catch (e) {
    console.error(e);
    alert("Помилка генерації ключів: " + e);
  } finally {
    btnGenerate.disabled = false;
    btnGenerate.textContent = "Згенерувати пару ключів (2048 b)";
  }
});

btnExportPub.addEventListener("click", async () => {
  if (!cryptoKeyPair) return alert("Спочатку згенеруйте ключі");
  const pem = await exportPublicKeyToPEM(cryptoKeyPair.publicKey);
  pubPemArea.value = pem;
});

btnExportPriv.addEventListener("click", async () => {
  if (!cryptoKeyPair) return alert("Спочатку згенеруйте ключі");
  const pem = await exportPrivateKeyToPEM(cryptoKeyPair.privateKey);
  privPemArea.value = pem;
});

btnDownloadPub.addEventListener("click", () => {
  const pem = pubPemArea.value;
  if (!pem) return alert("Немає публічного ключа для завантаження");
  const blob = new Blob([pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "public.pem";
  a.click();
  URL.revokeObjectURL(url);
});
btnDownloadPriv.addEventListener("click", () => {
  const pem = privPemArea.value;
  if (!pem) return alert("Немає приватного ключа для завантаження");
  const blob = new Blob([pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "private.pem";
  a.click();
  URL.revokeObjectURL(url);
});

btnCopyPubToImport.addEventListener("click", () => {
  inputImportPub.value = pubPemArea.value;
});

// імпорт публічних ключів для шифрування */
btnImportPub.addEventListener("click", async () => {
  const pem = inputImportPub.value.trim();
  if (!pem) return alert("Вставте публічний ключ у полі вище (PEM)");
  try {
    importedPublicKey = await importPublicKeyFromPEM(pem);
    alert("Публічний ключ імпортовано (для шифрування).");
    btnEncrypt.disabled = false;
  } catch (e) {
    console.error(e);
    alert("Помилка імпорту публічного ключа: " + e);
  }
});

// імпорт приватних ключів
btnImportPriv.addEventListener("click", async () => {
  const pem = inputImportPriv.value.trim();
  if (!pem) return alert("Вставте приватний ключ (PEM) у полі вище");
  try {
    importedPrivateKey = await importPrivateKeyFromPEM(pem);
    alert("Приватний ключ імпортовано в сесію (для розшифрування).");
    btnDecrypt.disabled = false;
  } catch (e) {
    console.error(e);
    alert("Помилка імпорту приватного ключа: " + e);
  }
});

btnClearKeys.addEventListener("click", () => {
  cryptoKeyPair = null;
  importedPrivateKey = null;
  importedPublicKey = null;
  pubPemArea.value = "";
  privPemArea.value = "";
  inputImportPriv.value = "";
  inputImportPub.value = "";
  btnExportPub.disabled = true;
  btnExportPriv.disabled = true;
  btnEncrypt.disabled = true;
  btnDecrypt.disabled = true;
  btnDownloadPub.disabled = true;
  btnDownloadPriv.disabled = true;
  alert("Ключі очищено з пам'яті (сесії).");
});

btnEncrypt.addEventListener("click", async () => {
  const key = importedPublicKey || (cryptoKeyPair && cryptoKeyPair.publicKey);
  if (!key)
    return alert("Немає імпортованого або згенерованого публічного ключа.");
  const plain = plaintextArea.value;
  const data = str2ab(plain);
  try {
    const ct = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      key,
      data
    );
    const b64 = arrayBufferToBase64(ct);
    ciphertextArea.value = b64;
    // автоматичне заповнення поля для розшифрування
    ctToDecrypt.value = b64;
    alert("Текст зашифровано. Шифротекст у полі нижче (base64).");
  } catch (e) {
    console.error(e);
    alert("Помилка шифрування: " + e);
  }
});

btnDecrypt.addEventListener("click", async () => {
  const key = importedPrivateKey || (cryptoKeyPair && cryptoKeyPair.privateKey);
  if (!key)
    return alert(
      "Немає приватного ключа у сесії. Згенеруйте або імпортуйте його."
    );
  const b64 = ctToDecrypt.value.trim();
  if (!b64) return alert("Вставте шифротекст (base64) у полі вище.");
  try {
    const ctBuf = base64ToArrayBuffer(b64);
    const ptBuf = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      key,
      ctBuf
    );
    const text = ab2str(ptBuf);
    decryptedArea.value = text;
    alert('Розшифрування успішне. Див. поле "Розшифрований текст".');
  } catch (e) {
    console.error(e);
    alert("Помилка розшифрування: " + e);
  }
});

document
  .getElementById("paste-ct-from-cipher")
  .addEventListener("click", () => {
    ctToDecrypt.value = ciphertextArea.value;
  });

btnClearCt.addEventListener("click", () => {
  ciphertextArea.value = "";
});

// на завантаження сторінки: відключення кнопок, які вимагають ключа
window.addEventListener("load", () => {
  btnExportPub.disabled = true;
  btnExportPriv.disabled = true;
  btnEncrypt.disabled = true;
  btnDecrypt.disabled = true;
  btnDownloadPub.disabled = true;
  btnDownloadPriv.disabled = true;
});
