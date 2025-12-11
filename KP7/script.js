function generateKeys() {
  const crypt = new JSEncrypt({ default_key_size: 1024 });
  crypt.getKey();

  const fullPrivateKey = crypt.getPrivateKey();
  const fullPublicKey = crypt.getPublicKey();

  const cleanKey = (key) => {
    return key
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .trim();
  };

  document.getElementById("privkey").value = cleanKey(fullPrivateKey);
  document.getElementById("pubkey").value = cleanKey(fullPublicKey);

  document.getElementById("sign_privkey").value = fullPrivateKey;
  document.getElementById("verify_pubkey").value = fullPublicKey;
}

function signMessage() {
  const message = document.getElementById("sign_message").value;
  const privateKey = document.getElementById("sign_privkey").value;

  if (!message || !privateKey) {
    alert("Будь ласка, введіть повідомлення та приватний ключ.");
    return;
  }

  const sign = new JSEncrypt();
  sign.setPrivateKey(privateKey);

  const signature = sign.sign(message, CryptoJS.SHA1, "sha1");

  document.getElementById("signature_result").value = signature;

  document.getElementById("verify_signature").value = signature;
}

function verifyMessage() {
  const message = document.getElementById("verify_message").value;
  const signature = document.getElementById("verify_signature").value;
  const publicKey = document.getElementById("verify_pubkey").value;

  if (!message || !signature || !publicKey) {
    alert("Заповніть всі поля для перевірки.");
    return;
  }

  const verify = new JSEncrypt();
  verify.setPublicKey(publicKey);

  const isValid = verify.verify(message, signature, CryptoJS.SHA1);

  const statusDiv = document.getElementById("verification_status");
  if (isValid) {
    statusDiv.innerHTML =
      '<div class="result-box success">Підпис ВІРНИЙ! Повідомлення цілісне.</div>';
  } else {
    statusDiv.innerHTML =
      '<div class="result-box error">Підпис НЕВІРНИЙ! Дані змінено або ключ не підходить.</div>';
  }
}
