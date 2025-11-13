async function postJson(url, data){
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(data)
  });
  return r.json();
}

const supportedModes = {
  DES:    ['CBC','ECB','CFB','OFB','CTR'],
  '3DES': ['CBC','ECB','CFB','OFB','CTR'],
  AES:    ['CBC','ECB','CFB','OFB','CTR','GCM']
};

document.getElementById('encrypt').onclick = async () => {
  const alg = document.getElementById('alg').value;
  const mode = document.getElementById('mode').value;
  const key = document.getElementById('key').value || '';
  const plaintext = document.getElementById('plain').value || '';

  if (!supportedModes[alg].includes(mode)) {
    alert(`Режим "${mode}" не підтримується для алгоритму "${alg}"!`);
    return;
  }

  const res = await postJson('/encrypt', {alg, mode, key, plaintext});
  if (res.error) {
    alert('Помилка шифрування: ' + res.error);
    return;
  }

  document.getElementById('result').value = res.ciphertext || '';
  document.getElementById('payload').value = JSON.stringify(res, null, 2);
};

document.getElementById('decrypt').onclick = async () => {
  try {
    const alg = document.getElementById('alg').value;
    const mode = document.getElementById('mode').value;
    const key = document.getElementById('key').value || '';

    if (!supportedModes[alg].includes(mode)) {
      alert(`Режим "${mode}" не підтримується для алгоритму "${alg}"!`);
      return;
    }

    const payloadText = document.getElementById('payload').value;
    if (!payloadText) {
      alert('Спочатку зашифруйте або вставте payload JSON у поле "Full payload JSON".');
      return;
    }

    const payload = JSON.parse(payloadText);
    const res = await postJson('/decrypt', {alg, mode, key, payload});

    if (res.error) {
      alert('Помилка: ' + res.error);
    } else {
      document.getElementById('plain').value = res.plaintext;
    }
  } catch(e) {
    alert('Помилка розшифрування: ' + e.message);
  }
};
