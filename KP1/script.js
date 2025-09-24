const textArea = document.getElementById("textArea");
const keyInput = document.getElementById("key");
const messageDiv = document.getElementById("message");
const bruteResultsDiv = document.getElementById("bruteResults");

// Файл: Створити
document.getElementById("newFile").onclick = () => {
  textArea.value = "";
  messageDiv.textContent = "";
};

// Файл: Відкрити
document.getElementById("openFile").onclick = () => {
  let input = document.createElement("input");
  input.type = "file";
  input.accept = ".txt";
  input.onchange = e => {
    let file = e.target.files[0];
    let reader = new FileReader();
    reader.onload = evt => {
      textArea.value = evt.target.result;
      messageDiv.textContent = "Файл завантажено";
    };
    reader.readAsText(file);
  };
  input.click();
};

// Файл: Зберегти
document.getElementById("saveFile").onclick = () => {
  const blob = new Blob([textArea.value], {type: "text/plain"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "encrypted.txt";
  a.click();
  messageDiv.textContent = "Файл збережено";
};

// Файл: Друк
document.getElementById("printFile").onclick = () => {
  let win = window.open("", "", "width=600,height=400");
  win.document.write("<pre>" + textArea.value + "</pre>");
  win.print();
  messageDiv.textContent = "Друк відправлено";
};

// Операції: Шифрувати
document.getElementById("encryptBtn").onclick = () => {
  messageDiv.textContent = "";
  bruteResultsDiv.innerHTML = "";
  try {
    const rawShift = keyInput.value.trim();
    if (!rawShift || isNaN(rawShift) || !Number.isInteger(Number(rawShift))) {
      throw new Error("Ключ має бути цілим числом");
    }
    const shift = parseInt(rawShift, 10);
    const cipher = new CaesarCipher(shift);
    const { text, key } = cipher.encrypt(textArea.value);
    textArea.value = text;
    messageDiv.textContent = `Текст зашифровано (використаний ключ = ${key})`;
  } catch (err) {
    messageDiv.textContent = "Помилка: " + err.message;
  }
};

// Операції: Дешифрувати
document.getElementById("decryptBtn").onclick = () => {
  messageDiv.textContent = "";
  bruteResultsDiv.innerHTML = "";
  try {
    const rawShift = keyInput.value.trim();
    if (!rawShift || isNaN(rawShift) || !Number.isInteger(Number(rawShift))) {
      throw new Error("Ключ має бути цілим числом");
    }
    const shift = parseInt(rawShift, 10);
    const cipher = new CaesarCipher(shift);
    const { text, key } = cipher.decrypt(textArea.value);
    textArea.value = text;
    messageDiv.textContent = `Текст дешифровано (використаний ключ = ${key})`;
  } catch (err) {
    messageDiv.textContent = "Помилка: " + err.message;
  }
};

// Операції: Brute Force
document.getElementById("bruteForceBtn").onclick = () => {
  messageDiv.textContent = "";
  bruteResultsDiv.innerHTML = "";

  try {
    const text = textArea.value.trim();
    if (!text) throw new Error("Текст для атаки не може бути порожнім");

    const results = CaesarCipher.bruteForce(text);

    if (results.length === 0) {
      bruteResultsDiv.textContent = "Не знайдено можливих варіантів.";
      return;
    }

    // Вивід результатів у блок
    results.forEach(r => {
      const p = document.createElement("p");
      p.textContent = `Ключ ${r.key}: ${r.text}`;
      bruteResultsDiv.appendChild(p);
    });

    messageDiv.textContent = `Атака завершена. Перегляньте всі можливі варіанти нижче.`;
  } catch (err) {
    messageDiv.textContent = "Помилка: " + err.message;
  }
};

// Довідка: Про розробника
document.getElementById("aboutDev").onclick = () => {
  alert("Комп'ютерний практикум №1.\nРозробник: Лисенко Олекснадр Сергійович, група ТВ-23.");
};

// Вихід
document.getElementById("exitApp").onclick = () => {
  if (confirm("Вийти з програми?")) window.close();
};