import { CaesarCipher } from "./encryption/caesar.js";
import { TrithemiusLinearCipher } from "./encryption/trithemiusLinear.js";
import { TrithemiusPolynomialCipher } from "./encryption/trithemiusPolynomial.js";
import { TrithemiusPasswordCipher } from "./encryption/trithemiusPassword.js";
import { BookCipher } from "./encryption/book.js";

const textArea = document.getElementById("textArea");
const keyInput = document.getElementById("keyInput");
const keyHint = document.getElementById("keyHint");
const cipherType = document.getElementById("cipherType");
const messageDiv = document.getElementById("message");
const bruteResultsDiv = document.getElementById("bruteResults");

const poemContainer = document.getElementById("poemContainer");
const poemInput = document.getElementById("poemInput");
const keyContainer = document.getElementById("keyContainer");

// Оновлення placeholder / підказки при зміні типу шифру
function updateKeyUI() {
  const type = cipherType.value;

  // Зміна на відповідні поля
  if (type === "book") {
    keyContainer.style.display = "none";
    poemContainer.style.display = "block";
  } else {
    keyContainer.style.display = "block";
    poemContainer.style.display = "none";
  }

  switch (type) {
    case "caesar":
      keyInput.placeholder = "Ціле число, наприклад: 3 або -5";
      keyHint.textContent = "Цезар: один цілий зсув k.";
      break;
    case "trithemiusLinear":
      keyInput.placeholder = "Два цілі числа A B або A,B (наприклад: 2 5)";
      keyHint.textContent = "Лінійне: k = A * p + B — введіть A і B.";
      break;
    case "trithemiusPolynomial":
      keyInput.placeholder =
        "Три цілі числа A B C або A,B,C (наприклад: 1,2,3)";
      keyHint.textContent = "Поліном: k = A*p^2 + B*p + C — введіть A, B, C.";
      break;
    case "trithemiusPassword":
      keyInput.placeholder = "Текстове гасло (наприклад: mypass)";
      keyHint.textContent = "Гасло: зсув для позиції p — індекс символу гасла.";
      break;
    case "book":
      keyHint.textContent = "Віршований шифр: використовуйте поле нижче для вставки вірша (багаторядковий).";
      break;
    default:
      keyInput.placeholder = "";
      keyHint.textContent = "";
  }
}
cipherType.addEventListener("change", updateKeyUI);
updateKeyUI(); // початково

// допоміжна: парсить числа з рядка, допускаючи роздільники кома/пробіл
function parseNumbers(raw) {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const n = Number(s);
      return Number.isInteger(n) ? n : NaN;
    });
}

const getCipherInstance = () => {
  const type = cipherType.value;
  const raw = keyInput.value.trim();

  switch (type) {
    case "caesar": {
      if (!/^-?\d+$/.test(raw))
        throw new Error("Ключ має бути цілим числом (наприклад 3)");
      return new CaesarCipher(parseInt(raw, 10));
    }

    case "trithemiusLinear": {
      const nums = parseNumbers(raw);
      if (nums.length !== 2 || nums.some((n) => Number.isNaN(n)))
        throw new Error(
          "Лінійний ключ: введіть **два** цілі числа A і B (наприклад: 2 5 або 2,5)"
        );
      return new TrithemiusLinearCipher([nums[0], nums[1]]);
    }

    case "trithemiusPolynomial": {
      const nums = parseNumbers(raw);
      if (nums.length !== 3 || nums.some((n) => Number.isNaN(n)))
        throw new Error(
          "Поліноміальний ключ: введіть **три** цілі числа A, B, C (наприклад: 1 2 3)"
        );
      return new TrithemiusPolynomialCipher([nums[0], nums[1], nums[2]]);
    }

    case "trithemiusPassword": {
      if (!raw) throw new Error("Ключ-гасло не може бути порожнім");
      return new TrithemiusPasswordCipher(raw);
    }

    case "book": {
      const poem = poemInput.value.replace(/\r/g, "").trim();
      if (!poem) throw new Error("Вірш (ключ) не може бути порожнім");
      return new BookCipher(poem);
    }

    default:
      throw new Error("Невідомий тип шифру");
  }
};

// ====== Кнопки ФАЙЛ ======
document.getElementById("newFile").onclick = () => {
  textArea.value = "";
  messageDiv.textContent = "";
  bruteResultsDiv.innerHTML = "";
};

document.getElementById("openFile").onclick = () => {
  let input = document.createElement("input");
  input.type = "file";
  input.accept = ".txt";
  input.onchange = (e) => {
    let reader = new FileReader();
    reader.onload = (ev) => (textArea.value = ev.target.result);
    reader.readAsText(e.target.files[0]);
  };
  input.click();
};

document.getElementById("saveFile").onclick = () => {
  const blob = new Blob([textArea.value], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "result.txt";
  a.click();
};

document.getElementById("printFile").onclick = () => {
  let win = window.open("", "", "width=600,height=400");
  win.document.write("<pre>" + textArea.value + "</pre>");
  win.print();
};

// ====== Операції ======
document.getElementById("encryptBtn").onclick = () => {
  try {
    messageDiv.textContent = "";
    const cipher = getCipherInstance();
    const enc = cipher.encrypt(textArea.value);
    textArea.value =
      typeof enc === "object" && enc.text !== undefined ? enc.text : enc;
    messageDiv.textContent = "Текст зашифровано успішно.";
  } catch (err) {
    messageDiv.textContent = "Помилка: " + err.message;
  }
};

document.getElementById("decryptBtn").onclick = () => {
  try {
    messageDiv.textContent = "";
    const cipher = getCipherInstance();
    const dec = cipher.decrypt(textArea.value);
    textArea.value =
      typeof dec === "object" && dec.text !== undefined ? dec.text : dec;
    messageDiv.textContent = "Текст дешифровано успішно.";
  } catch (err) {
    messageDiv.textContent = "Помилка: " + err.message;
  }
};

// Brute Force — лише для Цезаря
document.getElementById("bruteForceBtn").onclick = () => {
  bruteResultsDiv.innerHTML = "";
  if (cipherType.value !== "caesar") {
    messageDiv.textContent = "Brute Force доступний лише для шифру Цезаря.";
    return;
  }
  const text = textArea.value.trim();
  if (!text) return (messageDiv.textContent = "Введіть текст для атаки.");
  const results = CaesarCipher.bruteForce(text);
  results.forEach((r) => {
    const p = document.createElement("p");
    p.textContent = `Ключ ${r.key}: ${r.text}`;
    bruteResultsDiv.appendChild(p);
  });
  messageDiv.textContent = "Brute Force завершено.";
};

// ====== Довідка ======
document.getElementById("aboutDev").onclick = () =>
  alert(
    "Комп'ютерний практикум №3.\nРозробник: Лисенко Олександр Сергійович, ТВ-23."
  );

document.getElementById("exitApp").onclick = () => {
  if (confirm("Вийти з програми?")) window.close();
};
