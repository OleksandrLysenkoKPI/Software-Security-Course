export class BookCipher {
  constructor(poem) {
    if (typeof poem !== "string" || poem.trim().length === 0)
      throw new Error("Вірш (ключ) не може бути порожнім.");

    // таблиця символів
    this.table = this.#buildTable(poem);
    this.rows = this.table.length;
    this.cols = this.table[0]?.length || 0;

    // карта символів => усі позиції
    this.map = {};
    for (let r = 0; r < this.rows; r++) {
      for (let c = 0; c < this.cols; c++) {
        const ch = this.table[r][c];
        if (!this.map[ch]) this.map[ch] = [];
        this.map[ch].push([r + 1, c + 1]); // 1-based
      }
    }
  }

  // перетворення вірша у прямокутну таблицю
  #buildTable(poem) {
    const lines = poem
      .replace(/\r/g, "")
      .split("\n")
      .map((l) => l.replace(/\s+/g, "").trim())
      .filter(Boolean);

    const maxLen = Math.max(...lines.map((l) => l.length));
    return lines.map((l) =>
      l.padEnd(maxLen, " ").split("") // заповнення пропусками, якщо коротший
    );
  }

  encrypt(text) {
    let codes = [];
    for (let ch of text) {
      const positions = this.map[ch] || this.map[ch.toUpperCase()] || this.map[ch.toLowerCase()];
      if (!positions || positions.length === 0) {
        // якщо символ не знайдено, залишається як є
        codes.push(ch);
        continue;
      }
      // випадкова позиція
      const [r, c] = positions[Math.floor(Math.random() * positions.length)];
      codes.push(`${r.toString().padStart(2, "0")}/${c.toString().padStart(2, "0")}`);
    }
    return codes.join(",");
  }

  decrypt(cipherText) {
    // поділ за комами
    const parts = cipherText.split(",").map((p) => p.trim());
    let result = "";
    for (let part of parts) {
      const match = part.match(/^(\d{1,2})\/(\d{1,2})$/);
      if (!match) {
        result += part; // залишається як є (наприклад, пробіли або роздільники)
        continue;
      }
      const r = parseInt(match[1], 10) - 1;
      const c = parseInt(match[2], 10) - 1;
      if (r >= 0 && r < this.rows && c >= 0 && c < this.cols) {
        result += this.table[r][c];
      } else {
        result += "?";
      }
    }
    return result;
  }
}
