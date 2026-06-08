"use strict";

// Crypto-gated quest client.
// Loads quest.json (only ciphertext for locked stages), shows the current
// clue, and unlocks the next stage by deriving an AES key from the player's
// answer (PBKDF2-SHA256) and decrypting the next blob with Web Crypto.
// A wrong answer fails AES-GCM authentication -> no plaintext is ever exposed.

const $ = (id) => document.getElementById(id);

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// MUST match build.py's normalize_answer().
function normalizeAnswer(s) {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}

async function deriveKey(answer, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalizeAnswer(answer)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

// Returns the decrypted payload object, or null if the answer is wrong.
async function tryUnlock(screen, answer, iterations) {
  try {
    const key = await deriveKey(answer, b64ToBytes(screen.salt), iterations);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(screen.iv) },
      key,
      b64ToBytes(screen.ct)
    );
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (_e) {
    return null; // auth tag mismatch == wrong answer
  }
}

const App = {
  quest: null,
  index: 0, // index into quest.stages of the currently displayed screen
  answers: [], // correct answers entered so far (used to restore progress)
  storeKey: "quest_progress_v1",

  async init() {
    let res;
    try {
      res = await fetch("quest.json", { cache: "no-store" });
    } catch (e) {
      return this.fatal("Не удалось загрузить quest.json");
    }
    if (!res.ok) return this.fatal("quest.json не найден (" + res.status + ")");
    this.quest = await res.json();

    $("title").textContent = this.quest.title || "Quest";
    document.title = this.quest.title || "Quest";
    $("intro").textContent = this.quest.intro || "";

    $("reset").addEventListener("click", () => this.reset());
    await this.restoreProgress();
    this.render();
  },

  // Replay saved answers to re-decrypt unlocked screens (no plaintext clues
  // are persisted -- only the answers the player already discovered).
  async restoreProgress() {
    let saved = [];
    try {
      saved = JSON.parse(localStorage.getItem(this.storeKey) || "[]");
    } catch (_e) {
      saved = [];
    }
    this.index = 0;
    this.answers = [];
    if (!Array.isArray(saved)) return;
    for (const ans of saved) {
      const next = this.quest.stages[this.index + 1];
      if (!next) break;
      const payload = await tryUnlock(next, ans, this.quest.iterations);
      if (!payload) break; // stale/changed quest -> stop where it still matches
      next._payload = payload;
      this.answers.push(ans);
      this.index += 1;
    }
  },
  saveProgress() {
    localStorage.setItem(this.storeKey, JSON.stringify(this.answers));
  },
  reset() {
    localStorage.removeItem(this.storeKey);
    this.index = 0;
    this.answers = [];
    this.render();
  },

  renderProgress() {
    const total = this.quest.stages.length;
    const bar = $("progress");
    bar.innerHTML = "";
    for (let i = 0; i < total; i++) {
      const d = document.createElement("div");
      d.className = "dot" + (i < this.index ? " done" : i === this.index ? " curr" : "");
      bar.appendChild(d);
    }
  },

  render() {
    this.renderProgress();
    this.saveProgress();
    const screen = this.quest.stages[this.index];
    // For index 0 the payload is public; for others it was decrypted on unlock
    // and cached on the screen object as `_payload`.
    const payload = this.index === 0 ? screen.payload : screen._payload;
    if (!payload) {
      // Locked screen with no cached payload (e.g. fresh load past stage 0):
      // fall back to stage 0. Progress only advances via correct answers.
      this.index = 0;
      return this.render();
    }
    if (payload.kind === "prize") return this.renderPrize(payload);
    this.renderClue(payload);
  },

  renderClue(p) {
    const card = $("card");
    card.innerHTML = "";
    const no = document.createElement("div");
    no.className = "stage-no";
    no.textContent = `Этап ${p.n} / ${p.total}`;
    const title = document.createElement("div");
    title.className = "stage-title";
    title.textContent = p.title || "";
    const clue = document.createElement("div");
    clue.className = "clue";
    clue.textContent = p.clue || "";

    const form = document.createElement("form");
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = "Введите ответ…";
    input.autocomplete = "off";
    input.autocapitalize = "off";
    input.spellcheck = false;
    const btn = document.createElement("button");
    btn.type = "submit";
    btn.textContent = "Разблокировать";
    form.append(input, btn);

    const msg = document.createElement("div");
    msg.className = "msg";

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const answer = input.value;
      if (!answer.trim()) return;
      btn.disabled = true;
      input.disabled = true;
      msg.className = "msg busy";
      msg.textContent = "Проверяю ключ…";
      const next = this.quest.stages[this.index + 1];
      const payload = await tryUnlock(next, answer, this.quest.iterations);
      if (payload) {
        next._payload = payload;
        this.answers = this.answers.slice(0, this.index);
        this.answers.push(answer);
        this.index += 1;
        this.render();
      } else {
        btn.disabled = false;
        input.disabled = false;
        msg.className = "msg bad";
        msg.textContent = "Неверный ответ. Этап остаётся зашифрованным.";
        input.focus();
        input.select();
      }
    });

    card.append(no, title, clue, form, msg);
    setTimeout(() => input.focus(), 0);
  },

  renderPrize(p) {
    const card = $("card");
    card.innerHTML = "";
    const box = document.createElement("div");
    box.className = "win";
    const h = document.createElement("h2");
    h.textContent = p.title || "Готово";
    const body = document.createElement("div");
    body.textContent = p.win || "";
    box.append(h, body);
    card.appendChild(box);
  },

  fatal(text) {
    $("card").innerHTML = '<div class="msg bad"></div>';
    $("card").firstChild.textContent = text;
  },
};

App.init();
