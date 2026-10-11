/* bitbid landing — The Rotor Machine. Vanilla, no dependencies. */
(() => {
  "use strict";

  /* ---------- build the machine's drawn parts ---------- */
  const NS = "http://www.w3.org/2000/svg";
  const CX = 300, CY = 288;
  const svgEl = (tag, attrs) => {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  };
  const fan = (group, count, place) => {
    if (!group) return;
    for (let i = 0; i < count; i++) {
      const g = svgEl("g", { transform: `rotate(${(360 / count) * i} ${CX} ${CY})` });
      place(g, i);
      group.appendChild(g);
    }
  };

  fan(document.getElementById("bolts"), 12, (g) => {
    g.appendChild(svgEl("circle", { cx: CX, cy: CY - 233, r: 4, fill: "#aeb4bc", stroke: "#16181c", "stroke-width": 1 }));
    g.appendChild(svgEl("circle", { cx: CX, cy: CY - 233, r: 1.4, fill: "#16181c" }));
  });
  fan(document.getElementById("contacts"), 8, (g) => {
    g.appendChild(svgEl("rect", { x: CX - 6, y: CY - 216, width: 12, height: 18, fill: "#ece7da", stroke: "#16181c", "stroke-width": 1 }));
  });
  fan(document.getElementById("ticks"), 48, (g, i) => {
    const long = i % 4 === 0;
    g.appendChild(svgEl("line", {
      x1: CX, y1: CY - (long ? 206 : 202), x2: CX, y2: CY - 194,
      stroke: "#16181c", "stroke-width": long ? 1.4 : 0.8
    }));
  });
  fan(document.getElementById("teeth"), 30, (g) => {
    g.appendChild(svgEl("rect", { x: CX - 3.5, y: CY - 186, width: 7, height: 14, fill: "#3a4048", stroke: "#0d0f12", "stroke-width": 0.8 }));
  });
  fan(document.getElementById("spokes"), 12, (g, i) => {
    g.appendChild(svgEl("line", {
      x1: CX, y1: CY - 62, x2: CX, y2: CY - 176,
      stroke: i === 4 ? "#c93a1b" : "#3a4048", "stroke-width": i === 4 ? 2 : 1
    }));
  });
  fan(document.getElementById("segments"), 24, (g, i) => {
    const r = i % 2 ? 140 : 102;
    g.appendChild(svgEl("line", { x1: CX, y1: CY - r, x2: CX, y2: CY - r + 9, stroke: "#4a5058", "stroke-width": 1 }));
  });

  /* ---------- hero crank: one control turns the drum ---------- */
  const machine = document.getElementById("machine");
  const readIn = document.getElementById("read-in");
  const readOut = document.getElementById("read-out");
  const lamps = Array.from(document.querySelectorAll(".lamp__glass"));
  const HEX = "0123456789abcdef";
  const randHex = (n) => Array.from({ length: n }, () => HEX[(Math.random() * 16) | 0]).join("");

  function tug() {
    if (!machine) return;
    machine.classList.remove("is-grinding");
    void machine.offsetWidth;
    machine.classList.add("is-grinding");
    readIn.textContent = `sk_${Math.random() < 0.5 ? "live" : "prod"}_${randHex(8)}`;
    readOut.textContent = `${randHex(4)}${randHex(4)}…${randHex(4)}`;
    lamps.forEach((l, i) => {
      l.classList.remove("lamp__glass--cy", "lamp__glass--vm");
      setTimeout(() => {
        if (!l.isConnected) return;
        l.classList.add(i % 3 === 2 ? "lamp__glass--vm" : "lamp__glass--cy");
      }, 90 + i * 55);
    });
    setTimeout(() => machine.classList.remove("is-grinding"), 780);
  }
  const crank = document.getElementById("crank");
  if (crank) crank.addEventListener("click", tug);
  // the drum settles once on arrival
  window.addEventListener("load", () => setTimeout(tug, 520));

  /* ---------- copy the install line ---------- */
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy");
      try {
        await navigator.clipboard.writeText(text);
        const old = btn.textContent;
        btn.textContent = "copied";
        setTimeout(() => (btn.textContent = old), 1400);
      } catch {
        btn.textContent = "select + copy";
      }
    });
  });

  /* ---------- reveal on scroll ---------- */
  const revealables = document.querySelectorAll("[data-reveal]");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("is-in");
          io.unobserve(e.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });
    revealables.forEach((el) => io.observe(el));
  } else {
    revealables.forEach((el) => el.classList.add("is-in"));
  }

  /* ---------- the bench: real AES-256-GCM + HKDF-SHA256 ---------- */
  const input = document.getElementById("demo-input");
  const sealBtn = document.getElementById("demo-seal");
  const openBtn = document.getElementById("demo-open");
  const ctEl = document.getElementById("demo-ct");
  const keyEl = document.getElementById("demo-key");
  const ivEl = document.getElementById("demo-iv");
  const statusEl = document.getElementById("demo-status");

  const toHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
  const group = (hex) => hex.replace(/(.{4})/g, "$1 ").trim();
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  let sealed = null; // { key, iv, ct }

  const say = (msg, state = "") => {
    statusEl.textContent = msg;
    statusEl.setAttribute("data-state", state);
  };

  async function deriveKey() {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const base = await crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: crypto.getRandomValues(new Uint8Array(16)), info: enc.encode("bitbid/v1 secret key") },
      base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const raw = await crypto.subtle.exportKey("raw", key);
    return { key, raw };
  }

  if (sealBtn) {
    sealBtn.addEventListener("click", async () => {
      const text = (input.value || "").trim();
      if (!text) return say("nothing to seal. type a secret first.", "err");
      if (!crypto?.subtle) return say("this browser has no WebCrypto available.", "err");
      try {
        sealBtn.disabled = true;
        say("turning the drum…");
        const { key, raw } = await deriveKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
        sealed = { key, iv, ct };
        ctEl.textContent = group(toHex(ct));
        keyEl.textContent = group(toHex(raw));
        ivEl.textContent = group(toHex(iv));
        say("sealed. the plaintext is gone from this pane.", "");
      } catch (e) {
        say("the seal failed: " + (e?.message || e), "err");
      } finally {
        sealBtn.disabled = false;
      }
    });
  }

  if (openBtn) {
    openBtn.addEventListener("click", async () => {
      if (!sealed) return say("nothing sealed yet. turn the crank first.", "err");
      try {
        openBtn.disabled = true;
        say("unwrapping with the recipient key…");
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.iv }, sealed.key, sealed.ct);
        input.value = dec.decode(pt);
        say("opened. only the key that wrapped it could do that.", "");
      } catch (e) {
        say("no key, no secret: " + (e?.message || e), "err");
      } finally {
        openBtn.disabled = false;
      }
    });
  }
})();
