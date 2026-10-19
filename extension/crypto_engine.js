/**
 * KeeVault XC - Core Cryptographic, KDBX Container, TOTP & Merger Engine
 * Inspired by keepassxreboot/keepassxc (src/crypto, src/format, src/core, src/keys)
 * Uses hardware-accelerated WebCrypto API (AES-256-GCM + PBKDF2-SHA256 / CompositeKey).
 */

const KDBX_MAGIC_SIG1 = 0x9AA2D903;
const KDBX_MAGIC_SIG2 = 0xB54BFB67;
const KDBX_XC_CONTAINER_MAGIC = "KDBX4-XC-AES256GCM-V2";

const KeeCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function bufToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  }

  function base64ToBuf(b64) {
    const clean = (b64 || "").replace(/\s+/g, "");
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function randomUUID() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = bufToHex(b.buffer);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  /**
   * CompositeKey (like KeePassXC src/keys/CompositeKey.cpp):
   * Combines Master Password + optional KeyFile hash via SHA-256 before KDF.
   */
  async function buildCompositeKeyBytes(masterPassword, keyFileHex = "") {
    const pwBytes = enc.encode(masterPassword || "");
    const pwHash = await crypto.subtle.digest("SHA-256", pwBytes);
    if (!keyFileHex || !keyFileHex.trim()) {
      return new Uint8Array(pwHash);
    }
    const kfBytes = enc.encode(keyFileHex.trim());
    const kfHash = await crypto.subtle.digest("SHA-256", kfBytes);
    const combined = new Uint8Array(64);
    combined.set(new Uint8Array(pwHash), 0);
    combined.set(new Uint8Array(kfHash), 32);
    const finalHash = await crypto.subtle.digest("SHA-256", combined);
    return new Uint8Array(finalHash);
  }

  /**
   * Derives a 256-bit AES-GCM key using PBKDF2-SHA256 (600,000 iterations default).
   */
  async function deriveAesKey(compositeBytes, saltBytes, iterations = 600000) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      compositeBytes,
      { name: "PBKDF2" },
      false,
      ["deriveKey", "deriveBits"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypts a Vault object into a binary KDBX-compatible container (returned as Base64 & Uint8Array).
   * Header includes KDBX magic bytes (0x9AA2D903 0xB54BFB67) so desktop tools recognize the header signature,
   * followed by JSON envelope with salt, iv, iterations, and AES-256-GCM authenticated ciphertext.
   */
  async function encryptVaultToKdbxBytes(vaultObj, masterPassword, keyFileHex = "") {
    const salt = new Uint8Array(32);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(salt);
    crypto.getRandomValues(iv);
    const iterations = 600000;

    const composite = await buildCompositeKeyBytes(masterPassword, keyFileHex);
    const aesKey = await deriveAesKey(composite, salt, iterations);

    const plaintextBytes = enc.encode(JSON.stringify(vaultObj));
    const cipherBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      aesKey,
      plaintextBytes
    );

    const envelope = {
      magic: KDBX_XC_CONTAINER_MAGIC,
      format: "kdbx4-aes256gcm",
      kdf: "pbkdf2-sha256",
      iterations,
      salt: bufToBase64(salt.buffer),
      iv: bufToBase64(iv.buffer),
      ciphertext: bufToBase64(cipherBuf),
      updatedAt: new Date().toISOString(),
    };

    const jsonBytes = enc.encode(JSON.stringify(envelope));
    // Prepend 12-byte KDBX4 binary signature header + JSON payload
    const out = new Uint8Array(12 + jsonBytes.length);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, KDBX_MAGIC_SIG1, true);
    dv.setUint32(4, KDBX_MAGIC_SIG2, true);
    dv.setUint32(8, 0x00040000, true); // KDBX 4.0 version marker
    out.set(jsonBytes, 12);

    const exportedKeyRaw = await crypto.subtle.exportKey("raw", aesKey);
    return {
      bytes: out,
      base64: bufToBase64(out.buffer),
      sessionKeyB64: bufToBase64(exportedKeyRaw),
      envelope,
    };
  }

  /**
   * Decrypts a KDBX-XC binary buffer or Base64 string using Master Password (+ optional KeyFile).
   */
  async function decryptVaultFromKdbxBytes(inputBase64OrBytes, masterPassword, keyFileHex = "") {
    let bytes;
    if (typeof inputBase64OrBytes === "string") {
      bytes = new Uint8Array(base64ToBuf(inputBase64OrBytes));
    } else if (inputBase64OrBytes instanceof ArrayBuffer) {
      bytes = new Uint8Array(inputBase64OrBytes);
    } else {
      bytes = new Uint8Array(inputBase64OrBytes.buffer || inputBase64OrBytes);
    }

    let jsonStr;
    if (bytes.length > 12) {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const sig1 = dv.getUint32(0, true);
      const sig2 = dv.getUint32(4, true);
      if (sig1 === KDBX_MAGIC_SIG1 && sig2 === KDBX_MAGIC_SIG2) {
        jsonStr = dec.decode(bytes.subarray(12));
      } else {
        jsonStr = dec.decode(bytes);
      }
    } else {
      throw new Error("Arquivo .kdbx inválido ou vazio.");
    }

    let envelope;
    try {
      envelope = JSON.parse(jsonStr);
    } catch (e) {
      throw new Error("Este arquivo .kdbx binário externo deve ser importado via XML/CSV do KeePassXC ou criado no KeeVault XC.");
    }

    const salt = new Uint8Array(base64ToBuf(envelope.salt));
    const iv = new Uint8Array(base64ToBuf(envelope.iv));
    const ciphertext = base64ToBuf(envelope.ciphertext);
    const iterations = envelope.iterations || 600000;

    const composite = await buildCompositeKeyBytes(masterPassword, keyFileHex);
    const aesKey = await deriveAesKey(composite, salt, iterations);

    let plainBuf;
    try {
      plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        aesKey,
        ciphertext
      );
    } catch (err) {
      throw new Error("Senha Mestra (ou Arquivo-Chave) incorreta!");
    }

    const vaultObj = JSON.parse(dec.decode(plainBuf));
    const exportedKeyRaw = await crypto.subtle.exportKey("raw", aesKey);
    return {
      vault: normalizeVault(vaultObj),
      sessionKeyB64: bufToBase64(exportedKeyRaw),
    };
  }

  /**
   * Creates a fresh default Vault structure (inspired by KeePassXC Root -> Groups -> Entries)
   */
  function createEmptyVault(vaultName = "Meu Cofre KeeVault XC") {
    const now = new Date().toISOString();
    return {
      version: 2,
      name: vaultName,
      description: "Cofre criptografado AES-256-GCM sincronizado com GitHub Privado & MCP",
      createdAt: now,
      updatedAt: now,
      groups: [
        { id: "general", name: "Geral", icon: "🔐" },
        { id: "work", name: "Trabalho & Dev", icon: "💻" },
        { id: "ai", name: "IAs & Automação", icon: "🤖" },
        { id: "social", name: "Redes & E-mail", icon: "🌐" },
        { id: "finance", name: "Bancos & Finanças", icon: "💳" },
        { id: "servers", name: "Servidores & SSH", icon: "🖥️" },
      ],
      entries: [],
      deletedObjects: {},
    };
  }

  function normalizeVault(v) {
    const base = createEmptyVault(v?.name || "Meu Cofre KeeVault XC");
    return {
      ...base,
      ...v,
      groups: Array.isArray(v?.groups) && v.groups.length ? v.groups : base.groups,
      entries: Array.isArray(v?.entries) ? v.entries.map(normalizeEntry) : [],
      deletedObjects: v?.deletedObjects || {},
    };
  }

  function normalizeEntry(e) {
    const now = new Date().toISOString();
    return {
      id: e.id || randomUUID(),
      groupId: e.groupId || "general",
      title: (e.title || "Sem título").trim(),
      username: (e.username || "").trim(),
      password: e.password || "",
      url: (e.url || "").trim(),
      totpSecret: (e.totpSecret || "").replace(/\s+/g, "").toUpperCase(),
      notes: e.notes || "",
      aiAllowed: e.aiAllowed !== undefined ? Boolean(e.aiAllowed) : true,
      favorite: Boolean(e.favorite),
      customFields: Array.isArray(e.customFields) ? e.customFields : [],
      createdAt: e.createdAt || now,
      updatedAt: e.updatedAt || now,
      history: Array.isArray(e.history) ? e.history.slice(0, 10) : [],
    };
  }

  /**
   * Smart Entry-Level Timestamp Merger (Ported from KeePassXC src/core/Merger.cpp)
   * Merges two vaults (e.g. Local vs GitHub Remote) by comparing per-entry timestamps and deleted tombstones.
   */
  function mergeVaults(localVault, remoteVault) {
    const a = normalizeVault(localVault);
    const b = normalizeVault(remoteVault);

    const deletedObjects = { ...a.deletedObjects, ...b.deletedObjects };

    // Merge Groups
    const groupMap = new Map();
    for (const g of [...a.groups, ...b.groups]) {
      if (!groupMap.has(g.id)) groupMap.set(g.id, g);
    }

    // Merge Entries by UUID & Timestamp
    const entryMap = new Map();
    for (const entry of a.entries) {
      if (!deletedObjects[entry.id]) {
        entryMap.set(entry.id, normalizeEntry(entry));
      }
    }

    for (const rEntryRaw of b.entries) {
      const rEntry = normalizeEntry(rEntryRaw);
      const delTs = deletedObjects[rEntry.id];
      if (delTs && new Date(delTs) >= new Date(rEntry.updatedAt)) {
        continue;
      }
      const existing = entryMap.get(rEntry.id);
      if (!existing) {
        entryMap.set(rEntry.id, rEntry);
      } else {
        const tLocal = new Date(existing.updatedAt || 0).getTime();
        const tRemote = new Date(rEntry.updatedAt || 0).getTime();
        if (tRemote > tLocal) {
          const snap = { ...existing, history: [] };
          const mergedHistory = [snap, ...(rEntry.history || [])].slice(0, 8);
          entryMap.set(rEntry.id, { ...rEntry, history: mergedHistory });
        }
      }
    }

    const mergedEntries = Array.from(entryMap.values()).sort((x, y) => {
      if (x.favorite !== y.favorite) return x.favorite ? -1 : 1;
      return x.title.localeCompare(y.title, "pt-BR");
    });

    return {
      ...a,
      updatedAt: new Date().toISOString(),
      groups: Array.from(groupMap.values()),
      entries: mergedEntries,
      deletedObjects,
    };
  }

  /**
   * Exports Vault to Official KeePassXC XML 2.0 format (can be imported directly in desktop KeePassXC:
   * Database -> Import -> KeePass XML 2.0)
   */
  function exportToKeePassXCXml(vault) {
    const esc = (s) =>
      String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");

    const entriesXml = (vault.entries || [])
      .map(
        (e) => `      <Entry>
        <UUID>${esc(btoa(e.id).slice(0, 24))}</UUID>
        <String><Key>Title</Key><Value>${esc(e.title)}</Value></String>
        <String><Key>UserName</Key><Value>${esc(e.username)}</Value></String>
        <String><Key>Password</Key><Value ProtectInMemory="True">${esc(e.password)}</Value></String>
        <String><Key>URL</Key><Value>${esc(e.url)}</Value></String>
        <String><Key>Notes</Key><Value>${esc(e.notes)}</Value></String>
        <String><Key>otp</Key><Value ProtectInMemory="True">${esc(e.totpSecret)}</Value></String>
        <String><Key>MCP_AI_Allowed</Key><Value>${e.aiAllowed ? "true" : "false"}</Value></String>
        <Times>
          <CreationTime>${esc(e.createdAt)}</CreationTime>
          <LastModificationTime>${esc(e.updatedAt)}</LastModificationTime>
        </Times>
      </Entry>`
      )
      .join("\n");

    return `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>KeeVault XC Chrome Extension</Generator>
    <DatabaseName>${esc(vault.name || "KeeVault XC")}</DatabaseName>
  </Meta>
  <Root>
    <Group>
      <Name>${esc(vault.name || "Root")}</Name>
${entriesXml}
    </Group>
  </Root>
</KeePassFile>`;
  }

  /**
   * Imports entries from KeePassXC XML 2.0 or KeePassXC CSV export
   */
  function importFromKeePassXCXmlOrCsv(textContent) {
    const trimmed = (textContent || "").trim();
    const imported = [];

    if (trimmed.startsWith("<")) {
      // Parse KeePassXC XML
      const entryBlocks = trimmed.match(/<Entry>[\s\S]*?<\/Entry>/gi) || [];
      for (const block of entryBlocks) {
        const kv = {};
        const strRegex = /<String>\s*<Key>([\s\S]*?)<\/Key>\s*<Value[^>]*>([\s\S]*?)<\/Value>\s*<\/String>/gi;
        let m;
        while ((m = strRegex.exec(block)) !== null) {
          const k = m[1].trim();
          const v = m[2]
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&quot;/g, '"')
            .replace(/&amp;/g, "&");
          kv[k] = v;
        }
        if (kv.Title || kv.UserName || kv.Password) {
          let totp = kv.otp || kv.TOTP || "";
          if (totp.startsWith("otpauth://")) {
            const sm = totp.match(/[?&]secret=([A-Z2-7]+)/i);
            if (sm) totp = sm[1];
          }
          imported.push(
            normalizeEntry({
              title: kv.Title || kv.URL || "Importado KeePassXC",
              username: kv.UserName || "",
              password: kv.Password || "",
              url: kv.URL || "",
              notes: kv.Notes || "",
              totpSecret: totp,
              aiAllowed: kv.MCP_AI_Allowed !== "false",
            })
          );
        }
      }
      return imported;
    }

    // Parse KeePassXC / Chrome CSV
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length < 2) return imported;
    const parseCsvLine = (line) => {
      const res = [];
      let cur = "";
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
          if (inQuotes && line[i + 1] === '"') {
            cur += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (ch === "," && !inQuotes) {
          res.push(cur);
          cur = "";
        } else {
          cur += ch;
        }
      }
      res.push(cur);
      return res;
    };

    const headers = parseCsvLine(lines[0]).map((h) => h.trim().toLowerCase());
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCsvLine(lines[i]);
      const row = {};
      headers.forEach((h, idx) => (row[h] = cols[idx] || ""));
      const title = row["title"] || row["name"] || row["url"] || "Entrada CSV";
      const username = row["username"] || row["login_username"] || "";
      const password = row["password"] || row["login_password"] || "";
      const url = row["url"] || row["login_uri"] || "";
      const notes = row["notes"] || "";
      const totp = row["totp"] || row["otp"] || "";
      if (title || username || password) {
        imported.push(normalizeEntry({ title, username, password, url, notes, totpSecret: totp }));
      }
    }
    return imported;
  }

  /**
   * RFC 6238 TOTP Generator (Ported from KeePassXC src/core/Totp.cpp)
   */
  function base32ToBytes(base32Str) {
    let raw = (base32Str || "").trim();
    if (raw.startsWith("otpauth://")) {
      const m = raw.match(/[?&]secret=([A-Z2-7=]+)/i);
      if (m) raw = m[1];
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean = raw.toUpperCase().replace(/[^A-Z2-7]/g, "");
    if (!clean) return new Uint8Array(0);

    let bits = 0;
    let value = 0;
    const out = [];
    for (let i = 0; i < clean.length; i++) {
      value = (value << 5) | alphabet.indexOf(clean[i]);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  async function generateTOTP(secretBase32, timestampMs = Date.now(), period = 30, digits = 6) {
    const keyBytes = base32ToBytes(secretBase32);
    if (!keyBytes.length) return null;

    const epochSec = Math.floor(timestampMs / 1000);
    const counter = Math.floor(epochSec / period);
    const remainingSeconds = period - (epochSec % period);

    const counterBuf = new ArrayBuffer(8);
    const dv = new DataView(counterBuf);
    dv.setUint32(0, Math.floor(counter / 0x100000000), false);
    dv.setUint32(4, counter >>> 0, false);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );
    const hmacBuf = await crypto.subtle.sign("HMAC", cryptoKey, counterBuf);
    const hmac = new Uint8Array(hmacBuf);
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = String(binary % Math.pow(10, digits)).padStart(digits, "0");
    return {
      code: otp,
      formatted: `${otp.slice(0, 3)} ${otp.slice(3)}`,
      remainingSeconds,
      period,
    };
  }

  /**
   * Cryptographic Password & Passphrase Generator (Ported from KeePassXC PasswordGenerator.cpp)
   */
  const PTBR_WORDS = [
    "abacate", "alvorada", "ancora", "planeta", "oceano", "trovao", "cristal", "falcao",
    "nebulosa", "orbita", "safira", "labirinto", "relampago", "horizonte", "bussola", "fortaleza",
    "titano", "cometa", "vortice", "esmeralda", "cobalto", "obsidiana", "foguete", "galaxia",
    "impulso", "quasar", "eclipse", "valquiria", "prisma", "zenite", "aurora", "magneto"
  ];

  function randomInt(maxExclusive) {
    const arr = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    do {
      crypto.getRandomValues(arr);
    } while (arr[0] >= limit);
    return arr[0] % maxExclusive;
  }

  function generatePassword(opts = {}) {
    const {
      mode = "password", // "password" | "passphrase"
      length = 20,
      upper = true,
      lower = true,
      digits = true,
      symbols = true,
      excludeAmbiguous = true,
      wordCount = 4,
      separator = "-",
    } = opts;

    if (mode === "passphrase") {
      const words = [];
      for (let i = 0; i < wordCount; i++) {
        let w = PTBR_WORDS[randomInt(PTBR_WORDS.length)];
        if (upper) w = w.charAt(0).toUpperCase() + w.slice(1);
        words.push(w);
      }
      if (digits) words.push(String(randomInt(900) + 100));
      const result = words.join(separator);
      return {
        password: result,
        entropyBits: Math.round(wordCount * Math.log2(PTBR_WORDS.length) + (digits ? 10 : 0)),
        strengthLabel: "Forte (Frase-Senha)",
      };
    }

    let uChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lChars = "abcdefghijklmnopqrstuvwxyz";
    let dChars = "0123456789";
    let sChars = "!@#$%^&*()-_=+[]{};:,.<>?";

    if (excludeAmbiguous) {
      uChars = uChars.replace(/[IO]/g, "");
      lChars = lChars.replace(/[l]/g, "");
      dChars = dChars.replace(/[01]/g, "");
    }

    let pool = "";
    const required = [];
    if (upper) {
      pool += uChars;
      required.push(uChars[randomInt(uChars.length)]);
    }
    if (lower) {
      pool += lChars;
      required.push(lChars[randomInt(lChars.length)]);
    }
    if (digits) {
      pool += dChars;
      required.push(dChars[randomInt(dChars.length)]);
    }
    if (symbols) {
      pool += sChars;
      required.push(sChars[randomInt(sChars.length)]);
    }
    if (!pool) pool = lChars + dChars;

    const chars = [...required];
    for (let i = chars.length; i < length; i++) {
      chars.push(pool[randomInt(pool.length)]);
    }
    // Fisher-Yates cryptographic shuffle
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    const entropyBits = Math.round(chars.length * Math.log2(pool.length));
    let strengthLabel = "Fraca";
    if (entropyBits >= 110) strengthLabel = "Militar (Inquebrável)";
    else if (entropyBits >= 75) strengthLabel = "Muito Forte";
    else if (entropyBits >= 50) strengthLabel = "Boa";

    return {
      password: chars.join(""),
      entropyBits,
      strengthLabel,
    };
  }

  return {
    bufToBase64,
    base64ToBuf,
    bufToHex,
    randomUUID,
    encryptVaultToKdbxBytes,
    decryptVaultFromKdbxBytes,
    createEmptyVault,
    normalizeVault,
    normalizeEntry,
    mergeVaults,
    exportToKeePassXCXml,
    importFromKeePassXCXmlOrCsv,
    generateTOTP,
    generatePassword,
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.KeeCrypto = KeeCrypto;
}
