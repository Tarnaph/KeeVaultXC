/**
 * KeeVault XC - Background Service Worker (Manifest V3)
 * Manages:
 *   1. Encrypted Vault Storage + Permanent Unlock Switch (ON/OFF)
 *   2. Automatic Private GitHub Sync (.kdbx) with Smart Timestamp Merge
 *   3. Local MCP Bridge (http://127.0.0.1:18455) for Zero-Knowledge AI Blind Autofill
 *   4. Content Script Autofill, TOTP 2FA & Save-Login Prompts
 */

importScripts("crypto_engine.js", "github_sync.js");

const MCP_BRIDGE_URL = "http://127.0.0.1:18455";

let runtimeState = {
  initialized: false,
  hasVault: false,
  unlocked: false,
  permanentUnlock: true,   // Switch 1: ON = keep unlocked permanently until user turns OFF
  mcpEnabled: true,        // Switch 2: ON = allow AI MCP agents to see login catalog & trigger blind autofill
  vault: null,             // Decrypted vault in memory
  masterPassword: "",      // Kept in memory (and in local storage ONLY when permanentUnlock === true)
  keyFileHex: "",
  githubConfig: {
    token: "",
    repoFullName: "",
    filePath: "cofre.kdbx",
    branch: "main",
    autoSync: true,
    lastSyncAt: null,
    lastSha: null,
    lastError: null,
  },
  mcpBridgeOnline: false,
  mcpAuditLog: [],
};

// ---------------------------------------------------------------------------
// 1. Initialization & Persistent Session Recovery
// ---------------------------------------------------------------------------
async function initRuntimeState() {
  if (runtimeState.initialized) return;
  const stored = await chrome.storage.local.get([
    "encryptedKdbxBase64",
    "permanentUnlock",
    "mcpEnabled",
    "savedMasterSession",
    "githubConfig",
    "mcpAuditLog",
  ]);

  runtimeState.hasVault = Boolean(stored.encryptedKdbxBase64);
  runtimeState.permanentUnlock = stored.permanentUnlock !== undefined ? Boolean(stored.permanentUnlock) : true;
  runtimeState.mcpEnabled = stored.mcpEnabled !== undefined ? Boolean(stored.mcpEnabled) : true;
  if (stored.githubConfig) {
    runtimeState.githubConfig = { ...runtimeState.githubConfig, ...stored.githubConfig };
  }
  if (Array.isArray(stored.mcpAuditLog)) {
    runtimeState.mcpAuditLog = stored.mcpAuditLog.slice(0, 50);
  }

  // If permanentUnlock is ON and savedMasterSession exists, auto-unlock silently!
  if (
    runtimeState.hasVault &&
    runtimeState.permanentUnlock &&
    stored.savedMasterSession &&
    stored.savedMasterSession.masterPassword
  ) {
    try {
      const res = await KeeCrypto.decryptVaultFromKdbxBytes(
        stored.encryptedKdbxBase64,
        stored.savedMasterSession.masterPassword,
        stored.savedMasterSession.keyFileHex || ""
      );
      runtimeState.vault = res.vault;
      runtimeState.masterPassword = stored.savedMasterSession.masterPassword;
      runtimeState.keyFileHex = stored.savedMasterSession.keyFileHex || "";
      runtimeState.unlocked = true;
    } catch (e) {
      runtimeState.unlocked = false;
    }
  }

  runtimeState.initialized = true;
  updateExtensionBadge();
  syncMcpBridgeNow();
}

function updateExtensionBadge() {
  if (!runtimeState.hasVault) {
    chrome.action.setBadgeText({ text: "NEW" });
    chrome.action.setBadgeBackgroundColor({ color: "#6366F1" });
    return;
  }
  if (runtimeState.unlocked) {
    chrome.action.setBadgeText({ text: runtimeState.mcpEnabled ? "MCP" : "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#10B981" });
  } else {
    chrome.action.setBadgeText({ text: "LOCK" });
    chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
  }
}

async function addMcpAudit(action, detail) {
  const item = {
    id: KeeCrypto.randomUUID(),
    time: new Date().toLocaleTimeString("pt-BR"),
    action,
    detail,
  };
  runtimeState.mcpAuditLog.unshift(item);
  runtimeState.mcpAuditLog = runtimeState.mcpAuditLog.slice(0, 50);
  await chrome.storage.local.set({ mcpAuditLog: runtimeState.mcpAuditLog });
}

// ---------------------------------------------------------------------------
// 2. Vault Persistence & GitHub Auto-Sync
// ---------------------------------------------------------------------------
async function persistVaultAndSync(commitMsg = "") {
  if (!runtimeState.unlocked || !runtimeState.vault || !runtimeState.masterPassword) {
    throw new Error("O cofre está trancado.");
  }
  runtimeState.vault.updatedAt = new Date().toISOString();
  const encRes = await KeeCrypto.encryptVaultToKdbxBytes(
    runtimeState.vault,
    runtimeState.masterPassword,
    runtimeState.keyFileHex
  );

  const toStore = {
    encryptedKdbxBase64: encRes.base64,
    permanentUnlock: runtimeState.permanentUnlock,
    mcpEnabled: runtimeState.mcpEnabled,
  };

  if (runtimeState.permanentUnlock) {
    toStore.savedMasterSession = {
      masterPassword: runtimeState.masterPassword,
      keyFileHex: runtimeState.keyFileHex,
    };
  } else {
    toStore.savedMasterSession = null;
  }

  await chrome.storage.local.set(toStore);
  runtimeState.hasVault = true;
  updateExtensionBadge();
  syncMcpBridgeNow();

  // Trigger background GitHub Sync if configured and autoSync is ON
  const gh = runtimeState.githubConfig;
  if (gh.autoSync && gh.token && gh.repoFullName) {
    syncWithGitHub({ mode: "auto", commitMessage: commitMsg }).catch((err) => {
      runtimeState.githubConfig.lastError = err.message;
      chrome.storage.local.set({ githubConfig: runtimeState.githubConfig });
    });
  }

  return encRes.base64;
}

async function syncWithGitHub({ mode = "both", commitMessage = "" } = {}) {
  const gh = runtimeState.githubConfig;
  if (!gh.token || !gh.repoFullName) {
    throw new Error("Configure seu Token PAT e Repositório na aba GitHub primeiro.");
  }

  // Ensure Private Repo exists
  const repoCheck = await GitHubSync.ensurePrivateRepo(gh.token, gh.repoFullName);
  gh.repoFullName = repoCheck.fullName;

  // Step 1: Pull remote .kdbx if it exists
  const remote = await GitHubSync.pullEncryptedKdbx({
    token: gh.token,
    repoFullName: gh.repoFullName,
    filePath: gh.filePath || "cofre.kdbx",
    branch: gh.branch || "main",
  });

  if (remote.exists && remote.contentBase64 && mode !== "push_only") {
    try {
      const decRemote = await KeeCrypto.decryptVaultFromKdbxBytes(
        remote.contentBase64,
        runtimeState.masterPassword,
        runtimeState.keyFileHex
      );
      if (runtimeState.vault) {
        runtimeState.vault = KeeCrypto.mergeVaults(runtimeState.vault, decRemote.vault);
      } else {
        runtimeState.vault = decRemote.vault;
      }
      gh.lastSha = remote.sha;
    } catch (decErr) {
      if (mode === "pull_only") {
        throw new Error(`Não foi possível descriptografar o .kdbx do GitHub: ${decErr.message}`);
      }
    }
  }

  // Step 2: Re-encrypt merged vault and Push to GitHub (unless pull_only)
  const encRes = await KeeCrypto.encryptVaultToKdbxBytes(
    runtimeState.vault,
    runtimeState.masterPassword,
    runtimeState.keyFileHex
  );
  await chrome.storage.local.set({ encryptedKdbxBase64: encRes.base64 });

  if (mode !== "pull_only") {
    const pushRes = await GitHubSync.pushEncryptedKdbx({
      token: gh.token,
      repoFullName: gh.repoFullName,
      filePath: gh.filePath || "cofre.kdbx",
      branch: gh.branch || "main",
      contentBase64: encRes.base64,
      sha: remote.exists ? remote.sha : gh.lastSha,
      commitMessage: commitMessage || `🔐 KeeVault XC Sync (${runtimeState.vault.entries.length} senhas)`,
    });
    gh.lastSha = pushRes.sha;
  }

  gh.lastSyncAt = new Date().toISOString();
  gh.lastError = null;
  await chrome.storage.local.set({ githubConfig: gh });
  syncMcpBridgeNow();
  return {
    ok: true,
    repoFullName: gh.repoFullName,
    lastSyncAt: gh.lastSyncAt,
    entriesCount: runtimeState.vault?.entries?.length || 0,
    repoCreated: repoCheck.created,
  };
}

// ---------------------------------------------------------------------------
// 3. Domain Matching & Blind Autofill Execution
// ---------------------------------------------------------------------------
function extractHostname(urlStr) {
  try {
    const u = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
    return u.hostname.replace(/^www\./i, "").toLowerCase();
  } catch (e) {
    return (urlStr || "").toLowerCase();
  }
}

function findMatchingEntriesForUrl(urlStr, onlyAiAllowed = false) {
  if (!runtimeState.unlocked || !runtimeState.vault) return [];
  const targetHost = extractHostname(urlStr);
  return runtimeState.vault.entries.filter((e) => {
    if (onlyAiAllowed && !e.aiAllowed) return false;
    if (!targetHost) return true;
    const entryHost = extractHostname(e.url);
    if (!entryHost) return false;
    return (
      targetHost === entryHost ||
      targetHost.endsWith(`.${entryHost}`) ||
      entryHost.endsWith(`.${targetHost}`) ||
      e.title.toLowerCase().includes(targetHost.split(".")[0])
    );
  });
}

async function executeAutofillOnTab(tabId, entryId, source = "user") {
  if (!runtimeState.unlocked || !runtimeState.vault) {
    throw new Error("Cofre trancado. Desbloqueie com a Senha Mestra primeiro.");
  }
  const entry = runtimeState.vault.entries.find((e) => e.id === entryId);
  if (!entry) {
    throw new Error("Credencial não encontrada no cofre.");
  }
  if (source === "mcp" && (!runtimeState.mcpEnabled || !entry.aiAllowed)) {
    throw new Error("Esta credencial não está autorizada para uso por IA (MCP).");
  }

  let totpCode = "";
  if (entry.totpSecret) {
    const totp = await KeeCrypto.generateTOTP(entry.totpSecret);
    if (totp) totpCode = totp.code;
  }

  if (source === "mcp") {
    await addMcpAudit(
      "Blind Autofill (IA)",
      `Preencheu login '${entry.title}' (${entry.username}) sem expor a senha.`
    );
  }

  // Send autofill payload directly to the tab's content script
  try {
    const resp = await chrome.tabs.sendMessage(tabId, {
      type: "KEEVAULT_FILL_CREDENTIALS",
      payload: {
        title: entry.title,
        username: entry.username,
        password: entry.password,
        totpCode,
        autoSubmit: source === "mcp",
      },
    });
    return { ok: true, filled: true, title: entry.title, username: entry.username, totpFilled: Boolean(totpCode), resp };
  } catch (err) {
    // Fallback: inject via chrome.scripting.executeScript if content script wasn't loaded yet
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (creds) => {
        const setNativeValue = (el, val) => {
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
          if (setter) setter.call(el, val);
          else el.value = val;
          el.dispatchEvent(new Event("input", { bubbles: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
        };
        const passInputs = Array.from(document.querySelectorAll('input[type="password"]:not([disabled])'));
        const userInputs = Array.from(
          document.querySelectorAll(
            'input[type="email"], input[type="text"], input[name*="user" i], input[name*="login" i], input[name*="email" i], input[autocomplete="username"]'
          )
        ).filter((el) => el.offsetParent !== null);
        if (userInputs.length && creds.username) setNativeValue(userInputs[0], creds.username);
        if (passInputs.length && creds.password) setNativeValue(passInputs[0], creds.password);
      },
      args: [{ username: entry.username, password: entry.password, totpCode }],
    });
    return { ok: true, filled: true, title: entry.title, username: entry.username, totpFilled: Boolean(totpCode) };
  }
}

// ---------------------------------------------------------------------------
// 4. Local MCP Bridge Synchronization (Zero-Knowledge Catalog + Blind Actions)
// ---------------------------------------------------------------------------
async function syncMcpBridgeNow() {
  try {
    // Build sanitized catalog (NEVER includes password or raw totpSecret!)
    const safeEntries =
      runtimeState.unlocked && runtimeState.mcpEnabled && runtimeState.vault
        ? runtimeState.vault.entries
            .filter((e) => e.aiAllowed)
            .map((e) => ({
              id: e.id,
              groupId: e.groupId,
              title: e.title,
              username: e.username,
              url: e.url,
              domain: extractHostname(e.url),
              hasTotp: Boolean(e.totpSecret),
              notesPreview: (e.notes || "").slice(0, 80),
              updatedAt: e.updatedAt,
            }))
        : [];

    const resp = await fetch(`${MCP_BRIDGE_URL}/extension-sync`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hasVault: runtimeState.hasVault,
        unlocked: runtimeState.unlocked,
        permanentUnlock: runtimeState.permanentUnlock,
        mcpEnabled: runtimeState.mcpEnabled,
        entries: safeEntries,
      }),
    });

    if (!resp.ok) {
      runtimeState.mcpBridgeOnline = false;
      return;
    }

    runtimeState.mcpBridgeOnline = true;
    const data = await resp.json();

    // Execute any queued MCP commands from AI agents (Blind Autofill or TOTP generation)
    if (Array.isArray(data.pendingCommands) && data.pendingCommands.length > 0) {
      for (const cmd of data.pendingCommands) {
        let cmdResult = { id: cmd.id, ok: false };
        try {
          if (!runtimeState.unlocked) {
            throw new Error("Cofre trancado. Peça ao usuário para desbloquear na extensão KeeVault XC.");
          }
          if (!runtimeState.mcpEnabled) {
            throw new Error("O botão 'Acesso MCP para IA' está em OFF na extensão KeeVault XC.");
          }

          if (cmd.action === "autofill_login") {
            const entry = runtimeState.vault.entries.find((e) => e.id === cmd.entryId);
            if (!entry || !entry.aiAllowed) {
              throw new Error("Entrada não encontrada ou não autorizada para IA.");
            }
            let targetTabId = null;
            const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });

            if (cmd.openUrlIfNeeded && entry.url) {
              const targetUrl = entry.url.startsWith("http") ? entry.url : `https://${entry.url}`;
              const curHost = activeTab?.url ? extractHostname(activeTab.url) : "";
              const entryHost = extractHostname(targetUrl);
              if (!activeTab || (entryHost && !curHost.includes(entryHost))) {
                const newTab = await chrome.tabs.create({ url: targetUrl, active: true });
                targetTabId = newTab.id;
                await new Promise((r) => setTimeout(r, 2200));
              } else {
                targetTabId = activeTab.id;
              }
            } else if (activeTab) {
              targetTabId = activeTab.id;
            }

            if (!targetTabId) throw new Error("Nenhuma aba ativa encontrada no Chrome.");
            const fillRes = await executeAutofillOnTab(targetTabId, entry.id, "mcp");
            cmdResult = { id: cmd.id, ok: true, result: fillRes };
          } else if (cmd.action === "get_totp") {
            const entry = runtimeState.vault.entries.find((e) => e.id === cmd.entryId);
            if (!entry || !entry.aiAllowed) {
              throw new Error("Entrada não encontrada ou não autorizada para IA.");
            }
            if (!entry.totpSecret) {
              throw new Error("Esta conta não possui segredo 2FA (TOTP) cadastrado.");
            }
            const totp = await KeeCrypto.generateTOTP(entry.totpSecret);
            await addMcpAudit("Código 2FA (IA)", `Gerou código TOTP de 6 dígitos para '${entry.title}'.`);
            cmdResult = { id: cmd.id, ok: true, result: totp };
          }
        } catch (e) {
          cmdResult = { id: cmd.id, ok: false, error: e.message };
        }

        await fetch(`${MCP_BRIDGE_URL}/command-result`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cmdResult),
        }).catch(() => {});
      }
    }
  } catch (e) {
    runtimeState.mcpBridgeOnline = false;
  }
}

// Poll MCP Bridge every 2.5 seconds while service worker is active + Chrome Alarm keepalive
setInterval(() => {
  initRuntimeState().then(() => syncMcpBridgeNow());
}, 2500);

chrome.alarms.create("keevault-mcp-poll", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "keevault-mcp-poll") {
    initRuntimeState().then(() => syncMcpBridgeNow());
  }
});

// ---------------------------------------------------------------------------
// 5. Context Menus & Keyboard Shortcuts
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  initRuntimeState();
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "keevault-fill",
      title: "🔐 Preencher Login desta página (KeeVault XC)",
      contexts: ["editable", "page"],
    });
    chrome.contextMenus.create({
      id: "keevault-gen-pass",
      title: "🎲 Gerar e Inserir Senha Militar (20 caracteres)",
      contexts: ["editable"],
    });
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  await initRuntimeState();
  if (!tab?.id) return;
  if (info.menuItemId === "keevault-fill") {
    const matches = findMatchingEntriesForUrl(tab.url || "");
    if (matches.length > 0) {
      await executeAutofillOnTab(tab.id, matches[0].id, "user");
    }
  } else if (info.menuItemId === "keevault-gen-pass") {
    const gen = KeeCrypto.generatePassword({ length: 20 });
    chrome.tabs.sendMessage(tab.id, {
      type: "KEEVAULT_INSERT_GENERATED_PASSWORD",
      password: gen.password,
    });
  }
});

chrome.commands.onCommand.addListener(async (command) => {
  await initRuntimeState();
  if (command === "autofill-active-tab") {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.id && tab.url) {
      const matches = findMatchingEntriesForUrl(tab.url);
      if (matches.length > 0) {
        await executeAutofillOnTab(tab.id, matches[0].id, "user");
      }
    }
  }
});

// ---------------------------------------------------------------------------
// 6. Message Router for Popup UI & Content Scripts
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    await initRuntimeState();

    switch (msg.type) {
      case "GET_STATE": {
        await syncMcpBridgeNow();
        sendResponse({
          ok: true,
          hasVault: runtimeState.hasVault,
          unlocked: runtimeState.unlocked,
          permanentUnlock: runtimeState.permanentUnlock,
          mcpEnabled: runtimeState.mcpEnabled,
          mcpBridgeOnline: runtimeState.mcpBridgeOnline,
          mcpAuditLog: runtimeState.mcpAuditLog,
          githubConfig: runtimeState.githubConfig,
          vault: runtimeState.unlocked ? runtimeState.vault : null,
        });
        break;
      }

      case "CREATE_NEW_VAULT": {
        const { vaultName, masterPassword, keyFileHex, permanentUnlock, seedDemoEntries } = msg;
        const newVault = KeeCrypto.createEmptyVault(vaultName || "Meu Cofre KeeVault XC");
        if (seedDemoEntries) {
          newVault.entries.push(
            KeeCrypto.normalizeEntry({
              groupId: "ai",
              title: "Google / Agenda & Workspace",
              username: "seu-email@gmail.com",
              password: KeeCrypto.generatePassword({ length: 18 }).password,
              url: "https://accounts.google.com",
              notes: "Conta liberada para automação via MCP.",
              aiAllowed: true,
              favorite: true,
            }),
            KeeCrypto.normalizeEntry({
              groupId: "work",
              title: "GitHub — Conta Principal",
              username: "rapha",
              password: KeeCrypto.generatePassword({ length: 22 }).password,
              url: "https://github.com/login",
              notes: "Repositórios privados e sincronização .kdbx.",
              aiAllowed: true,
              favorite: true,
            })
          );
        }
        runtimeState.vault = newVault;
        runtimeState.masterPassword = masterPassword;
        runtimeState.keyFileHex = keyFileHex || "";
        runtimeState.permanentUnlock = permanentUnlock !== undefined ? Boolean(permanentUnlock) : true;
        runtimeState.unlocked = true;
        await persistVaultAndSync("🎉 Cofre inicial KeeVault XC criado");
        sendResponse({ ok: true, vault: runtimeState.vault });
        break;
      }

      case "UNLOCK_VAULT": {
        const { masterPassword, keyFileHex, permanentUnlock } = msg;
        const stored = await chrome.storage.local.get(["encryptedKdbxBase64"]);
        if (!stored.encryptedKdbxBase64) {
          throw new Error("Nenhum cofre encontrado. Crie um novo ou baixe do GitHub Privado.");
        }
        const decRes = await KeeCrypto.decryptVaultFromKdbxBytes(
          stored.encryptedKdbxBase64,
          masterPassword,
          keyFileHex || ""
        );
        runtimeState.vault = decRes.vault;
        runtimeState.masterPassword = masterPassword;
        runtimeState.keyFileHex = keyFileHex || "";
        runtimeState.unlocked = true;
        if (permanentUnlock !== undefined) {
          runtimeState.permanentUnlock = Boolean(permanentUnlock);
        }
        await chrome.storage.local.set({
          permanentUnlock: runtimeState.permanentUnlock,
          savedMasterSession: runtimeState.permanentUnlock
            ? { masterPassword, keyFileHex: keyFileHex || "" }
            : null,
        });
        updateExtensionBadge();
        syncMcpBridgeNow();
        sendResponse({ ok: true, vault: runtimeState.vault });
        break;
      }

      case "LOCK_VAULT": {
        runtimeState.unlocked = false;
        runtimeState.vault = null;
        runtimeState.masterPassword = "";
        await chrome.storage.local.set({ savedMasterSession: null });
        updateExtensionBadge();
        syncMcpBridgeNow();
        sendResponse({ ok: true });
        break;
      }

      case "SET_PERMANENT_UNLOCK": {
        runtimeState.permanentUnlock = Boolean(msg.enabled);
        await chrome.storage.local.set({
          permanentUnlock: runtimeState.permanentUnlock,
          savedMasterSession:
            runtimeState.permanentUnlock && runtimeState.unlocked
              ? { masterPassword: runtimeState.masterPassword, keyFileHex: runtimeState.keyFileHex }
              : null,
        });
        updateExtensionBadge();
        syncMcpBridgeNow();
        sendResponse({ ok: true, permanentUnlock: runtimeState.permanentUnlock });
        break;
      }

      case "SET_MCP_ENABLED": {
        runtimeState.mcpEnabled = Boolean(msg.enabled);
        await chrome.storage.local.set({ mcpEnabled: runtimeState.mcpEnabled });
        await addMcpAudit(
          runtimeState.mcpEnabled ? "MCP Ativado (ON)" : "MCP Desativado (OFF)",
          runtimeState.mcpEnabled
            ? "Acesso liberado para IAs consultarem catálogo e efetuarem Blind Autofill."
            : "Acesso das IAs bloqueado."
        );
        updateExtensionBadge();
        await syncMcpBridgeNow();
        sendResponse({ ok: true, mcpEnabled: runtimeState.mcpEnabled });
        break;
      }

      case "SAVE_ENTRY": {
        if (!runtimeState.unlocked || !runtimeState.vault) throw new Error("Cofre trancado.");
        const incoming = KeeCrypto.normalizeEntry({
          ...msg.entry,
          updatedAt: new Date().toISOString(),
        });
        const idx = runtimeState.vault.entries.findIndex((e) => e.id === incoming.id);
        if (idx >= 0) {
          const prev = { ...runtimeState.vault.entries[idx], history: [] };
          incoming.history = [prev, ...(runtimeState.vault.entries[idx].history || [])].slice(0, 8);
          runtimeState.vault.entries[idx] = incoming;
        } else {
          runtimeState.vault.entries.unshift(incoming);
        }
        await persistVaultAndSync(`🔐 Salvo: ${incoming.title}`);
        sendResponse({ ok: true, entry: incoming, vault: runtimeState.vault });
        break;
      }

      case "DELETE_ENTRY": {
        if (!runtimeState.unlocked || !runtimeState.vault) throw new Error("Cofre trancado.");
        const target = runtimeState.vault.entries.find((e) => e.id === msg.entryId);
        runtimeState.vault.entries = runtimeState.vault.entries.filter((e) => e.id !== msg.entryId);
        runtimeState.vault.deletedObjects[msg.entryId] = new Date().toISOString();
        await persistVaultAndSync(`🗑️ Removido: ${target?.title || msg.entryId}`);
        sendResponse({ ok: true, vault: runtimeState.vault });
        break;
      }

      case "AUTOFILL_TAB": {
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (!tab?.id) throw new Error("Nenhuma aba ativa no navegador.");
        const res = await executeAutofillOnTab(tab.id, msg.entryId, "user");
        sendResponse(res);
        break;
      }

      case "SAVE_GITHUB_CONFIG": {
        runtimeState.githubConfig = { ...runtimeState.githubConfig, ...msg.config };
        await chrome.storage.local.set({ githubConfig: runtimeState.githubConfig });
        sendResponse({ ok: true, githubConfig: runtimeState.githubConfig });
        break;
      }

      case "GITHUB_SYNC_NOW": {
        if (msg.config) {
          runtimeState.githubConfig = { ...runtimeState.githubConfig, ...msg.config };
          await chrome.storage.local.set({ githubConfig: runtimeState.githubConfig });
        }
        // Special case: if user doesn't have a local vault yet and wants to clone from GitHub
        if (!runtimeState.unlocked && msg.mode === "clone_with_password") {
          const gh = runtimeState.githubConfig;
          const remote = await GitHubSync.pullEncryptedKdbx({
            token: gh.token,
            repoFullName: gh.repoFullName,
            filePath: gh.filePath || "cofre.kdbx",
            branch: gh.branch || "main",
          });
          if (!remote.exists) {
            throw new Error("Arquivo .kdbx não encontrado neste repositório GitHub.");
          }
          const decRes = await KeeCrypto.decryptVaultFromKdbxBytes(
            remote.contentBase64,
            msg.masterPassword,
            msg.keyFileHex || ""
          );
          runtimeState.vault = decRes.vault;
          runtimeState.masterPassword = msg.masterPassword;
          runtimeState.keyFileHex = msg.keyFileHex || "";
          runtimeState.unlocked = true;
          runtimeState.hasVault = true;
          await persistVaultAndSync();
          sendResponse({ ok: true, vault: runtimeState.vault });
          break;
        }

        const syncRes = await syncWithGitHub({ mode: msg.mode || "both" });
        sendResponse({ ...syncRes, vault: runtimeState.vault, githubConfig: runtimeState.githubConfig });
        break;
      }

      case "EXPORT_KDBX": {
        const stored = await chrome.storage.local.get(["encryptedKdbxBase64"]);
        const xml = runtimeState.vault ? KeeCrypto.exportToKeePassXCXml(runtimeState.vault) : "";
        sendResponse({
          ok: true,
          kdbxBase64: stored.encryptedKdbxBase64 || "",
          keepassXml: xml,
        });
        break;
      }

      case "IMPORT_ENTRIES": {
        if (!runtimeState.unlocked || !runtimeState.vault) throw new Error("Desbloqueie o cofre primeiro.");
        if (msg.format === "kdbx_binary") {
          const decImported = await KeeCrypto.decryptVaultFromKdbxBytes(
            msg.contentBase64,
            msg.importPassword || runtimeState.masterPassword,
            msg.importKeyFile || ""
          );
          runtimeState.vault = KeeCrypto.mergeVaults(runtimeState.vault, decImported.vault);
        } else {
          const entries = KeeCrypto.importFromKeePassXCXmlOrCsv(msg.textContent);
          for (const e of entries) {
            runtimeState.vault.entries.unshift(e);
          }
        }
        await persistVaultAndSync("📥 Importação de senhas concluída");
        sendResponse({ ok: true, vault: runtimeState.vault });
        break;
      }

      // Content Script Queries
      case "CONTENT_QUERY_DOMAIN_LOGINS": {
        const tabUrl = sender.tab?.url || msg.url || "";
        if (!runtimeState.unlocked) {
          sendResponse({ ok: true, unlocked: false, entries: [] });
          break;
        }
        const matches = findMatchingEntriesForUrl(tabUrl, false).map((e) => ({
          id: e.id,
          title: e.title,
          username: e.username,
          url: e.url,
          hasTotp: Boolean(e.totpSecret),
        }));
        sendResponse({ ok: true, unlocked: true, entries: matches });
        break;
      }

      case "CONTENT_REQUEST_FILL_ENTRY": {
        const tabId = sender.tab?.id;
        if (!tabId) throw new Error("Tab ID ausente.");
        const res = await executeAutofillOnTab(tabId, msg.entryId, "user");
        sendResponse(res);
        break;
      }

      case "CONTENT_GENERATE_PASSWORD": {
        const gen = KeeCrypto.generatePassword(msg.options || { length: 20 });
        sendResponse({ ok: true, ...gen });
        break;
      }

      case "CONTENT_OFFER_SAVE_LOGIN": {
        if (!runtimeState.unlocked || !runtimeState.vault) {
          sendResponse({ ok: false, reason: "locked" });
          break;
        }
        const { url, title, username, password } = msg.payload;
        if (!password) {
          sendResponse({ ok: false });
          break;
        }
        const host = extractHostname(url);
        const existing = runtimeState.vault.entries.find(
          (e) => extractHostname(e.url) === host && e.username.toLowerCase() === (username || "").toLowerCase()
        );
        if (existing && existing.password === password) {
          sendResponse({ ok: true, status: "already_saved" });
          break;
        }
        const savedEntry = KeeCrypto.normalizeEntry({
          id: existing ? existing.id : KeeCrypto.randomUUID(),
          groupId: existing ? existing.groupId : "general",
          title: existing ? existing.title : title || host || "Novo Login",
          username: username || "",
          password,
          url: url || "",
          aiAllowed: true,
        });
        if (existing) {
          const idx = runtimeState.vault.entries.findIndex((e) => e.id === existing.id);
          runtimeState.vault.entries[idx] = savedEntry;
        } else {
          runtimeState.vault.entries.unshift(savedEntry);
        }
        await persistVaultAndSync(`🔐 Capturado no navegador: ${savedEntry.title}`);
        sendResponse({ ok: true, status: existing ? "updated" : "created", entry: savedEntry });
        break;
      }

      default:
        sendResponse({ ok: false, error: `Comando desconhecido: ${msg.type}` });
    }
  })().catch((err) => {
    sendResponse({ ok: false, error: err.message || String(err) });
  });
  return true;
});
