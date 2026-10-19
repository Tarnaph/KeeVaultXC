/**
 * KeeVault XC Studio - Popup & Full-Tab Controller
 */

(() => {
  let appState = null;
  let currentGroupFilter = "all";
  let currentActiveTab = null;
  let totpInterval = null;

  const $ = (id) => document.getElementById(id);

  function showToast(msg, isError = false) {
    const bar = $("toast-bar");
    if (!bar) return;
    bar.textContent = msg;
    bar.style.background = isError ? "rgba(244, 63, 94, 0.96)" : "rgba(16, 185, 129, 0.96)";
    bar.style.color = isError ? "#fff" : "#042f1e";
    bar.classList.remove("hidden");
    clearTimeout(bar._timer);
    bar._timer = setTimeout(() => bar.classList.add("hidden"), 3200);
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function extractHostname(urlStr) {
    try {
      const u = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
      return u.hostname.replace(/^www\./i, "").toLowerCase();
    } catch (e) {
      return (urlStr || "").toLowerCase();
    }
  }

  // -------------------------------------------------------------------------
  // 1. State Synchronization with Background Service Worker
  // -------------------------------------------------------------------------
  async function refreshState() {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    currentActiveTab = tab || null;

    const res = await chrome.runtime.sendMessage({ type: "GET_STATE" });
    if (!res || !res.ok) return;
    appState = res;
    renderAll();
  }

  function renderAll() {
    if (!appState) return;

    const authScreen = $("auth-screen");
    const studioScreen = $("studio-screen");
    const lockBtn = $("btn-lock-now");

    if (!appState.unlocked) {
      authScreen.classList.remove("hidden");
      studioScreen.classList.add("hidden");
      lockBtn.classList.add("hidden");
      if (!appState.hasVault) {
        switchAuthMode("create");
      } else {
        switchAuthMode("unlock");
      }
      return;
    }

    // Unlocked Studio View
    authScreen.classList.add("hidden");
    studioScreen.classList.remove("hidden");
    lockBtn.classList.remove("hidden");

    // Update Dual ON/OFF Switches
    const permChk = $("toggle-permanent-unlock");
    const mcpChk = $("toggle-mcp-access");
    permChk.checked = Boolean(appState.permanentUnlock);
    mcpChk.checked = Boolean(appState.mcpEnabled);

    $("lbl-perm-state").textContent = appState.permanentUnlock ? "ON (Sem expirar)" : "OFF (Sessão)";
    $("lbl-perm-state").style.color = appState.permanentUnlock ? "#10b981" : "#f59e0b";

    $("lbl-mcp-state").textContent = appState.mcpEnabled ? "ON (Blind Login)" : "OFF (Bloqueado)";
    $("lbl-mcp-state").style.color = appState.mcpEnabled ? "#818cf8" : "#94a3b8";

    // Header Sync Subtitle
    const gh = appState.githubConfig || {};
    const entryCount = appState.vault?.entries?.length || 0;
    if (gh.repoFullName && gh.lastSyncAt) {
      const t = new Date(gh.lastSyncAt).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
      $("header-sync-status").textContent = `🐙 Sync: ${gh.repoFullName} às ${t} • ${entryCount} senhas`;
    } else {
      $("header-sync-status").textContent = `🔓 Destrancado • ${entryCount} senhas no cofre .KDBX`;
    }

    // Populate GitHub Config inputs
    if ($("gh-token") && !$("gh-token").dataset.dirty) {
      $("gh-token").value = gh.token || "";
      $("gh-repo").value = gh.repoFullName || "";
      $("gh-filepath").value = gh.filePath || "cofre.kdbx";
      $("gh-autosync").checked = gh.autoSync !== false;
    }

    renderActiveTabBanner();
    renderEntriesList();
    renderMcpView();
  }

  // -------------------------------------------------------------------------
  // 2. Auth Screen Mode Switching & Actions
  // -------------------------------------------------------------------------
  function switchAuthMode(mode) {
    document.querySelectorAll(".auth-tab").forEach((b) => {
      b.classList.toggle("active", b.dataset.authMode === mode);
    });
    $("auth-panel-unlock").classList.toggle("hidden", mode !== "unlock");
    $("auth-panel-create").classList.toggle("hidden", mode !== "create");
    $("auth-panel-clone").classList.toggle("hidden", mode !== "clone");
  }

  function renderActiveTabBanner() {
    const banner = $("active-tab-banner");
    if (!currentActiveTab?.url || ! currentActiveTab.url.startsWith("http")) {
      banner.classList.add("hidden");
      return;
    }
    const host = extractHostname(currentActiveTab.url);
    const matches = (appState.vault?.entries || []).filter((e) => {
      const eh = extractHostname(e.url);
      return eh && (host === eh || host.endsWith(`.${eh}`) || eh.endsWith(`.${host}`));
    });

    if (!matches.length) {
      banner.classList.add("hidden");
      return;
    }

    banner.classList.remove("hidden");
    const first = matches[0];
    $("tab-banner-title").textContent = `${first.title} (${host})`;
    $("tab-banner-sub").textContent = `${first.username || "Login pronto"} • Clique para preencher em 1 clique`;
    $("btn-quick-fill-banner").onclick = async () => {
      const res = await chrome.runtime.sendMessage({ type: "AUTOFILL_TAB", entryId: first.id });
      if (res?.ok) showToast(`⚡ Preenchido em ${host}!`);
      else showToast(res?.error || "Erro ao preencher", true);
    };
  }

  // -------------------------------------------------------------------------
  // 3. Render Vault Entries List + Live 2FA TOTP Counter
  // -------------------------------------------------------------------------
  async function renderEntriesList() {
    const container = $("entries-list");
    if (!container || !appState?.vault) return;

    const q = ($("vault-search")?.value || "").trim().toLowerCase();
    const entries = (appState.vault.entries || []).filter((e) => {
      if (currentGroupFilter === "fav" && !e.favorite) return false;
      if (currentGroupFilter === "ai" && !e.aiAllowed) return false;
      if (
        currentGroupFilter !== "all" &&
        currentGroupFilter !== "fav" &&
        currentGroupFilter !== "ai" &&
        e.groupId !== currentGroupFilter
      ) {
        return false;
      }
      if (!q) return true;
      return (
        (e.title || "").toLowerCase().includes(q) ||
        (e.username || "").toLowerCase().includes(q) ||
        (e.url || "").toLowerCase().includes(q) ||
        (e.notes || "").toLowerCase().includes(q)
      );
    });

    container.innerHTML = "";
    if (!entries.length) {
      container.innerHTML = `
        <div class="card-box" style="text-align:center;padding:24px 12px;color:#94a3b8;">
          Nenhuma senha encontrada neste filtro.<br/>
          Clique em <strong>➕ Nova</strong> para cadastrar ou importe seu <code>.kdbx</code>!
        </div>
      `;
      return;
    }

    for (const entry of entries) {
      const card = document.createElement("div");
      card.className = "entry-card";
      const domain = extractHostname(entry.url) || "local";

      let totpHtml = "";
      if (entry.totpSecret) {
        const totp = await KeeCrypto.generateTOTP(entry.totpSecret);
        if (totp) {
          totpHtml = `<span class="totp-chip" data-copy-totp="${totp.code}" title="Clique para copiar código 2FA (${totp.remainingSeconds}s)">⏱️ ${totp.formatted} (${totp.remainingSeconds}s)</span>`;
        }
      }

      card.innerHTML = `
        <div class="entry-top">
          <div class="entry-title-wrap">
            <span>${entry.favorite ? "⭐" : "🔐"}</span>
            <span class="entry-title" title="${escapeHtml(entry.title)}">${escapeHtml(entry.title)}</span>
          </div>
          <div style="display:flex;gap:5px;align-items:center;">
            ${totpHtml}
            <span class="ai-pill ${entry.aiAllowed ? "on" : "off"}" data-toggle-ai="${entry.id}" title="Clique para alternar se IAs (MCP) podem logar com esta conta">
              🤖 IA ${entry.aiAllowed ? "ON" : "OFF"}
            </span>
          </div>
        </div>
        <div class="entry-sub">
          <span>👤 ${escapeHtml(entry.username || "(Sem usuário)")}</span>
          <span style="color:#38bdf8">${escapeHtml(domain)}</span>
        </div>
        <div class="entry-sub hidden" id="pass-reveal-${entry.id}" style="background:#0f1523;padding:5px 8px;border-radius:6px;font-family:Consolas,monospace;color:#34d399;">
          🔑 ${escapeHtml(entry.password)}
        </div>
        <div class="entry-actions">
          <button class="act-btn fill" data-act="fill" data-id="${entry.id}">⚡ Preencher</button>
          <button class="act-btn" data-act="copy-user" data-id="${entry.id}">👤 Usuário</button>
          <button class="act-btn" data-act="copy-pass" data-id="${entry.id}">🔑 Senha</button>
          <button class="act-btn icon-only" data-act="reveal" data-id="${entry.id}" title="Mostrar/Ocultar Senha">👁️</button>
          <button class="act-btn icon-only" data-act="edit" data-id="${entry.id}" title="Editar">✏️</button>
          <button class="act-btn icon-only" data-act="delete" data-id="${entry.id}" title="Excluir">🗑️</button>
        </div>
      `;

      container.appendChild(card);
    }

    // Bind card actions
    container.querySelectorAll("[data-copy-totp]").forEach((el) => {
      el.onclick = () => {
        navigator.clipboard.writeText(el.dataset.copyTotp);
        showToast(`⏱️ Código 2FA (${el.dataset.copyTotp}) copiado!`);
      };
    });

    container.querySelectorAll("[data-toggle-ai]").forEach((el) => {
      el.onclick = async () => {
        const id = el.dataset.toggleAi;
        const target = appState.vault.entries.find((x) => x.id === id);
        if (!target) return;
        target.aiAllowed = !target.aiAllowed;
        const res = await chrome.runtime.sendMessage({ type: "SAVE_ENTRY", entry: target });
        if (res?.ok) {
          appState.vault = res.vault;
          renderEntriesList();
          showToast(
            target.aiAllowed
              ? `🤖 Login '${target.title}' liberado para IA (MCP)!`
              : `🔒 Login '${target.title}' ocultado para IA (MCP).`
          );
        }
      };
    });

    container.querySelectorAll("[data-act]").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const act = btn.dataset.act;
        const entry = appState.vault.entries.find((x) => x.id === id);
        if (!entry) return;

        if (act === "fill") {
          const res = await chrome.runtime.sendMessage({ type: "AUTOFILL_TAB", entryId: id });
          if (res?.ok) showToast(`⚡ Login '${entry.title}' preenchido na aba!`);
          else showToast(res?.error || "Abra um site para preencher", true);
        } else if (act === "copy-user") {
          await navigator.clipboard.writeText(entry.username || "");
          showToast(`👤 Usuário copiado!`);
        } else if (act === "copy-pass") {
          await navigator.clipboard.writeText(entry.password || "");
          showToast(`🔑 Senha copiada para a área de transferência!`);
        } else if (act === "reveal") {
          const rev = $(`pass-reveal-${id}`);
          if (rev) rev.classList.toggle("hidden");
        } else if (act === "edit") {
          openEditorForEntry(entry);
        } else if (act === "delete") {
          const res = await chrome.runtime.sendMessage({ type: "DELETE_ENTRY", entryId: id });
          if (res?.ok) {
            appState.vault = res.vault;
            renderEntriesList();
            showToast(`🗑️ '${entry.title}' removido.`);
          }
        }
      };
    });
  }

  // -------------------------------------------------------------------------
  // 4. Add / Edit Entry Form
  // -------------------------------------------------------------------------
  function openEditorForEntry(entry = null) {
    switchStudioView("editor");
    if (entry) {
      $("editor-form-title").textContent = `✏️ Editar: ${entry.title}`;
      $("edit-entry-id").value = entry.id;
      $("edit-title").value = entry.title || "";
      $("edit-group").value = entry.groupId || "general";
      $("edit-username").value = entry.username || "";
      $("edit-password").value = entry.password || "";
      $("edit-url").value = entry.url || "";
      $("edit-totp").value = entry.totpSecret || "";
      $("edit-notes").value = entry.notes || "";
      $("edit-ai-allowed").checked = entry.aiAllowed !== false;
      $("edit-favorite").checked = Boolean(entry.favorite);
    } else {
      $("editor-form-title").textContent = "➕ Adicionar Nova Senha ao Cofre";
      $("edit-entry-id").value = "";
      $("edit-title").value =
        currentActiveTab?.title && currentActiveTab.url?.startsWith("http")
          ? currentActiveTab.title.split(/[-|•]/)[0].trim()
          : "";
      $("edit-group").value = "general";
      $("edit-username").value = "";
      $("edit-password").value = KeeCrypto.generatePassword({ length: 20 }).password;
      $("edit-url").value = currentActiveTab?.url?.startsWith("http") ? currentActiveTab.url : "";
      $("edit-totp").value = "";
      $("edit-notes").value = "";
      $("edit-ai-allowed").checked = true;
      $("edit-favorite").checked = false;
    }
  }

  // -------------------------------------------------------------------------
  // 5. MCP Audit & Status View
  // -------------------------------------------------------------------------
  function renderMcpView() {
    if (!appState) return;
    const total = appState.vault?.entries?.length || 0;
    const allowed = (appState.vault?.entries || []).filter((e) => e.aiAllowed).length;
    const online = appState.mcpBridgeOnline;

    $("mcp-bridge-status-txt").textContent = online
      ? `🟢 Conectado ao Servidor MCP Local (127.0.0.1:18455) • ${allowed} de ${total} logins disponíveis para IA`
      : `⚪ Ponte MCP aguardando chamada do Antigravity • ${allowed} de ${total} logins marcados como IA ON`;

    $("mcp-live-pill").textContent = appState.mcpEnabled ? "MCP ON" : "MCP OFF";
    $("mcp-live-pill").style.background = appState.mcpEnabled
      ? "rgba(16, 185, 129, 0.2)"
      : "rgba(244, 63, 94, 0.2)";
    $("mcp-live-pill").style.color = appState.mcpEnabled ? "#10b981" : "#fda4af";

    const list = $("mcp-audit-list");
    const logs = appState.mcpAuditLog || [];
    if (!logs.length) {
      list.innerHTML = `<div class="audit-item" style="color:#94a3b8;">Nenhuma ação executada por IA ainda nesta sessão.</div>`;
      return;
    }
    list.innerHTML = logs
      .map(
        (l) => `
      <div class="audit-item">
        <span class="audit-time">${escapeHtml(l.time)}</span>
        <strong>${escapeHtml(l.action)}:</strong> ${escapeHtml(l.detail)}
      </div>
    `
      )
      .join("");
  }

  // -------------------------------------------------------------------------
  // 6. Password Generator Tab Logic
  // -------------------------------------------------------------------------
  function updateGeneratorPreview() {
    const mode = $("gen-mode").value;
    const length = parseInt($("gen-length").value, 10) || 20;
    $("gen-len-val").textContent = String(length);
    const res = KeeCrypto.generatePassword({
      mode,
      length,
      wordCount: Math.max(3, Math.min(8, Math.round(length / 4))),
      upper: $("gen-upper").checked,
      lower: $("gen-lower").checked,
      digits: $("gen-digits").checked,
      symbols: $("gen-symbols").checked,
      excludeAmbiguous: $("gen-no-ambig").checked,
    });
    $("gen-password-output").textContent = res.password;
    $("gen-entropy-badge").textContent = `${res.entropyBits} bits • ${res.strengthLabel}`;
  }

  function switchStudioView(viewName) {
    document.querySelectorAll(".nav-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === viewName);
    });
    ["vault", "editor", "generator", "github", "mcp"].forEach((v) => {
      $(`view-${v}`).classList.toggle("hidden", v !== viewName);
    });
    if (viewName === "generator") updateGeneratorPreview();
    if (viewName === "mcp") renderMcpView();
  }

  // -------------------------------------------------------------------------
  // 7. Wire Up All DOM Events
  // -------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", () => {
    refreshState();

    // Refresh 2FA TOTP countdown every second when unlocked
    totpInterval = setInterval(() => {
      if (appState?.unlocked && !$("view-vault").classList.contains("hidden")) {
        renderEntriesList();
      }
    }, 5000);

    // Auth Mode Tabs
    document.querySelectorAll(".auth-tab").forEach((btn) => {
      btn.onclick = () => switchAuthMode(btn.dataset.authMode);
    });

    // Eye password visibility toggles
    document.querySelectorAll("[data-toggle-pass]").forEach((btn) => {
      btn.onclick = () => {
        const inp = $(btn.dataset.togglePass);
        if (inp) inp.type = inp.type === "password" ? "text" : "password";
      };
    });

    // Open in Full Tab
    $("btn-open-tab").onclick = () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") });
    };

    // Lock Now (OFF)
    $("btn-lock-now").onclick = async () => {
      await chrome.runtime.sendMessage({ type: "LOCK_VAULT" });
      await refreshState();
      showToast("🔒 Cofre trancado e chave limpa da sessão!");
    };

    // Unlock Existing Vault
    $("btn-do-unlock").onclick = async () => {
      const masterPassword = $("unlock-password").value;
      const keyFileHex = $("unlock-keyfile").value;
      const permanentUnlock = $("unlock-permanent-chk").checked;
      if (!masterPassword) return showToast("Digite sua Senha Mestra!", true);
      const res = await chrome.runtime.sendMessage({
        type: "UNLOCK_VAULT",
        masterPassword,
        keyFileHex,
        permanentUnlock,
      });
      if (res?.ok) {
        $("unlock-password").value = "";
        await refreshState();
        showToast("🔓 Cofre destrancado com sucesso!");
      } else {
        showToast(res?.error || "Senha Mestra incorreta!", true);
      }
    };
    $("unlock-password").addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("btn-do-unlock").click();
    });

    // Create New Vault
    $("btn-do-create").onclick = async () => {
      const vaultName = $("create-vault-name").value.trim() || "Meu Cofre KeeVault XC";
      const masterPassword = $("create-password").value;
      const keyFileHex = $("create-keyfile").value.trim();
      const permanentUnlock = $("create-permanent-chk").checked;
      const seedDemoEntries = $("create-demo-chk").checked;
      if (!masterPassword || masterPassword.length < 4) {
        return showToast("Defina uma Senha Mestra (mínimo 4 caracteres)!", true);
      }
      const res = await chrome.runtime.sendMessage({
        type: "CREATE_NEW_VAULT",
        vaultName,
        masterPassword,
        keyFileHex,
        permanentUnlock,
        seedDemoEntries,
      });
      if (res?.ok) {
        await refreshState();
        showToast("🎉 Cofre .KDBX criado e destrancado!");
      } else {
        showToast(res?.error || "Erro ao criar cofre", true);
      }
    };

    // Clone from Private GitHub
    $("btn-do-clone").onclick = async () => {
      const token = $("clone-gh-token").value.trim();
      const repoFullName = $("clone-gh-repo").value.trim();
      const filePath = $("clone-gh-path").value.trim() || "cofre.kdbx";
      const masterPassword = $("clone-master-password").value;
      if (!token || !repoFullName || !masterPassword) {
        return showToast("Preencha Token, Repositório e Senha Mestra!", true);
      }
      showToast("⏳ Baixando e descriptografando .kdbx do GitHub...");
      const res = await chrome.runtime.sendMessage({
        type: "GITHUB_SYNC_NOW",
        mode: "clone_with_password",
        masterPassword,
        config: { token, repoFullName, filePath, autoSync: true },
      });
      if (res?.ok) {
        await refreshState();
        showToast("🐙 Cofre restaurado do GitHub Privado com sucesso!");
      } else {
        showToast(res?.error || "Erro ao restaurar do GitHub", true);
      }
    };

    // Dual Permanent Switches (Top Ribbon)
    $("toggle-permanent-unlock").onchange = async (e) => {
      const enabled = e.target.checked;
      await chrome.runtime.sendMessage({ type: "SET_PERMANENT_UNLOCK", enabled });
      await refreshState();
      showToast(
        enabled
          ? "🔓 Modo Permanente ON: O cofre ficará destrancado até você desligar."
          : "⏱️ Modo Permanente OFF: A chave não ficará salva ao fechar."
      );
    };

    $("toggle-mcp-access").onchange = async (e) => {
      const enabled = e.target.checked;
      await chrome.runtime.sendMessage({ type: "SET_MCP_ENABLED", enabled });
      await refreshState();
      showToast(
        enabled
          ? "🤖 Acesso MCP (IA) ON: Agentes autorizados podem fazer Blind Autofill."
          : "🔒 Acesso MCP (IA) OFF: Agentes bloqueados."
      );
    };

    // Studio Nav Buttons
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.onclick = () => {
        if (btn.dataset.view === "editor") {
          openEditorForEntry(null);
        } else {
          switchStudioView(btn.dataset.view);
        }
      };
    });

    // Search & Group Pills
    $("vault-search").oninput = () => renderEntriesList();
    document.querySelectorAll(".group-pill").forEach((pill) => {
      pill.onclick = () => {
        document.querySelectorAll(".group-pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        currentGroupFilter = pill.dataset.group;
        renderEntriesList();
      };
    });

    // Editor Actions
    $("btn-autofill-current-url").onclick = () => {
      if (currentActiveTab?.url?.startsWith("http")) {
        $("edit-url").value = currentActiveTab.url;
        if (!$("edit-title").value) {
          $("edit-title").value = (currentActiveTab.title || "").split(/[-|•]/)[0].trim();
        }
      }
    };

    $("btn-edit-gen-pass").onclick = () => {
      const gen = KeeCrypto.generatePassword({ length: 20 });
      $("edit-password").value = gen.password;
      $("edit-password").type = "text";
      showToast(`🎲 Senha forte gerada (${gen.entropyBits} bits)!`);
    };

    $("btn-save-entry").onclick = async () => {
      const entry = {
        id: $("edit-entry-id").value || KeeCrypto.randomUUID(),
        title: $("edit-title").value.trim() || "Sem título",
        groupId: $("edit-group").value,
        username: $("edit-username").value.trim(),
        password: $("edit-password").value,
        url: $("edit-url").value.trim(),
        totpSecret: $("edit-totp").value.trim(),
        notes: $("edit-notes").value.trim(),
        aiAllowed: $("edit-ai-allowed").checked,
        favorite: $("edit-favorite").checked,
      };
      const res = await chrome.runtime.sendMessage({ type: "SAVE_ENTRY", entry });
      if (res?.ok) {
        appState.vault = res.vault;
        switchStudioView("vault");
        renderAll();
        showToast(`💾 '${entry.title}' salvo no cofre!`);
      } else {
        showToast(res?.error || "Erro ao salvar", true);
      }
    };

    $("btn-cancel-edit").onclick = () => switchStudioView("vault");

    // Generator Controls
    ["gen-mode", "gen-length", "gen-upper", "gen-lower", "gen-digits", "gen-symbols", "gen-no-ambig"].forEach((id) => {
      $(id).oninput = updateGeneratorPreview;
      $(id).onchange = updateGeneratorPreview;
    });
    $("btn-gen-refresh").onclick = updateGeneratorPreview;
    $("btn-gen-copy").onclick = async () => {
      const pw = $("gen-password-output").textContent;
      await navigator.clipboard.writeText(pw);
      showToast("📋 Senha copiada!");
    };
    $("btn-gen-fill-tab").onclick = async () => {
      const pw = $("gen-password-output").textContent;
      if (currentActiveTab?.id) {
        await chrome.tabs.sendMessage(currentActiveTab.id, {
          type: "KEEVAULT_INSERT_GENERATED_PASSWORD",
          password: pw,
        });
        showToast("⚡ Senha inserida na aba atual e copiada!");
      }
    };

    // GitHub Sync Controls
    const getGhFormConfig = () => ({
      token: $("gh-token").value.trim(),
      repoFullName: $("gh-repo").value.trim(),
      filePath: $("gh-filepath").value.trim() || "cofre.kdbx",
      autoSync: $("gh-autosync").checked,
    });

    ["gh-token", "gh-repo", "gh-filepath"].forEach((id) => {
      $(id).oninput = () => ($(id).dataset.dirty = "1");
    });

    $("btn-gh-sync-both").onclick = async () => {
      const cfg = getGhFormConfig();
      if (!cfg.token || !cfg.repoFullName) {
        return showToast("Informe o Token PAT do GitHub e o nome do Repositório!", true);
      }
      showToast("⏳ Sincronizando .kdbx com seu GitHub Privado...");
      const res = await chrome.runtime.sendMessage({
        type: "GITHUB_SYNC_NOW",
        mode: "both",
        config: cfg,
      });
      if (res?.ok) {
        $("gh-token").dataset.dirty = "";
        await refreshState();
        showToast(
          res.repoCreated
            ? `🎉 Repo Privado '${res.repoFullName}' criado e sincronizado!`
            : `✅ Sincronizado com '${res.repoFullName}' (${res.entriesCount} senhas)!`
        );
      } else {
        showToast(res?.error || "Falha no Sync GitHub", true);
      }
    };

    $("btn-gh-pull").onclick = async () => {
      const cfg = getGhFormConfig();
      showToast("⬇️ Baixando e mesclando do GitHub...");
      const res = await chrome.runtime.sendMessage({
        type: "GITHUB_SYNC_NOW",
        mode: "pull_only",
        config: cfg,
      });
      if (res?.ok) {
        await refreshState();
        showToast(`✅ Pull concluído (${res.entriesCount} senhas)!`);
      } else {
        showToast(res?.error || "Erro no Pull", true);
      }
    };

    $("btn-gh-push").onclick = async () => {
      const cfg = getGhFormConfig();
      showToast("⬆️ Enviando .kdbx para o GitHub Privado...");
      const res = await chrome.runtime.sendMessage({
        type: "GITHUB_SYNC_NOW",
        mode: "push_only",
        config: cfg,
      });
      if (res?.ok) {
        await refreshState();
        showToast(`✅ Push concluído para ${res.repoFullName}!`);
      } else {
        showToast(res?.error || "Erro no Push", true);
      }
    };

    // Export / Import .KDBX & KeePassXC XML
    $("btn-export-kdbx").onclick = async () => {
      const res = await chrome.runtime.sendMessage({ type: "EXPORT_KDBX" });
      if (!res?.ok || !res.kdbxBase64) return showToast("Erro ao exportar .kdbx", true);
      const bytes = new Uint8Array(KeeCrypto.base64ToBuf(res.kdbxBase64));
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cofre-keevault.kdbx";
      a.click();
      showToast("💾 Arquivo cofre-keevault.kdbx baixado!");
    };

    $("btn-export-xml").onclick = async () => {
      const res = await chrome.runtime.sendMessage({ type: "EXPORT_KDBX" });
      if (!res?.ok || !res.keepassXml) return showToast("Erro ao exportar XML", true);
      const blob = new Blob([res.keepassXml], { type: "application/xml;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "keepassxc-export.xml";
      a.click();
      showToast("📄 XML compatível com KeePassXC Desktop exportado!");
    };

    $("file-import-input").onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      if (file.name.toLowerCase().endsWith(".kdbx")) {
        const buf = await file.arrayBuffer();
        const b64 = KeeCrypto.bufToBase64(buf);
        const res = await chrome.runtime.sendMessage({
          type: "IMPORT_ENTRIES",
          format: "kdbx_binary",
          contentBase64: b64,
        });
        if (res?.ok) {
          await refreshState();
          showToast("📥 Cofre .KDBX importado e mesclado!");
        } else {
          showToast(res?.error || "Erro ao importar .kdbx", true);
        }
      } else {
        const text = await file.text();
        const res = await chrome.runtime.sendMessage({
          type: "IMPORT_ENTRIES",
          format: "xml_or_csv",
          textContent: text,
        });
        if (res?.ok) {
          await refreshState();
          showToast("📥 Senhas importadas do XML/CSV com sucesso!");
        } else {
          showToast(res?.error || "Erro ao importar arquivo", true);
        }
      }
    };
  });
})();
