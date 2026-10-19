/**
 * KeeVault XC - Content Script
 * Injects inline autofill menu on login/password fields, captures new credentials to save to Vault + GitHub,
 * and executes Zero-Knowledge Blind Autofill triggered by the User or by AI Agents via MCP.
 */

(() => {
  let activeMenuEl = null;
  let lastFocusedInput = null;

  function setReactCompatibleValue(inputEl, value) {
    if (!inputEl) return;
    inputEl.focus();
    const proto =
      inputEl instanceof HTMLTextAreaElement
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
    const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (nativeSetter) {
      nativeSetter.call(inputEl, value);
    } else {
      inputEl.value = value;
    }
    inputEl.dispatchEvent(new Event("input", { bubbles: true }));
    inputEl.dispatchEvent(new Event("change", { bubbles: true }));
    inputEl.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  }

  function findFormInputs(anchorEl = null) {
    const scope = anchorEl?.closest("form") || document;
    const passInputs = Array.from(scope.querySelectorAll('input[type="password"]:not([disabled])')).filter(
      (el) => el.offsetParent !== null
    );

    const allCandidateUsers = Array.from(
      scope.querySelectorAll(
        'input[type="email"], input[type="text"], input[type="tel"], input:not([type])'
      )
    ).filter(
      (el) =>
        el.offsetParent !== null &&
        !el.disabled &&
        !el.readOnly &&
        !/search|query|coupon|promo|otp|totp|code|2fa/i.test(
          `${el.name} ${el.id} ${el.placeholder} ${el.autocomplete}`
        )
    );

    const totpInputs = Array.from(
      document.querySelectorAll(
        'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[name*="2fa" i], input[name*="code" i], input[id*="otp" i], input[id*="totp" i]'
      )
    ).filter((el) => el.offsetParent !== null && !el.disabled);

    let userInput = null;
    if (passInputs.length > 0) {
      const pRect = passInputs[0].getBoundingClientRect();
      const above = allCandidateUsers.filter((u) => u.getBoundingClientRect().top <= pRect.top + 10);
      userInput = above.length ? above[above.length - 1] : allCandidateUsers[0] || null;
    } else {
      userInput = allCandidateUsers[0] || null;
    }

    return {
      userInput,
      passInput: passInputs[0] || null,
      totpInput: totpInputs[0] || null,
      form: passInputs[0]?.closest("form") || userInput?.closest("form") || null,
    };
  }

  function removeInlineMenu() {
    if (activeMenuEl) {
      activeMenuEl.remove();
      activeMenuEl = null;
    }
  }

  async function showInlineMenuForInput(inputEl) {
    removeInlineMenu();
    lastFocusedInput = inputEl;

    let res;
    try {
      res = await chrome.runtime.sendMessage({
        type: "CONTENT_QUERY_DOMAIN_LOGINS",
        url: window.location.href,
      });
    } catch (e) {
      return;
    }
    if (!res || !res.ok) return;

    const rect = inputEl.getBoundingClientRect();
    const menu = document.createElement("div");
    menu.className = "kvxc-inline-menu";
    menu.style.top = `${window.scrollY + rect.bottom + 6}px`;
    menu.style.left = `${Math.max(8, window.scrollX + rect.left)}px`;

    const hdr = document.createElement("div");
    hdr.className = "kvxc-inline-header";
    hdr.innerHTML = `<span>🔐 KEEVAULT XC • AUTOFILL</span><span style="cursor:pointer;color:#94a3b8" id="kvxc-close-btn">✕</span>`;
    menu.appendChild(hdr);

    if (!res.unlocked) {
      const lockedRow = document.createElement("div");
      lockedRow.className = "kvxc-inline-item";
      lockedRow.innerHTML = `
        <div>
          <div class="kvxc-inline-title">🔒 Cofre Trancado</div>
          <div class="kvxc-inline-sub">Clique no ícone da extensão para destrancar</div>
        </div>
      `;
      menu.appendChild(lockedRow);
    } else {
      if (Array.isArray(res.entries) && res.entries.length > 0) {
        for (const entry of res.entries.slice(0, 4)) {
          const item = document.createElement("div");
          item.className = "kvxc-inline-item";
          item.innerHTML = `
            <div>
              <div class="kvxc-inline-title">${escapeHtml(entry.title)}</div>
              <div class="kvxc-inline-sub">${escapeHtml(entry.username || "Sem usuário")}</div>
            </div>
            <span class="kvxc-inline-badge">${entry.hasTotp ? "2FA + Login" : "Preencher"}</span>
          `;
          item.addEventListener("mousedown", (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            chrome.runtime.sendMessage({
              type: "CONTENT_REQUEST_FILL_ENTRY",
              entryId: entry.id,
            });
            removeInlineMenu();
          });
          menu.appendChild(item);
        }
      }

      // Quick Strong Password Generator row
      const genRow = document.createElement("div");
      genRow.className = "kvxc-inline-item";
      genRow.innerHTML = `
        <div>
          <div class="kvxc-inline-title">🎲 Gerar Senha Militar (20 chars)</div>
          <div class="kvxc-inline-sub">Preenche e copia automaticamente</div>
        </div>
        <span class="kvxc-inline-badge" style="background:rgba(99,102,241,0.2);color:#a5b4fc">Gerar</span>
      `;
      genRow.addEventListener("mousedown", async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        const gen = await chrome.runtime.sendMessage({
          type: "CONTENT_GENERATE_PASSWORD",
          options: { length: 20 },
        });
        if (gen && gen.password) {
          setReactCompatibleValue(inputEl, gen.password);
          navigator.clipboard?.writeText(gen.password).catch(() => {});
        }
        removeInlineMenu();
      });
      menu.appendChild(genRow);
    }

    document.body.appendChild(menu);
    activeMenuEl = menu;

    const closeBtn = menu.querySelector("#kvxc-close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("mousedown", (e) => {
        e.preventDefault();
        removeInlineMenu();
      });
    }
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Show inline menu when focusing a password input (or username input inside a login form)
  document.addEventListener(
    "focusin",
    (e) => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement)) return;
      if (el.type === "password") {
        showInlineMenuForInput(el);
      } else if (
        (el.type === "email" || el.type === "text") &&
        el.closest("form")?.querySelector('input[type="password"]')
      ) {
        showInlineMenuForInput(el);
      }
    },
    true
  );

  document.addEventListener("mousedown", (e) => {
    if (activeMenuEl && !activeMenuEl.contains(e.target) && e.target !== lastFocusedInput) {
      removeInlineMenu();
    }
  });

  // Listen for form submission to offer saving new/updated credentials into KeeVault XC + GitHub
  document.addEventListener(
    "submit",
    (e) => {
      const { userInput, passInput } = findFormInputs(e.target);
      if (!passInput || !passInput.value) return;
      const username = userInput ? userInput.value.trim() : "";
      const password = passInput.value;
      showSaveCredentialToast({
        url: window.location.origin,
        title: document.title ? document.title.split(/[-|•]/)[0].trim() : window.location.hostname,
        username,
        password,
      });
    },
    true
  );

  function showSaveCredentialToast(payload) {
    const existingToast = document.querySelector(".kvxc-save-toast");
    if (existingToast) existingToast.remove();

    const toast = document.createElement("div");
    toast.className = "kvxc-save-toast";
    toast.innerHTML = `
      <div class="kvxc-save-toast-title">🔐 Salvar no KeeVault XC + GitHub?</div>
      <div class="kvxc-save-toast-sub">
        <strong>${escapeHtml(payload.title)}</strong><br/>
        Usuário: ${escapeHtml(payload.username || "(Apenas senha)")}
      </div>
      <div class="kvxc-save-toast-actions">
        <button class="kvxc-btn-primary" id="kvxc-toast-save">💾 Salvar & Sync</button>
        <button class="kvxc-btn-secondary" id="kvxc-toast-dismiss">Agora não</button>
      </div>
    `;
    document.body.appendChild(toast);

    toast.querySelector("#kvxc-toast-save").addEventListener("click", async () => {
      await chrome.runtime.sendMessage({
        type: "CONTENT_OFFER_SAVE_LOGIN",
        payload,
      });
      toast.remove();
    });
    toast.querySelector("#kvxc-toast-dismiss").addEventListener("click", () => {
      toast.remove();
    });
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 12000);
  }

  // Listen for Autofill commands from Background (User click OR AI MCP Blind Autofill)
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "KEEVAULT_FILL_CREDENTIALS") {
      const { username, password, totpCode, autoSubmit } = msg.payload || {};
      const { userInput, passInput, totpInput, form } = findFormInputs(lastFocusedInput);

      if (userInput && username) {
        setReactCompatibleValue(userInput, username);
      }
      if (passInput && password) {
        setReactCompatibleValue(passInput, password);
      }
      if (totpInput && totpCode) {
        setReactCompatibleValue(totpInput, totpCode);
      } else if (totpCode) {
        navigator.clipboard?.writeText(totpCode).catch(() => {});
      }

      removeInlineMenu();

      if (autoSubmit && form) {
        setTimeout(() => {
          const submitBtn = form.querySelector(
            'button[type="submit"], input[type="submit"], button:not([type="button"])'
          );
          if (submitBtn) submitBtn.click();
          else form.requestSubmit ? form.requestSubmit() : form.submit();
        }, 250);
      }

      sendResponse({
        ok: true,
        userFilled: Boolean(userInput && username),
        passFilled: Boolean(passInput && password),
        totpFilled: Boolean(totpInput && totpCode),
      });
      return true;
    }

    if (msg.type === "KEEVAULT_INSERT_GENERATED_PASSWORD") {
      const target =
        lastFocusedInput ||
        document.activeElement ||
        document.querySelector('input[type="password"]');
      if (target instanceof HTMLInputElement) {
        setReactCompatibleValue(target, msg.password);
      }
      navigator.clipboard?.writeText(msg.password).catch(() => {});
      sendResponse({ ok: true });
      return true;
    }
  });
})();
