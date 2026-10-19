/**
 * KeeVault XC - Private GitHub Repository Sync Engine
 * Synchronizes the encrypted .kdbx binary container directly with a Private GitHub Repository via REST API v3.
 */

const GitHubSync = (() => {
  const API_BASE = "https://api.github.com";

  function buildHeaders(token) {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${(token || "").trim()}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    };
  }

  /**
   * Verifies GitHub Token & returns authenticated user login
   */
  async function verifyToken(token) {
    const resp = await fetch(`${API_BASE}/user`, {
      method: "GET",
      headers: buildHeaders(token),
    });
    if (!resp.ok) {
      throw new Error(`Token GitHub inválido (HTTP ${resp.status})`);
    }
    const data = await resp.json();
    return { login: data.login, name: data.name || data.login, avatarUrl: data.avatar_url };
  }

  /**
   * Ensures a Private Repository exists on the user's GitHub account.
   * If it doesn't exist, creates it automatically with private=true!
   */
  async function ensurePrivateRepo(token, repoFullNameOrName) {
    const user = await verifyToken(token);
    let owner = user.login;
    let repo = (repoFullNameOrName || "keevault-privado").trim().replace(/^\/+|\/+$/g, "");
    if (repo.includes("/")) {
      const parts = repo.split("/");
      owner = parts[0];
      repo = parts[1];
    }

    const checkResp = await fetch(`${API_BASE}/repos/${owner}/${repo}`, {
      method: "GET",
      headers: buildHeaders(token),
    });

    if (checkResp.status === 200) {
      const repoInfo = await checkResp.json();
      return {
        owner,
        repo,
        fullName: `${owner}/${repo}`,
        private: repoInfo.private,
        created: false,
        htmlUrl: repoInfo.html_url,
      };
    }

    if (checkResp.status === 404) {
      const createResp = await fetch(`${API_BASE}/user/repos`, {
        method: "POST",
        headers: buildHeaders(token),
        body: JSON.stringify({
          name: repo,
          description: "🔒 Cofre Privado Criptografado KeeVault XC (.kdbx AES-256-GCM)",
          private: true,
          auto_init: true,
        }),
      });
      if (!createResp.ok) {
        const errBody = await createResp.text();
        throw new Error(`Falha ao criar repositório privado (${createResp.status}): ${errBody}`);
      }
      const createdRepo = await createResp.json();
      return {
        owner: createdRepo.owner.login,
        repo: createdRepo.name,
        fullName: createdRepo.full_name,
        private: createdRepo.private,
        created: true,
        htmlUrl: createdRepo.html_url,
      };
    }

    throw new Error(`Erro ao verificar repositório GitHub (HTTP ${checkResp.status})`);
  }

  /**
   * Downloads the encrypted .kdbx file from the Private GitHub Repo
   */
  async function pullEncryptedKdbx({ token, repoFullName, filePath = "cofre.kdbx", branch = "main" }) {
    const cleanPath = (filePath || "cofre.kdbx").replace(/^\/+/, "");
    const url = `${API_BASE}/repos/${repoFullName}/contents/${cleanPath}?ref=${encodeURIComponent(branch)}`;
    const resp = await fetch(url, {
      method: "GET",
      headers: buildHeaders(token),
      cache: "no-store",
    });

    if (resp.status === 404) {
      return { exists: false, sha: null, contentBase64: null };
    }
    if (!resp.ok) {
      throw new Error(`Erro ao baixar ${cleanPath} do GitHub (HTTP ${resp.status})`);
    }

    const data = await resp.json();
    const cleanBase64 = (data.content || "").replace(/\s+/g, "");
    return {
      exists: true,
      sha: data.sha,
      contentBase64: cleanBase64,
      htmlUrl: data.html_url,
      size: data.size,
    };
  }

  /**
   * Uploads/Updates the encrypted .kdbx file in the Private GitHub Repo
   */
  async function pushEncryptedKdbx({
    token,
    repoFullName,
    filePath = "cofre.kdbx",
    branch = "main",
    contentBase64,
    sha = null,
    commitMessage = "",
  }) {
    const cleanPath = (filePath || "cofre.kdbx").replace(/^\/+/, "");
    let currentSha = sha;
    if (!currentSha) {
      const existing = await pullEncryptedKdbx({ token, repoFullName, filePath: cleanPath, branch }).catch(() => null);
      if (existing && existing.exists) {
        currentSha = existing.sha;
      }
    }

    const body = {
      message: commitMessage || `🔐 Sync KeeVault XC (${new Date().toLocaleString("pt-BR")})`,
      content: contentBase64,
      branch,
    };
    if (currentSha) {
      body.sha = currentSha;
    }

    const url = `${API_BASE}/repos/${repoFullName}/contents/${cleanPath}`;
    const resp = await fetch(url, {
      method: "PUT",
      headers: buildHeaders(token),
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const errTxt = await resp.text();
      throw new Error(`Erro no Push para GitHub (${resp.status}): ${errTxt}`);
    }

    const resData = await resp.json();
    return {
      sha: resData.content?.sha || null,
      commitUrl: resData.commit?.html_url || null,
      timestamp: new Date().toISOString(),
    };
  }

  return {
    verifyToken,
    ensurePrivateRepo,
    pullEncryptedKdbx,
    pushEncryptedKdbx,
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.GitHubSync = GitHubSync;
}
