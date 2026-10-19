# 🔐 KeeVault XC — Extensão Chrome (.KDBX + GitHub Privado + MCP IA)

Extensão de navegador autônoma inspirada na arquitetura oficial do **KeePassXC** (`src/crypto`, `src/format`, `src/core`, `src/keys`), com sincronização em **Repositório Privado do GitHub** e **Preenchimento Cego (Blind Autofill) via MCP para Agentes de IA**.

---

## 🚀 Como Instalar no Google Chrome / Brave / Edge (Leva 15 segundos)

1. Abra o seu navegador e digite na barra de endereços:
   ```text
   chrome://extensions
   ```
2. No canto superior direito da página, ative a chave **"Modo do desenvolvedor"** (*Developer mode*).
3. No canto superior esquerdo, clique no botão **"Carregar sem compactação"** (*Load unpacked*).
4. Selecione a pasta:
   ```text
   C:\Users\rapha\Documents\KeeVaultXC\extension
   ```
5. Clique no ícone de **Quebra-Cabeça (Extensões)** no topo do Chrome e clique no **Alfinete (Pin)** ao lado do **KeeVault XC** para fixá-lo na barra!

---

## 🎛️ Como Funcionam os 2 Botões `ON / OFF` no Topo

- **`🔓 Permanente (ON / OFF)`**:
  - **Quando `ON`:** Depois que você digitar sua Senha Mestra uma vez, o cofre permanece **destrancado permanentemente** (mesmo se você fechar o popup ou reiniciar o Chrome), até o momento em que você clicar em **`🔒 Trancar`** ou mudar para `OFF`.
- **`🤖 MCP para IA (ON / OFF)`**:
  - **Quando `ON`:** Permite que agentes de IA locais (como o Antigravity) vejam **quais contas existem** (Título, URL e Usuário — **nunca a senha**) e executem o **Blind Autofill** (`keevault_autofill_login`) direto na aba do Chrome.
  - Além disso, cada senha individual tem uma tag **`🤖 IA ON / OFF`** para você escolher exatamente quais contas a IA pode usar para logar!

---

## 🐙 Como Sincronizar com seu GitHub Privado

1. Abra a aba **`🐙 GitHub`** dentro da extensão.
2. Cole seu **Personal Access Token (PAT)** do GitHub (com permissão `repo`).
3. Digite o nome do repositório desejado (ex: `meu-cofre-senhas`).
   - *Se o repositório ainda não existir na sua conta do GitHub, a própria extensão cria ele automaticamente como **Privado**!*
4. Clique em **`🚀 Salvar & Sincronizar Agora (Merge + Push)`**.
   - A partir daí, toda nova senha que você salvar no Chrome já é criptografada em formato `.kdbx` (`AES-256-GCM`) e enviada automaticamente para o seu GitHub Privado!
