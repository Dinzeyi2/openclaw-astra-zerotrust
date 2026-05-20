# openclaw-astra-zerotrust

# Astra Zero Trust — OpenClaw Plugin

Zero Trust AI data protection for OpenClaw. Every message tokenized before it reaches the LLM. Real names, SSNs, card numbers, patient records, trade positions — none of it ever touches OpenAI or Anthropic. The AI works. The data stays protected.

Install it once. Never think about it again.

```bash
openclaw plugins install clawhub:astra-zerotrust
```

---

## Why this exists

When you use OpenClaw with OpenAI or Anthropic, your messages go directly to their servers. A nurse types a patient name. A trader types a client position. A lawyer types a case reference. All of it sits on someone else's infrastructure.

Most of the time that is fine. When it is not — HIPAA, GLBA, FINRA, GDPR, attorney-client privilege — there has been no good answer. Redaction kills the agent. Encryption does not help when the server decrypts to process anyway.

Astra tokenizes the sensitive parts before the request leaves your machine. The LLM receives `[CVT:NAME:A1B2]` instead of "John Smith." It still reasons. It still acts. The real value never moves.

---

## What the LLM actually sees

```
You type:   "Follow up with Sarah Chen at Goldman, position $4.2M"

LLM sees:   "Follow up with [CVT:NAME:A1B2] at [CVT:ORG:C3D4], position [CVT:AMT:E5F6]"

Agent acts: Email sent to real address (executor resolves at action time)

After:      Real values wiped. Cryptographic proof generated. Nothing stored.
```

The agent did exactly what it would have done. The LLM just never knew what the real values were.

---

## Install

```bash
openclaw plugins install clawhub:astra-zerotrust
```

Add your API key to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "astra-zerotrust": {
        "enabled": true,
        "config": {
          "apiKey": "sk-guard-YOUR_KEY"
        }
      }
    }
  }
}
```

Restart OpenClaw:

```bash
openclaw restart
```

Every message from this point is protected automatically.

---

## Get your API key

Sign up at **app.codeastra.dev**

Free tier: 1,000 protected values per month. No credit card required.

```
Free:       1,000 values/month
Starter:    $49/month — 50,000 values
Pro:        $199/month — unlimited
Enterprise: Contact us — on-premise, BAA, custom pricing
```

---

## What it protects

Detected and tokenized automatically:

- Full names and initials
- Social Security Numbers (SSN / TIN / EIN)
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- Bank account and routing numbers
- Email addresses
- Phone numbers (US and international)
- Medical Record Numbers (MRN)
- Dates of birth
- IP addresses
- Passport and driver's license numbers
- Financial amounts (configurable threshold)
- Custom patterns you define yourself

---

## Custom sensitive data — sensitivity recipes

Standard PII detection is not enough for every industry. A Goldman Sachs analyst has internal strategy codes. A hospital has trial cohort IDs. A law firm has matter references.

You define your own patterns at app.codeastra.dev. The plugin loads them automatically and applies them to every message alongside standard PII detection.

```
Goldman example:   GSAM-[0-9]{4} → tokenized
Hospital example:  TRIAL-COHORT-[A-Z] → tokenized
Law firm example:  MATTER-2024-[0-9]{4} → tokenized
```

No code changes. No plugin updates. Define the pattern, the plugin picks it up within 5 minutes.

---

## Security model

**Injection sanitization**
Every tool result (web scrapes, CRM queries, email reads) is scanned for prompt injection patterns before the LLM reads it. 18 patterns stripped automatically. A malicious web page cannot hijack your agent.

**K-anonymity**
If a tool returns results that could identify a single person — zip code 30314, age 67, diagnosis diabetes — the result is suppressed. Combination re-identification attacks blocked.

**Differential privacy**
Every aggregate query has calibrated mathematical noise applied. An attacker who queries "is this amount above $4M?" repeatedly cannot reconstruct the exact value through binary search.

**Fail-closed**
If Astra is unreachable for any reason, the message is blocked. Not passed through unprotected. Blocked. You can set `failClosed: false` if you prefer a warning instead of a block — but for healthcare and finance, fail-closed is the correct setting.

**Vault wipe on session end**
When you type `/new` to start a fresh session, every real value from the previous session is permanently deleted from the vault. A cryptographic wipe ID is generated and logged. Nothing persists between sessions.

---

## ThinkingTokens — for aggregate queries

Sometimes you need to query across sensitive data without touching individual records. "How many patients in cohort A match these criteria." "Which clients are above $4M."

ThinkingTokens are tokens with facts attached. The AI reasons on the facts — age bracket, diagnosis code, amount range — without ever seeing the real values. Differential privacy is applied to every query result automatically.

Use `api.astra.mintThinkingToken()` and `api.astra.queryThinkingTokens()` inside any OpenClaw skill.

---

## On-premise deployment

If your data cannot leave your network — HIPAA air-gapped environments, government classification, defense contractors — point the plugin at your local Astra instance instead of the cloud.

```json
"config": {
  "apiKey":   "sk-guard-YOUR_KEY",
  "astraUrl": "http://localhost:4000"
}
```

Your on-premise Astra runs four Docker containers on your own server: the Codeastra API, a local Ollama LLM, PostgreSQL for the vault, and Redis. The LLM makes no external API calls. Patient data never leaves the building.

Get the deployment package at app.codeastra.dev/onprem or via the API:

```bash
curl -X POST https://app.codeastra.dev/onprem/generate/codeastra \
  -H "X-API-Key: sk-guard-YOUR_KEY" \
  -d '{"industry": "healthcare", "air_gapped": true}'
```

You receive a `docker-compose.yml`, `.env`, and `setup.sh`. Run `./setup.sh` on your server. Done in under 15 minutes.

---

## Healthcare — HIPAA

Astra tokenizes all 18 PHI identifiers defined by HIPAA before they reach any AI model. Names, dates, geographic data, phone numbers, fax numbers, email, SSN, MRN, health plan numbers, account numbers, certificate numbers, VIN, device identifiers, URLs, IP addresses, biometric identifiers, photos, and any other unique identifying number.

For healthcare deployments: request a Business Associate Agreement (BAA) at app.codeastra.dev. We countersign within three business days. The BAA explicitly covers on-premise deployments — it documents that PHI is processed on your infrastructure, not ours.

On-premise plus BAA satisfies the HIPAA technical safeguard requirements. No SOC 2 needed for on-premise deployments because your data never touches our servers.

---

## Finance — GLBA, FINRA, DORA, SEC

Client names, account numbers, trade positions, deal sizes, and strategy codes are tokenized before any AI model processes them. The audit log records every protection event in tamper-proof format with a hash chain.

One-click compliance report covers GLBA, SOX, SEC 17a-4, FINRA, and DORA. Export it as a PDF and hand it to your compliance team or regulator.

---

## The autonomous executor

When your OpenClaw agent needs to take a real action — send an email, update a Salesforce record, make an API call — it plans the action using tokens. The executor resolves real values from the vault, fires the action, and wipes the real values immediately after.

The agent never sees the real values at any point. Not during planning. Not during execution. It receives only a confirmation that the action completed.

Use `api.astra.executeWithAstra()` inside any OpenClaw skill.

---

## What the plugin does automatically

You install it once. After that:

- Every message tokenized before LLM call
- Custom sensitivity recipes applied on every message
- Every tool result scanned for injection patterns
- Every LLM response scanned for data leakage
- Vault wiped when you start a new session
- Cryptographic proof generated on every wipe
- Protection stats logged to your Astra dashboard

Nothing to configure per-agent. Nothing to enable per-session. It runs on every turn automatically.


---

## How your data stays protected — every single time

Here is what actually happens to a message from the moment you type it to the moment the agent acts.

**01 — You type a message**

"Follow up with Sarah Chen at Goldman, account $4.2M"

That message never travels anywhere yet. It sits in your OpenClaw session.

**02 — Astra intercepts it — on your machine**

Before the message leaves, Astra scans it. Every name, number, email, account reference, and custom pattern you have defined in your sensitivity recipes — all of it gets pulled out and replaced with a token. The real values go into an encrypted vault. The vault sits on your server (on-premise) or in Astra's infrastructure for milliseconds (cloud).

**03 — The LLM receives tokens only**

What reaches OpenAI, Anthropic, or your local Ollama:

```
"Follow up with [CVT:NAME:A1B2] at [CVT:ORG:C3D4], account [CVT:AMT:E5F6]"
```

The LLM has never seen Sarah Chen's name. It has never seen the dollar amount. It reasons on abstractions. It can still do its job — the tokens preserve the structure of the original message.

**04 — The agent plans using tokens**

Everything the agent thinks, decides, and plans happens in token space. It drafts an email to [CVT:NAME:A1B2]. It references [CVT:AMT:E5F6] in the body. It knows a person exists and an amount exists. It does not know who or how much.

**05 — The trusted executor resolves**

When the agent is ready to act, the executor — a separate trusted layer — takes the plan, looks up each token in the vault, gets the real values, and fires the action. This is the only moment real values are in memory. The LLM is not involved in this step at all.

**06 — The action fires**

The email goes to Sarah Chen's real address. The CRM record updates with the real amount. The API call uses the real account number. Everything works exactly as it would without Astra.

**07 — Instant wipe**

The moment the action confirms, every real value is overwritten in the vault. Not after 24 hours. Not at session end. Immediately. A wipe ID and timestamp are written to a tamper-proof audit log with a cryptographic hash. You can request proof of any wipe at any time.

**08 — What survives**

Token IDs. Timestamps. Wipe proofs. No names. No amounts. No account numbers. If someone breached the database after this point, they would find wiped records and hash chain entries. There is nothing to steal.

---

## Why it cannot leak

**The LLM never had it.** You cannot extract from a model what was never in the model's context. The LLM saw `[CVT:NAME:A1B2]`. It could tell you a token ID exists. It cannot tell you what Sarah Chen's name is because it never knew.

**The vault wipes immediately.** The window between "real value enters vault" and "real value is wiped" is under one second per execution. An attacker would need to dump the database during that exact millisecond during an active execution. The real value does not sit around.

**Fail-closed.** If Astra cannot protect the message — network error, service down, any failure — the request is blocked. The unprotected message never reaches the LLM. The system fails safe.

**On-premise removes us entirely.** When you deploy on-premise, Astra runs on your server. The vault is your PostgreSQL. The LLM is your local Ollama. We ship software. We have no access to your infrastructure, your vault, or your data at any point.

---

## Configuration options

```json
{
  "apiKey":     "sk-guard-YOUR_KEY",
  "astraUrl":   "https://app.codeastra.dev",
  "failClosed":  true,
  "scanOutput":  true,
  "trackStats":  true,
  "logLevel":   "info"
}
```

| Option | Default | What it does |
|---|---|---|
| apiKey | required | Your Codeastra API key |
| astraUrl | app.codeastra.dev | Astra endpoint. Change for on-premise |
| failClosed | true | Block if Astra unreachable. Set false to warn instead |
| scanOutput | true | Scan LLM responses for leaked data |
| trackStats | true | Log protection counts per session |
| logLevel | info | silent, info, or debug |

---

## Works with every OpenClaw channel

Slack. WhatsApp. Telegram. Discord. Signal. iMessage. Teams. Every channel OpenClaw supports. The plugin sits at the message pipeline level — channel-agnostic. A message that comes in from WhatsApp gets the same tokenization as one typed in the terminal.

---

## Builds on

- **Codeastra** — AI privacy infrastructure. app.codeastra.dev
- **OpenClaw** — open-source autonomous AI agent. github.com/openclaw/openclaw
- **MIT licensed** — fork it, modify it, use it commercially

---

## Links

- Get your API key: app.codeastra.dev
- On-premise setup: app.codeastra.dev/onprem
- BAA for healthcare: app.codeastra.dev/legal/baa/generate
- Compliance report: app.codeastra.dev/compliance/report
- Codeastra docs: app.codeastra.dev/docs
- OpenClaw docs: docs.openclaw.ai
- Issues: github.com/YOUR_USERNAME/openclaw-astra-zerotrust/issues
- Email: hello@codeastra.dev

---

*Codeastra — Agentic Capability with Zero Trust Infrastructure. The AI can act on the secret, without learning the secret.*
