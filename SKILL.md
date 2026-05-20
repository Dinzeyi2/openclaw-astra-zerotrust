---
name: astra-zerotrust
version: 1.0.0
author: Codeastra
description: Zero Trust AI data protection. Tokenizes sensitive data before it reaches the LLM. Real patient names, SSNs, card numbers, client data — never seen by any AI model. Use when handling sensitive data.
metadata:
  openclaw:
    plugin: true
    hooks:
      - onMessageReceived
      - onResponseGenerated
      - onToolCallCompleted
      - onSessionEnded
    config_required:
      - name: apiKey
        description: Your Codeastra API key from app.codeastra.dev
        env: ASTRA_API_KEY
    config_optional:
      - name: failClosed
        description: Block request if Astra fails. Default true. Recommended for healthcare/finance.
        default: true
      - name: astraUrl
        description: Astra backend URL. Default https://app.codeastra.dev
        default: https://app.codeastra.dev
---

# Astra Zero Trust Protection

Astra sits between your messages and the LLM.
Every message is tokenized before the AI sees it.
Real data goes into an encrypted vault.
The AI reasons on tokens — never real values.
Vault wiped at end of every session.

## What Astra protects automatically

- Names (patients, clients, employees)
- SSNs and national ID numbers
- Credit card and bank account numbers
- Email addresses and phone numbers
- Medical record numbers and diagnoses
- Trading positions and financial amounts
- Any data matching your custom sensitivity recipes

## How it works

```
Your message → Astra intercepts → tokenizes PII → 
LLM sees [CVT:NAME:A1B2] not "John Smith" → 
LLM responds → Astra scans response → 
Session ends → vault wiped → nothing stored
```

## Security guarantees

- real_data_seen_by_llm: false — always
- failClosed: true — if Astra fails, request blocked
- Instant wipe at session end — cryptographic proof
- Tamper-proof audit log — every protection event logged

## Setup

1. Get your API key at app.codeastra.dev
2. Add to openclaw.json:

```json
{
  "plugins": {
    "astra-zerotrust": {
      "apiKey": "sk-guard-YOUR_KEY",
      "failClosed": true
    }
  }
}
```

Or set environment variable:
```
ASTRA_API_KEY=sk-guard-YOUR_KEY
```

## For healthcare (HIPAA)

Set failClosed: true (default).
Every message blocked if Astra is unreachable.
No PHI ever reaches OpenAI or Anthropic.
BAA available at app.codeastra.dev/legal/baa/generate

## For finance (GLBA, FINRA, DORA)

Client names, deal sizes, trade positions — all tokenized.
Audit trail exported as compliance PDF.
On-premise deployment available — data never leaves your network.

## Rules

- This plugin runs automatically on every message
- The user does not need to invoke it
- It is invisible — the agent behaves exactly the same
- The only difference: the LLM never sees real data
