# VYOM phishing assessment flow

```mermaid
flowchart TD
    A["Email comes in<br/>Paste one email, upload .eml / .txt files, or upload a dataset"] --> B["Read the email<br/>Split out subject, body, headers, links and attachments.<br/>Several emails can form a thread."]

    B --> C1["1 Wording · 25% weight<br/>Does the writing read like phishing?"]
    B --> C2["2 Sender and headers · 15% weight<br/>Who really sent it?"]
    B --> C3["3 Throw-away address · 10% weight<br/>Is the sender a disposable email?"]
    B --> C4["4 Attachments · 10% weight<br/>Could a file be dangerous?"]
    B --> C5["5 Links · 20% weight<br/>Do the links look fake?"]
    C5 --> C6["6 Linked websites · 20% weight<br/>Do the pages behind the links look fake?"]
    B --> C7["7 Consistency and threads · adds up to +0.12<br/>Does everything tell the same story?"]
    B --> C8["8 Warning-sign rules · adds up to +0.55<br/>Does it use known phishing tricks?"]

    C1 --> S1
    C2 --> S1
    C3 --> S1
    C4 --> S1
    C5 --> S1
    C6 --> S1
    S1["Step 1 · Weighted average of the checks 1-6 that could run<br/>Wording 25% · Links 20% · Websites 20% · Sender 15% · Throw-away 10% · Attachments 10%<br/>A check that cannot run is left out and the others are rescaled to make 100%"]
    S1 --> S2["Step 2 · Add boosts"]

    C7 -. "up to +0.12" .-> S2
    C8 -. "up to +0.55" .-> S2
    N["Link text hides the real address and the email asks for a password or payment details"] -. "+0.15" .-> S2

    S2 --> S3["Step 3 · Cap at 1.0"]
    S3 --> P["Final score P, 0.00 to 1.00<br/>plus how much evidence was available"]

    P --> Q{"Enough evidence?<br/>Human Review if any one is true"}
    Q -->|"Yes: less than 60% of the check weight ran,<br/>fewer than 4 checks could run,<br/>or consistency could not be judged"| R["Human Review<br/>a person decides"]
    Q -->|No| J{"Score P"}
    J -->|"below 0.30"| K["Safe"]
    J -->|"0.30 to 0.60"| L["Suspicious"]
    J -->|"0.60 or higher"| M["Phishy"]
```

## Check details

| # | Check | Question | What it looks at | Contribution |
|---|-------|----------|------------------|--------------|
| 1 | Wording | Does the writing read like phishing? | Common phishing phrases, word-importance model, rare wording, pressure and "click here" phrases | 25% weight |
| 2 | Sender and headers | Who really sent it? | From vs Reply-To, missing or odd headers, login-check claims, fake display name, look-alike domain | 15% weight |
| 3 | Throw-away address | Is the sender a disposable email? | Known disposable domains (about 150), type of sender, how new the domain is, Reply-To address too | 10% weight |
| 4 | Attachments | Could a file be dangerous? | Risky file types, hidden double extensions like `invoice.pdf.exe`, name vs type mismatch; files are never opened | 10% weight |
| 5 | Links | Do the links look fake? | Odd length or structure, IP addresses, look-alike spelling, redirects, link text hiding the real address | 20% weight |
| 6 | Linked websites | Do the pages behind the links look fake? | Domain and its age, brand imitation and logo, urgent wording, password or payment forms | 20% weight |
| 7 | Consistency and threads | Does everything tell the same story? | Sender, wording, links and page about the same topic; earlier emails in the thread | adds up to +0.12 |
| 8 | Warning-sign rules | Does it use known phishing tricks? | Fake brand domains, mismatched Reply-To, hidden links, disposable sender, pressure language | adds up to +0.55 |

## Combining the scores

1. **Weighted average** of checks 1-6 that could run. A check that cannot run is left out and the remaining weights are rescaled to make 100%.
2. **Add boosts:**
   - Link text hides the real address and the email asks for a password or payment details: +0.15
   - Consistency and thread check: up to +0.12
   - Warning-sign rules: up to +0.55
3. **Cap at 1.0.**

## Verdicts

| Condition | Outcome |
|-----------|---------|
| Less than 60% of the check weight ran, fewer than 4 checks could run, or consistency could not be judged | Human Review |
| P below 0.30 | Safe |
| P 0.30 to below 0.60 | Suspicious |
| P 0.60 or higher | Phishy |

Scores are rough risk signals, not probabilities. Website retrieval fetches bounded static HTML only. Attachments are assessed from metadata and are never opened.
