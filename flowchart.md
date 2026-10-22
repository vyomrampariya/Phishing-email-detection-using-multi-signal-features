# VYOM phishing assessment flow

```mermaid
flowchart TD
    A[1 Input: single email or email dataset file] --> B[Parse MIME and headers]
    B --> C[2 Text processing and Word Pool · 0.25]
    B --> D[3 Sender and header · 0.15]
    B --> E[4 Temporary email From + Reply-To · 0.10]
    B --> F[5 URL extraction and analysis · 0.20]
    F --> G[6 Website intelligence · 0.20 · page retrieval and RDAP opt-in]
    B --> H[Attachment metadata · 0.10]
    B --> X[7 Additional features: evidence consistency and thread / cross-email]
    C --> I[8 Adaptive weighted fusion]
    D --> I
    E --> I
    F --> I
    G --> I
    H --> I
    X -. bounded boost up to +0.12 .-> I
    N[Anchor mismatch plus credential request] -. bounded +0.15 .-> I
    O[Missing phases excluded; remaining weights renormalize] -.-> I
    I --> Q{At least 0.30 evidence coverage?}
    Q -->|No| R[Human Review]
    Q -->|Yes| J{Score P}
    J -->|0.00 to below 0.30| K[Safe]
    J -->|0.30 to below 0.60| L[Suspicious]
    J -->|0.60 to 1.00| M[Phishy]
```

Scores are heuristic risk signals, not calibrated probabilities. Website retrieval fetches bounded static HTML only. Attachments are assessed from metadata and are never opened.
