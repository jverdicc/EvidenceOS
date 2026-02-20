# EvidenceOS Architecture Diagrams

## Inside the EvidenceOS Vault & Oracle System: Mechanisms & Maths

```mermaid
flowchart LR
    AM[Admissible Model<br/>Wasm/HIR] --> ASPEC
    SDS[Secure Data Stream<br/>Merkle Proofs] --> SG

    subgraph SV[2. The Sealed Vault (Trusted Execution Environment)]
      subgraph DE[Deterministic Execution Engine (Sandbox)]
        ASPEC[ASPEC Linter<br/>Code Scanning]
        PLN[Path-Length Normalization (PLN)<br/>Cycle Padding]
        DLC[Deterministic Logical Clock (DLC)<br/>Logical Time]
        ASPEC --> PLN --> DLC
      end

      subgraph OS[Oracle System]
        IJ[Internal Judge Model<br/>LLM-as-a-Judge]
        AO[Accuracy Oracle<br/>Compare Prediction vs. Private Label]
        SO[Safety/Compliance Oracle<br/>Constraint Check]
        CO[Canary Oracle<br/>Drift Detection]
        IJ --> AO
        IJ --> SO
        IJ --> CO
      end

      SG[Secure Gateway<br/>Merkle Proofs]
      SL[Settlement & Feedback Logic]
      PLN --> IJ
      AO --> SL
      SO --> SL
      CO --> SL
      SG --> IJ
      SG --> CO
    end

    SL --> HF[Output Hysteresis & Quantization<br/>Distortion Filter]
    SL --> JIB[Joint Information Budget<br/>Ledger & Tax]
    HF --> CC[Claim Capsule<br/>Quantized Result & Proof]
    JIB --> CC
```

## EvidenceOS Workflow: From Hypothesis to Certified Claim (UVP Concept)

```mermaid
flowchart LR
    subgraph M[1. The Modeler (You)]
      H[Hypothesis & Code]
      PD[Public Data<br/>Training]
      AC[Admissibility Check<br/>ASPEC Linter]
      H --> AC
      PD --> AC
    end

    AC --> DV

    subgraph V[2. The Sealed Vault (Trusted Enclave)]
      DV[Deterministic Execution Sandbox]
      PT[Private Data & Truth<br/>Ticks, Labels]
      SG2[Secure Gateway<br/>Merkle Proofs]
      DLC2[Deterministic Logical Clock (DLC)]
      IB[Information Budget<br/>Joint Entropy Tax]

      subgraph LP[Pass/Private Lanes]
        MODEL[Model<br/>Hypothesis]
        ORACLE[Oracle<br/>Judge]
        SETTLE[Settlement & Ledger]
        MODEL --> SETTLE
        ORACLE --> SETTLE
      end

      DV --> SG2
      PT --> SG2
      SG2 --> MODEL
      SG2 --> ORACLE
      DLC2 --> SETTLE
      IB --> SETTLE
    end

    SETTLE --> OF[Oracle Feedback<br/>Hysteresis Filter / Quantization]
    OF --> CAPSULE[Claim Capsule<br/>Certified Merkle Proof + Score + Metadata]

    subgraph B[3. ETL / Transparency Log (Public Ledger)]
      PRE[Pre-Commitment<br/>Hashes only: Model, Data]
      CHAIN[Certified Claim<br/>32-byte hash]
      PRE --> CHAIN
    end

    CAPSULE --> CHAIN
```
