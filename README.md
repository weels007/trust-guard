# TrustGuard — On-Chain Trust Scoring with LLM Consensus

> **Build reputation through proven behavior, judged by validators.**
> TrustGuard is a reputation system where users build trust through
> evidence, and validators independently judge trustworthiness under
> LLM consensus — producing Reliable, Neutral, or Distrusted verdicts
> settled on-chain only after validator agreement.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-18%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. User registers identity by signing a message with their wallet (EIP-191).
2. User submits evidence URLs (proof of positive interactions), each signed.
3. Anyone triggers evaluation for a registered user.
4. Under consensus, validators independently:
   a. Fetch evidence URLs (with SSRF blocklist).
   b. Generate trust criteria (Python expressions, AST sandbox).
   c. Evaluate criteria against evidence content.
   d. Judge overall trustworthiness.
5. If validators agree, trust score is stored on-chain.
6. Users can dispute a trust score with new evidence.
7. Trust scores can be consumed by other contracts for access control.

---

## Consensus design

TrustGuard uses `run_nondet_unsafe` with the Equivalence Principle:
- **Leader**: fetches evidence, generates criteria via LLM, evaluates criteria in AST sandbox, judges trust.
- **Validator**: independently re-runs the same pipeline and compares `(verdict, score)` decision fields.
- Consensus requires agreement on both fields. Mismatches trigger rotation.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[TRANSIENT]` for network errors (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).

## Security & audit

- **Signature verification**: all state-changing actions require EIP-191 signatures verified on-chain via pure-Python secp256k1 ecrecover.
- **SSRF blocklist**: blocks localhost, private networks, cloud metadata endpoints.
- **AST sandbox**: criteria expressions run in restricted AST sandbox (only `text` variable, `len` function, safe string methods).
- **Anti-replay**: disputes require unique evidence URL per signature.
- **Access control**: only registered user can dispute their own profile.

## Reusable patterns

TrustGuard establishes patterns that can be reused in other contracts:

- **EIP-191 signature verification**: `_signer_of()` + `_ecrecover()` — pure-Python secp256k1 ecrecover. Drop-in pattern for any contract requiring wallet authentication.
- **AST sandbox**: `_safe_eval()` — restricted expression evaluation with allowlisted nodes only. Reuse for any user-supplied formula/rule.
- **SSRF blocklist**: `_validate_url()` — blocks localhost, private networks, cloud metadata. Reuse for any URL-fetching logic.
- **Consensus via `run_nondet_unsafe`**: Leader + Validator with `(verdict, score)` decision field comparison. Reuse for any subjective judgment task.
- **Profile + counter storage**: `Map[str, T]` + `TreeMap[str, u256]` pattern for entity-state with per-entity counters.

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/trust_guard.py
```

18 GenVM direct-mode tests pass. Lint passes. Validate fails due to known SDK bug (missing runner tar). Deployed to studionet.

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xBCdF5F6448C7DF90660Ea47447F26A0096D2d8E2`  
**Chain:** Studionet (Genlayer Studio Network)  
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`  
**Tx:** `0xa93422bd00d08cf1be5a1edd32dfc1b33c5719164237aca9c3e97139031a1f71`  
**Status:** Deployed and E2E tested on studionet (register, submit_evidence, evaluate consensus, views). Duplicate registration correctly reverted. Steward fixes: evaluate stores profile address in trust_address (not evaluator), dispute enforces MAX_EVIDENCE_PER_USER limit.

---

## Extension ideas

- Cross-contract trust score integration (e.g., access control for other contracts)
- Time-decay for trust scores
- Reputation tiers with different permissions
