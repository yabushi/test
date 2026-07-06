# Sourcehunt Report — sh-1f30983e

- **Repo:** target/WebGoat/src/main/java/org/owasp/webgoat/lessons/authbypass/
- **Findings:** 11 (7 verified)
- **Spend by tier:** A=$2.1058, B=$0.0000, C=$0.0000
- **Total spend:** $2.1058

## Band Distribution
- **Fast:** 0 runs, $0.00 (avg $0.00/run)
- **Standard:** 7 runs, $2.11 (avg $0.30/run)
- **Deep:** 0 runs, $0.00 (avg $0.00/run)

## Dedup Summary
- **Total findings:** 7
- **Unique clusters:** 7
- **Duplicates removed:** 0

## Pipeline Health
  ranker: succeeded
  hunter_pool: succeeded

## Severity Histogram
- **critical**: 11

## Findings
### 1. [CRITICAL] Authentication Bypass / Broken Authentication Logic at `AccountVerificationHelper.java:57`

- **CWE:** CWE-287
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The `verifyAccount` method contains a logic flaw that allows complete authentication bypass without knowing any security question answers. The method only checks whether submitted keys are *wrong* — it never enforces that the *correct* keys are *present*. The only hard check is that the submitted map has the same number of entries as the stored question map (line 59). After passing that size check, each individual question guard (lines 63–74) starts with `containsKey("secQuestionX")`: if the attacker omits those keys entirely (submitting arbitrary keys instead), `containsKey` returns false and the guard short-circuits, silently skipping the answer comparison. The method then falls through to `return true` at line 78, granting full verification to the account without any correct answer being validated.

```
public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // Only check: map size must match number of stored questions
    if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
        return false;
    }
    // Guard is skipped entirely when key is absent — never returns false
    if (submittedQuestions.containsKey("secQuestion0")
        && !submittedQuestions.get("secQuestion0")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion0"))) {
        return false;
    }
    if (submittedQuestions.containsKey("secQuestion1")
        && !submittedQuestions.get("secQuestion1")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion1"))) {
        return false;
    }
    return true;   // ← reached with ZERO correct answers
}
```

**Crash evidence:**
```
Compiled and executed TestBypass.java against a faithful replica of the method. Output: "[Case 3] BYPASS (no real answers, arbitrary keys): true" — authentication succeeds with zero correct answers.
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This appears to be WebGoat or a similar intentionally vulnerable training application, which means the vulnerability may be a deliberate teaching exercise rather than an accidental bug. In a production context, the attack surface depends on whether this endpoint is exposed and whether userId/verifyUserId validation is properly handled elsewhere.
- **Mitigations bypassed:** cheat-detection wrapper (didUserLikelylCheat), HTTP parameter filter (parseSecQuestions — circumvented by using 'secQuestion'-prefixed non-canonical keys)
- **Exploit cost:** $0.67
- **Stability:** stable (100% reproduction rate)

### 2. [CRITICAL] Authentication Bypass at `VerifyAccount.java:58`

- **CWE:** CWE-287
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The verifyAccount() method in AccountVerificationHelper.java contains a broken conditional logic flaw that allows complete authentication bypass without knowing any security-question answers. The method checks the submitted map size equals the expected number of questions (2), then uses `containsKey("secQuestion0")` / `containsKey("secQuestion1")` guards before checking the actual answer values. Because those guards are AND-combined with the incorrect-answer check using &&, if the attacker submits two entries that do NOT use the keys "secQuestion0" or "secQuestion1" (e.g., "secQuestion2" and "secQuestion3"), neither guard is true, neither rejection branch fires, and the method falls through to `return true` — granting full account access. The anti-cheat check `didUserLikelylCheat()` is also bypassed because it only sets `likely = true` when the real correct answers are submitted; arbitrary-key submissions make it return false, so the cheat gate passes too.

```
// AccountVerificationHelper.java – verifyAccount()
if (submittedQuestions.containsKey("secQuestion0")          // <-- guard is false when attacker uses "secQuestion2"
    && !submittedQuestions.get("secQuestion0").equals(...))  //     so this whole branch is skipped
  return false;

if (submittedQuestions.containsKey("secQuestion1")          // <-- same: false when attacker uses "secQuestion3"
    && !submittedQuestions.get("secQuestion1").equals(...))
  return false;

return true;  // <-- reached unconditionally with the crafted input
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This is WebGoat, an intentionally vulnerable application used for security training. The 'vulnerability' is by design — it is the lesson itself (CWE-287 auth bypass via broken logic). In a production context this would be critical, but the intended deployment is a local training environment where exploitation is the educational goal, not a threat to real user data.
- **Mitigations bypassed:** Anti-cheat gate (didUserLikelylCheat returns false for bypass payload), Security-question answer verification (containsKey short-circuit skips both rejection branches)
- **Exploit cost:** $0.67

### 3. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:57`

- **CWE:** CWE-287
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The verifyAccount() method performs security-question verification using a flawed conditional pattern: each check is only executed when containsKey() is true for the expected question key. An attacker can submit a request with completely different parameter names (e.g., secQuestion2=x&secQuestion3=y instead of secQuestion0 and secQuestion1). The size check (line 59) passes because the map contains 2 entries — matching the 2 entries in the store — but since secQuestion0 and secQuestion1 are absent, both validation blocks are skipped entirely, and the method returns true unconditionally, granting full authentication without knowing any correct answer.

```
if (submittedQuestions.containsKey("secQuestion0")
    && !submittedQuestions.get("secQuestion0")
        .equals(secQuestionStore.get(verifyUserId).get("secQuestion0"))) {
  return false;   // ← skipped entirely if key is absent
}

if (submittedQuestions.containsKey("secQuestion1")
    && !submittedQuestions.get("secQuestion1")
        .equals(secQuestionStore.get(verifyUserId).get("secQuestion1"))) {
  return false;   // ← skipped entirely if key is absent
}

return true;  // ← reached with no correct answers!
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This is WebGoat, a deliberately vulnerable training application; the comment on line 55 explicitly invites users to find this flaw. In a real production deployment the map would likely be constructed server-side from a validated set of known question keys, making the bypass impossible. However, if the parameter map is populated directly from request parameters (as WebGoat does), the bypass is fully exploitable.
- **Mitigations bypassed:** security_question_authentication, cheat_detection_gate
- **Exploit cost:** $0.75

### 4. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:57`

- **CWE:** CWE-287
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The verifyAccount() method checks that the submitted map has exactly 2 entries (matching the expected security-question count), then uses "if containsKey(X) && wrong → return false" guards for each expected key. If neither expected key (secQuestion0, secQuestion1) is present, both guards are bypassed and the function unconditionally returns true. An attacker submits two arbitrary security-question parameters (e.g., secQuestion2 and secQuestion3 with any values) to satisfy the size check without triggering either guard, gaining full account verification with zero knowledge of the real answers. The anti-cheat check (didUserLikelylCheat) is also evaded because it only flags correct answers to the real questions.

```
// verifyAccount() lines 59-78
if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
  return false;  // size must be 2 — attacker satisfies this with any 2 keys
}
if (submittedQuestions.containsKey("secQuestion0")  // skipped if key absent
    && !submittedQuestions.get("secQuestion0").equals(...)) { return false; }
if (submittedQuestions.containsKey("secQuestion1")  // skipped if key absent
    && !submittedQuestions.get("secQuestion1").equals(...)) { return false; }
return true;  // ← reached with secQuestion2=foo&secQuestion3=bar
```

**Crash evidence:**
```
Java proof-of-concept confirms: Test 3 (arbitrary keys secQuestion2/secQuestion3) → didUserLikelylCheat=false, verifyAccount=true
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This is WebGoat, an intentionally vulnerable training application. The flaw is a deliberately planted lesson, not an accidental vulnerability in production software. Real-world impact is limited to the educational context, and the endpoint likely requires prior authentication or is sandboxed.
- **Mitigations bypassed:** Anti-cheat gate (didUserLikelylCheat returns false for arbitrary keys), Security-question answer validation (both containsKey guards short-circuit)
- **Exploit cost:** $0.72
- **Stability:** stable (100% reproduction rate)

### 5. [CRITICAL] Authentication Bypass via Flawed Security-Question Verification at `AccountVerificationHelper.java:57`

- **CWE:** CWE-287
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes
- **Crypto protocol:** N/A

The `verifyAccount()` method enforces two independent guards: first it checks that the submitted answer map has exactly as many entries as the stored questions (2), then it checks each answer with `containsKey()` before comparing values. Because the key check is used as an *optional gate* ("only reject if the key is present AND the value is wrong"), an attacker can submit any two parameters whose names contain "secQuestion" but are NOT "secQuestion0" or "secQuestion1" (e.g. "secQuestion2" and "secQuestion3"). The size check passes (2 == 2), but `containsKey("secQuestion0")` and `containsKey("secQuestion1")` both return false, so neither rejection branch is entered, and the method falls through to `return true` — granting full authentication without knowing any correct answer. The anti-cheat helper `didUserLikelylCheat()` also returns false for these inputs, so the bypass goes undetected.

```
public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // size check — attacker satisfies this by sending exactly 2 params
    if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
        return false;
    }
    // FLAW: only rejects if "secQuestion0" key IS present; attacker omits it
    if (submittedQuestions.containsKey("secQuestion0")
        && !submittedQuestions.get("secQuestion0")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion0"))) {
        return false;
    }
    // Same flaw for "secQuestion1"
    if (submittedQuestions.containsKey("secQuestion1")
        && !submittedQuestions.get("secQuestion1")
            .equals(secQuestionStore.get(verifyUserId).get("secQuestion1"))) {
        return false;
    }
    return true;  // ← reached without answering anything correctly
}
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This is WebGoat, a deliberately vulnerable training application, so this vulnerability is intentional and expected. In a real production deployment, the surrounding authentication infrastructure would likely prevent this from being a meaningful security issue, though the logic flaw itself is real and exploitable as described.
- **Mitigations bypassed:** Anti-cheat gate (didUserLikelylCheat returns false for bypass payload), Size/count check (exactly 2 entries satisfies entrySet().size() == 2), Q0 rejection guard (containsKey bypass), Q1 rejection guard (containsKey bypass)
- **Exploit cost:** $0.49

### 6. [CRITICAL] authentication_bypass at `AccountVerificationHelper.java:57`

- **CWE:** CWE-290
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The verifyAccount() method in AccountVerificationHelper.java contains a broken security-question authentication logic that allows a complete authentication bypass without knowing any correct answer.

ROOT CAUSE — Absent-key short-circuit:
The method checks each security question only when the submitted map *contains* that key:

    if (submittedQuestions.containsKey("secQuestion0")
        && !submittedQuestions.get("secQuestion0").equals(...)) {
        return false;
    }

If a submitted map contains the *right number of entries* but uses **different key names** (e.g. "secQuestion2" and "secQuestion3" instead of "secQuestion0" and "secQuestion1"), both `containsKey` guards return `false`. Neither rejection branch is ever entered, so the method falls through and returns `true` — granting authentication.

The anti-cheat guard (`didUserLikelylCheat`) detects only *correct* answers for the real keys, so it also returns `false` for the bypass payload, meaning the attacker is not blocked at any point.

PROOF-OF-CONCEPT (HTTP POST to /auth-bypass/verify-account):
    userId=1223445&verifyMethod=SEC_QUESTIONS&secQuestion2=anything&secQuestion3=anything

Submitted map: {"secQuestion2":"anything","secQuestion3":"anything"}
  - Size check:  2 == 2  → passes (not short-circuited)
  - secQuestion0 check: containsKey("secQuestion0") == false → skipped
  - secQuestion1 check: containsKey("secQuestion1") == false → skipped
  - return true  ← authentication granted with no correct answers

IMPACT: An unauthenticated attacker can fully bypass the account-verification step for user ID 1223445 and take over that account session without knowing any security-question answer.

```
// AccountVerificationHelper.java lines 63-75
if (submittedQuestions.containsKey("secQuestion0")       // ← only checks if key present
    && !submittedQuestions.get("secQuestion0")
        .equals(secQuestionStore.get(verifyUserId).get("secQuestion0"))) {
  return false;
}
if (submittedQuestions.containsKey("secQuestion1")       // ← same flaw
    && !submittedQuestions.get("secQuestion1")
        .equals(secQuestionStore.get(verifyUserId).get("secQuestion1"))) {
  return false;
}
return true;   // ← reached when keys are simply absent
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This is WebGoat, a deliberately vulnerable training application — the flaw is intentional (note the comment on line 55: 'Can you find the flaw?'). In a real production deployment this would be critical, but the impact is limited to users of the intentionally vulnerable app.
- **Mitigations bypassed:** Size-count guard (entrySet().size() check), Anti-cheat flag (didUserLikelylCheat() else-branch self-neutralizes)
- **Exploit cost:** $0.50

### 7. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:57`

- **CWE:** CWE-290
- **Evidence:** exploit_demonstrated
- **Discovered by:** hunter:unconstrained
- **Verified:** yes

The verifyAccount() method enforces that exactly N (=2) parameters whose names start with "secQuestion" are submitted, but it only validates the answers when the map *contains* the canonical keys "secQuestion0" and "secQuestion1". Because the size check is done on the submitted map instead of checking that the submitted keys exactly match the expected keys, an attacker can supply two arbitrarily named keys such as "secQuestion2" and "secQuestion99". The size guard passes (2 == 2), but neither if-branch fires because containsKey("secQuestion0") and containsKey("secQuestion1") are both false, so the method falls through and returns true — full authentication bypass without knowing a single correct answer. The anti-cheat check (didUserLikelylCheat) is also bypassed because it returns false when the correct canonical keys are absent.

```
// verifyAccount — size guard passes for arbitrary key names
if (submittedQuestions.entrySet().size() != secQuestionStore.get(verifyUserId).size()) {
    return false;  // size matches, so NOT taken
}
// Both guards use containsKey on canonical names — skipped if attacker uses fake names
if (submittedQuestions.containsKey("secQuestion0") && ...)  { return false; }
if (submittedQuestions.containsKey("secQuestion1") && ...)  { return false; }
return true;  // ← reached with arbitrary keys, no correct answer needed
```

**Crash evidence:**
```
Reproduced with standalone Java test:
  HashMap bypass = {secQuestion2="anything", secQuestion99="foobar"}
  verifyAccount(1223445, bypass) → true   (AUTH BYPASS CONFIRMED)
  didUserLikelylCheat(bypass)   → false   (cheat-detection also bypassed)
```

- **Validation axes:**
  - REAL: PASS (high)
  - TRIGGERABLE: PASS (high)

_Verifier counter-argument:_ This appears to be WebGoat or a similar intentionally vulnerable training application (the comment on line 55 says 'Can you find the flaw?'), so this may be an intentional vulnerability in a non-production security training tool rather than a real production system. The severity in actual deployment risk is thus context-dependent.
- **Mitigations bypassed:** anti-cheat detection (didUserLikelylCheat), security-question size guard, answer validation if-blocks
- **Exploit cost:** $0.59
- **Stability:** stable (100% reproduction rate)

### 8. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:39`

- **CWE:** CWE-290
- **Evidence:** suspicion
- **Discovered by:** variant_loop

Variant of hunter-75cd0946: Security question validation that uses containsKey on canonical key names after only a size check — allowing bypass by submitting arbitrary key names that pass the size guard but skip all answer validation branches

```
    if ((submittedAnswers.containsKey("secQuestion0")
```

### 9. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:43`

- **CWE:** CWE-290
- **Evidence:** suspicion
- **Discovered by:** variant_loop

Variant of hunter-75cd0946: Security question validation that uses containsKey on canonical key names after only a size check — allowing bypass by submitting arbitrary key names that pass the size guard but skip all answer validation branches

```
        && (submittedAnswers.containsKey("secQuestion1")
```

### 10. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:63`

- **CWE:** CWE-290
- **Evidence:** suspicion
- **Discovered by:** variant_loop

Variant of hunter-75cd0946: Security question validation that uses containsKey on canonical key names after only a size check — allowing bypass by submitting arbitrary key names that pass the size guard but skip all answer validation branches

```
    if (submittedQuestions.containsKey("secQuestion0")
```

### 11. [CRITICAL] Authentication Bypass at `AccountVerificationHelper.java:70`

- **CWE:** CWE-290
- **Evidence:** suspicion
- **Discovered by:** variant_loop

Variant of hunter-75cd0946: Security question validation that uses containsKey on canonical key names after only a size check — allowing bypass by submitting arbitrary key names that pass the size guard but skip all answer validation branches

```
    if (submittedQuestions.containsKey("secQuestion1")
```
