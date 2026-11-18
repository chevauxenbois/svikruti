# Recall benchmark

Static privacy scanners usually publish what they find. This measures what
Svikruti **misses**: known leaks are planted in small files written in common
idioms of each language, and the scanner must report each one. Traps (code
that looks risky but is not) must stay quiet.

```bash
python benchmarks/recall/run.py                                        # tuning set
python benchmarks/recall/run.py --cases benchmarks/recall/holdout.yaml  # held-out set
python benchmarks/recall/run.py --into ../saleor                        # planted inside a real repository
```

## Method

1. `cases.yaml` (43 cases, 56 checks across Python, TypeScript/JavaScript, Go,
   Java, Ruby, PHP and C#) was written first, then run against Svikruti
   0.9.1 unchanged. That is the **baseline**.
2. The misses were fixed, using `cases.yaml` to check the fixes. Its later
   scores are therefore tuned and are not an estimate of real-world recall.
3. `holdout.yaml` (23 cases, 25 checks, different idioms and vendors) was
   then written and run **once, before any further change**. That first run
   is the honest number.
4. The held-out misses were fixed too, and both sets were planted inside
   three real repositories (healthchecks, saleor, a Next.js/Stripe starter)
   to check that a large codebase does not hide them.

Checks cover: personal data reaching a logging call, personal data passed to
a third party or AI provider (directly, through a variable, or through a
wrapper in another file), vendor detection, field protection, and erasure
coverage.

## Results

| Run | Recall | Traps quiet |
|---|---|---|
| Baseline, tuning set, before any fix | **33/53 (62%)** | 3/3 |
| **Held-out set, first run** | **18/21 (86%)** | **2/4** |
| Tuning set after fixes | 53/53 | 3/3 |
| Held-out set after its misses were fixed | 21/21 | 3/4 |
| Both sets planted in healthchecks, saleor and the Next.js starter | 74/74 | 6/7 |

What the baseline missed, by cause:

| Cause | Checks |
|---|---|
| Vendor not in the catalogue (Twilio, SendGrid, PostHog, Amplitude) | 9 |
| Vendor SDK spelled differently (`sentry_sdk`, `segment.analytics`) | 2 |
| A keyword argument (`json=`) hid a call made with a URL constant | 1 |
| Vendor client passed as a value (`generateText({ model: openai(...) })`) | 1 |
| Logging call not recognised (`error_log`, `puts`, C# `LogInformation`) | 3 |
| SQLAlchemy model not recognised as a stored table | 2 |
| Prisma `onDelete: Cascade` not read | 1 |
| Java `@Convert` encryption on the line above the field | 1 |

Once SQLAlchemy models were recognised, one more gap surfaced on the same
check: SHA-256 hashing where the field is written was not counted as
protection. That was fixed too.

What the held-out first run missed: Go `slog`, PHP Monolog `$logger->info`,
C# Serilog `Log.Information` (logging calls not recognised), and two false
alarms: `user.email_verified` (a boolean) treated as contact data, and a
function named `stripe_whitespace` treated as a Stripe integration. The last
one is still reported: an identifier that contains a vendor's name is
indistinguishable from real use by name alone.

## Precision on real code after the fixes

Rescanned with the same version, and every CRITICAL/HIGH defect finding read
by hand:

| Repository | CRITICAL/HIGH defects | Logging findings | Processor flows |
|---|---|---|---|
| excalidraw | 1 (search API key in docs config) | 0 | 0 |
| healthchecks | 8 (SHA-1 x6, wildcard CORS x2) | 0 | 0 |
| saleor | 2 (MD5 for cache keys) | 0 | 13, all Stripe, all pass customer or payment data |
| Next.js/Stripe starter | 0 | 0 | 6, all Stripe, all pass customer data |

Two false flows that appeared while fixing recall were found this way and
removed before release: `sentry_sdk.init(...)` configuration in saleor, and
a TypeScript type annotation (`payment_method: Stripe.PaymentMethod`).

## Limits

- The seeds were written by the author of the tool. They follow the idioms
  he expects, and the held-out set is small (25 checks).
- The real repositories contain few genuine privacy leaks, so they test
  precision far better than recall.
- Not measured: data passed through queues, event buses or dependency
  injection, free text sent to AI models, and languages other than those
  listed.

Treat the held-out first run (86% recall, 2 of 4 traps quiet) as the
estimate, and expect real code to be harder.
