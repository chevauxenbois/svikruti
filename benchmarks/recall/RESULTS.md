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
| saleor | 2 (MD5 for cache keys) | 0 | 13 reported, all Stripe; 10 pass customer or payment data (see correction below) |
| Next.js/Stripe starter | 0 | 0 | 6, all Stripe, all pass customer data |

Two false flows that appeared while fixing recall were found this way and
removed before release: `sentry_sdk.init(...)` configuration in saleor, and
a TypeScript type annotation (`payment_method: Stripe.PaymentMethod`).

## Queues, dependency injection and free text (0.11.0)

`channels.yaml` (18 cases: 14 checks and 4 traps) covers what 0.10.0 listed as
not followed: Dramatiq, RQ, NestJS events, kafkajs, amqplib, Spring
`@RabbitListener` with a constant queue name, Sidekiq, Laravel events, NATS in
Go, interface injection in TypeScript and C#, and request text sent to OpenAI,
Anthropic and Gemini. It was written after those detectors were built, using
idioms the development fixtures did not use, and run once before any change.

| Run | Recall | Traps quiet |
|---|---|---|
| **First run** | **9/14 (64%)** | **4/4** |
| After fixes | 14/14 | 4/4 |
| Planted in healthchecks, saleor and the Next.js starter | 14/14 each | 4/4 each |

What the first run missed: an RQ job (`q.enqueue(func, ...)` runs a plain,
undecorated function), Dramatiq's `actor.send(...)`, Mailgun (not in the
vendor catalogue), a PHP client built as `new \MailchimpMarketing\ApiClient()`,
and C# (`.cs` files were not read by the flow detector at all). The traps (a
redacted prompt, server-built text sent to a model, an event with no vendor
behind it, an interface declaration) stayed quiet on the first run.

Precision after these changes, same repositories and method as above:
CRITICAL/HIGH defects 1 / 8 / 2 / 0 and processor flows 0 / 0 / 13 / 6,
unchanged (saleor's 13 was later corrected to 10, below). Free text was checked on chatbot-ui (an open-source multi-provider
chat app): 14 sites reported, each read by hand; every one sends chat messages
or embedding input taken from the request to OpenAI, Anthropic or Gemini.

## Apache Fineract: a Java/Spring lending platform (0.12.1)

Fineract (7,640 files, core banking and loan management) was the first large
Java codebase reviewed. Every CRITICAL and HIGH finding was read against the
source.

**Scan, CRITICAL/HIGH defects: 44 before this review, 13 after.**

| What was flagged | Count | Verdict |
|---|---|---|
| Email in `log.debug(...)` (password reset, OIDC login) | 2 | True |
| `management.endpoints.web.cors.allowed-origins=*` | 1 | True |
| `loan.getAccountNumber()` in batch-job logs | 9 | Debatable: an internal loan reference that still identifies a borrower. Kept |
| Default admin row seeded by a schema migration | 1 | Borderline |
| Removed as false positives | 31 | Swagger `@Schema(example = ...)` emails (7), demo database dumps and project mailing lists (9), container service URLs such as `http://tempo:4318` (9), `"password=" + password` read as a hard-coded secret (2), loan amounts and `emailCampaign` read as personal data (3), a phone number in a validator test (1) |

**Privacy as code** (`init` then `check`, DPDPA and RBI packs). Before this
review the inventory found no stored fields in Fineract at all: Java `@Entity`
and `@Column` annotations sit on their own lines and were not read. After:
29 tables and 59 personal-data fields, and

- **P007, true:** `ClientIdentifier.documentKey` (passport, voter ID and other
  identity document numbers) and `CreditReport.nationalId` are stored with no
  field-level protection.
- **Rights requests:** `DeleteClientCommandHandler`, `CloseClientCommandHandler`
  and `DeleteUserCommandHandler` are found as entry points. Deleting a client
  reaches `Client` and, through the JPA `@OneToMany(cascade = ALL)` on its
  side, `ClientIdentifier`; deleting a user reaches `AppUser`.
- **D010, 26 tables with no erasure path:** most are ledgers (loans, savings,
  transactions, journal entries) that a regulated lender must retain; they
  belong under `erasure.retained`. `Guarantor`, `ClientFamilyMembers`, `Staff`
  and `Address` hold personal data with no deletion found; these were not
  verified individually.
- **P001 log findings, 25 locations:** 14 true (2 emails, 12 staff usernames
  and display names around OIDC login and webhooks), 9 debatable (loan account
  numbers), 2 false: a database connection username in `RoutingDataSource`,
  held in a bare `username` variable that cannot be told apart from a
  person's. Two more of the same kind (`tenant.getUsername()`,
  `readOnlyUsername`) were fixed.

Gaps this exposed, now fixed: JPA annotations above classes and fields,
parent-side JPA cascades, deletes through typed variables
(`final AppUser user = ...; user.delete()`) and Spring Data repositories
(`appUserRepository.delete(...)`), rights-request names that must have a
person as their whole object (`DeleteClient` but not `DeleteClientCharge`),
and a call tree that no longer follows builder classes naming every command.

**Correction to saleor.** The stricter payment-name rule removed 3 of saleor's
13 Stripe flows. They passed `payment_intent` to `get_payment_method_details()`,
which parses Stripe's response locally and makes no call. They were counted as
true in the first hand review; the correct figure is 10 true flows of 10
reported.

## Limits

- The seeds were written by the author of the tool. They follow the idioms
  he expects, and the held-out set is small (25 checks).
- The real repositories contain few genuine privacy leaks, so they test
  precision far better than recall.
- Not measured: Kotlin, Swift and Scala; channel names built at runtime;
  producers and consumers in different repositories.

Treat the held-out first run (86% recall, 2 of 4 traps quiet) as the
estimate, and expect real code to be harder.
