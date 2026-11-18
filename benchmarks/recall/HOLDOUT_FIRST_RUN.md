### Held-out cases

Recall: **18/21** expected findings reported (86%). Traps: **2/4** stayed quiet.

| By type | Found |
|---|---|
| erasure | 2/2 |
| flow | 6/6 |
| log | 6/9 |
| protection | 4/4 |

| By language | Found |
|---|---|
| C# | 0/1 |
| Go | 0/1 |
| Java | 1/1 |
| PHP | 0/1 |
| Python | 9/9 |
| Ruby | 1/1 |
| TypeScript | 7/7 |

Missed or wrong:

| Case | Expected | Got |
|---|---|---|
| py-log-bool-flag-trap | none-log  | Contact@5, Contact@5 |
| py-vendor-comment-trap | none-vendor  | Stripe |
| go-slog | log category=Contact | - |
| php-monolog | log category=Contact | - |
| cs-serilog | log category=Contact | - |
