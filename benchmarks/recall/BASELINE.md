### Baseline (0.9.1, before tuning)

Recall: **33/53** expected findings reported (62%). Traps: **3/3** stayed quiet.

| By type | Found |
|---|---|
| erasure | 5/6 |
| flow | 8/17 |
| log | 16/19 |
| protection | 4/7 |
| vendor | 0/4 |

| By language | Found |
|---|---|
| C# | 0/1 |
| Go | 3/3 |
| Java | 2/3 |
| JavaScript | 2/2 |
| PHP | 1/2 |
| Python | 17/26 |
| Ruby | 1/2 |
| TypeScript | 7/14 |

Missed or wrong:

| Case | Expected | Got |
|---|---|---|
| py-segment-identify | flow vendor=Segment, category=Contact | - |
| py-sentry-user | flow vendor=Sentry, category=Contact | - |
| py-twilio-sms | vendor vendor=Twilio | - |
| py-twilio-sms | flow vendor=Twilio, category=Contact | - |
| py-sendgrid-mail | vendor vendor=SendGrid | - |
| py-sendgrid-mail | flow vendor=SendGrid, category=Contact | - |
| py-wrapper-cross-file | flow vendor=MSG91, category=Contact | - |
| py-sqlalchemy-hash-on-write | protection field=phone_number, kinds=['hashed'] | field not inventoried |
| py-sqlalchemy-hash-on-write | protection field=email, kinds=['none'] | field not inventoried |
| ts-posthog-identify | vendor vendor=PostHog | - |
| ts-posthog-identify | flow vendor=PostHog, category=Contact | - |
| ts-amplitude | vendor vendor=Amplitude | - |
| ts-amplitude | flow vendor=Amplitude, category=Contact | - |
| ts-ai-sdk-generate | flow vendor=OpenAI, category=Identity | - |
| ts-wrapper-cross-file | flow vendor=SendGrid, category=Contact | - |
| ts-prisma-erasure | erasure store=Session, covered=True | not reached |
| java-jpa-entity | protection field=diagnosis, kinds=['encrypted'] | none |
| rb-puts-inspect | log category=Contact | - |
| php-error-log | log category=Contact | - |
| cs-ilogger | log category=Contact | - |
