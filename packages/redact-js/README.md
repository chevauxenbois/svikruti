# svikruti-redact

Strip personal data from logs and AI prompts at runtime. Zero dependencies,
Node 18+. Same detectors and output as Python's `svikruti.redact`.

```js
const { redact, redactMessages, installConsoleRedaction, pinoLogMethod } = require("svikruti-redact");

installConsoleRedaction();                       // every console.* call in the process
console.log("refund for", customer.email);       // -> refund for [EMAIL]

await openai.chat.completions.create({ model: "gpt-4o-mini", messages: redactMessages(messages) });

const logger = pino({ hooks: { logMethod: pinoLogMethod() } });

redact("Aadhaar 2345 6789 0124, PAN ABCPE1234F");  // -> "Aadhaar [AADHAAR], PAN [PAN]" when the Aadhaar checksum is valid
```

Detected: email, phone (Indian and international), Aadhaar (Verhoeff
checksum), PAN, payment card (Luhn), IFSC, UPI ID, IBAN (mod 97), US SSN,
IPv4. Validated detectors leave look-alike numbers (order ids, amounts)
alone.

Options: `{ kinds: ["EMAIL", "PHONE"], style: "label" | "partial" | "hash", key }`.
`partial` keeps the last four characters; `hash` replaces with a keyed
SHA-256 prefix so the same value still correlates across lines. The key comes
from `key` or `SVIKRUTI_REDACT_KEY`.

`svikruti check` recognises it: values passed through `redact()` are not
leaks, `redactMessages()` before an AI call clears the free-text finding, and
`installConsoleRedaction()` (or `pinoLogMethod()`) marks the matching log
findings as redacted at runtime.

Publish: `cd packages/redact-js && npm test && npm publish`.
