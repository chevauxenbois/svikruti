## Svikruti privacy check

❌ **Blocked**: 3 finding(s) at HIGH or above.

### Open findings

| Severity | Rule | What drifted | Where | Fix |
|---|---|---|---|---|
| HIGH | D002 | Activity 'repayments' processes Location data in code, but the record does not declare it. | `services/payments/refund.js:7`, `services/payments/refund.js:10` | Declare the category on the activity (and update the notice and legal basis), or remove the data from the code. |
| HIGH | D003 | Activity 'repayments' sends data to Mixpanel, which is not a declared processor. | `services/payments/refund.js` | Add the processor with country and contract reference, link it to the activity, or remove the integration. |
| HIGH | P001 | Contact data is written to logs in activity 'repayments' (1 location(s)). | `services/payments/refund.js:8` | Remove or mask the field before logging, or record a time-boxed exception with a reason. |

**DPDPA** 14/23 verified, 5 failing · **GDPR** 14/23 verified, 5 failing · **ISO 27701** 14/23 verified, 5 failing

<sub>Engineering evidence, not legal advice. Update `privacy.yaml` in this PR when processing changes on purpose.</sub>
