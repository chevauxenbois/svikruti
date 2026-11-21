# Svikruti Launch Plan

## Positioning

**Svikruti is open-source privacy as code.** The repository is the record of
processing: Svikruti reads what the code does with personal data, reconciles it
against a reviewed `privacy.yaml`, and fails the pull request when the two
drift apart. Framework packs (DPDPA, GDPR, ISO/IEC 27701, LGPD, CCPA, SOC 2,
RBI, SEBI CSCRF) read the same evidence; no single framework is the product.

Headline:

> Privacy as code.

Subheadline:

> Your privacy notice is a promise. Your code changes it every day. Svikruti
> catches the drift in the pull request.

Primary call to action:

```bash
pip install svikruti
svikruti init --repo .
svikruti check --repo .
```

## Who it is for

- Engineering and platform teams who want privacy checks in CI, next to tests
  and security scans.
- Security and privacy teams who need evidence from code, not questionnaires.
- Consultants and auditors who need a repeatable way to read a codebase.

## What to show

1. **Drift in one pull request**: a change that logs an email and sends
   location to an undeclared vendor, blocked with file and line.
2. **Where the data goes**: free text from a request sent to AI model
   providers, flagged against `policies.ai_allowed_categories`.
3. **Where it is stored**: fields with no protection and no erasure path, from
   the Apache Fineract review.
4. **One record across many services**: `svikruti org` and the processor
   register.
5. **Honest limits**: the recall benchmark, the held-out set and what static
   analysis cannot prove.

## Channels

- LinkedIn: launch post with the product film and the first Substack essay.
- Substack: the flagship essay, then one post per capability every one to two
  weeks.
- Show HN, r/privacy, r/devsecops, IAPP and privacy-engineering communities.
- Conference and meetup talks: privacy engineering, AppSec, DevSecOps.

## Timing hooks

- DPDP Rules apply fully from May 2027.
- Every new AI integration is a new processor; the AI free-text checks are the
  hook for teams shipping LLM features.

## Licence and services

Svikruti is source-available under FSL-1.1-MIT: free to use, modify and
self-host, including at work and by consultants for their clients; no
competing commercial offering; each release becomes MIT after two years.

Hands-on help (repository assessment, CI gate setup, a first `privacy.yaml`,
framework mapping) is available from the author: see "Work with me" in the
README.

## Success measures

- PyPI installs and GitHub stars per week.
- Repositories running `svikruti check` in CI (GitHub Action usage).
- Issues and pull requests from people outside the project.
- Inbound conversations from teams wanting help with a rollout.
