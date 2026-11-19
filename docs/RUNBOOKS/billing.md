# Runbook: billing (plans and payments)

Owner: on-call. Service: `songbird-billing` (Prompt 11; D-0126, D-0128, D-0129). Protocol:
`docs/PROTOCOL.md` §14.4–14.5.

## What it does

Billing verifies purchases with the App Store, Google Play and Mollie, keeps each
subscription's state in **its own database** under keyed hashes of the providers' identifiers,
and issues anonymous plan tokens against it. Accounts redeem the tokens at `api`. Billing never
sees an account and has no access to the registry. Its secrets (the providers' keys, the token
secret, its database credential) are mounted into the billing container only, which runs as a
uid of its own (`billing_uid`).

## Health

- `/readyz` on its admin port (9106) goes ready once the database is reachable and the
  listener bound.
- Apps that cannot fetch tokens keep the plan they have until its month and 3 days of grace
  are over: an outage of billing degrades nothing for up to a few days. Redemption is `api`'s
  and needs only the token secret.

## Failures

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Token requests answer 503 `provider` | Apple, Google or Mollie unreachable | Check the provider's status page. Nothing to do: apps retry, plans in force keep working until their month's end and grace |
| Every Apple request is 403 `proof` | The pinned root, the bundle ID or the environment in `[billing.apple]` | Check `root_ca` (Apple Root CA - G3; billing refuses to start in production with another), `bundle_id`, `environment` |
| Apple notifications answer 400 | Sandbox notifications sent to production (or the reverse), or another app's | Check the URLs registered in App Store Connect for each environment |
| Google notifications answer 401 | The Pub/Sub push subscription's audience or service account differs from `push_audience` / `push_email` | Fix the subscription or the configuration; Pub/Sub retries |
| Mollie webhooks answer 503 | The database or Mollie | Mollie retries for hours; check the database |
| Many 429 `cap` | A subscription asking for more tokens than its plan's month allows (2 Plus, 7 Family) | Expected for a reinstalled app that already spent its spare. Support can grant a month (`songbird-admin plans grant`) |

## Rotating the token keys

Add a key ID to `[billing.tokens] keys` and `[api.tokens] keys` (the highest issues), ship an
app build that pins the new public key (`GET /v1/tokens/keys`), wait two months (a token is
redeemable for its month and the one before), then drop the old ID from both.

## Owner's set-up (once)

- App Store Connect: the products (Plus and Family, monthly and yearly, one subscription
  group), an In-App Purchase key for the App Store Server API, and the Server Notifications V2
  URL `https://<billing>/v1/billing/apple` for production and for the sandbox.
- Play Console: the subscriptions, a service account with the Play Developer API, a Pub/Sub
  topic for real-time developer notifications with a **push** subscription to
  `https://<billing>/v1/billing/google`, authenticated with a service account (its e-mail is
  `push_email`, the audience `push_audience`).
- Mollie: a test-mode API key for the sandbox, then a live key; the webhook URL is per request.
- Counsel: VAT records for direct sales (Mollie): Songbird is the merchant of record.

## Webhook floods (D-0134)

Mollie's webhook carries only a payment ID, which billing fetches back from Mollie: made-up IDs
cost one Mollie API call each. Billing does not budget the path (a budget per range could refuse
Mollie's own calls). Rate-limit `POST /v1/billing/mollie/webhook` at the edge (Mollie's documented
retry pace is a few calls per payment); on a flood, lower that limit and watch
`billing` logs for "provider" errors. Each real payment still counts once, whatever is replayed.
