# Administrator portal (Phase 133)

Open `https://<your-api-host>/admin`. It is a single static page (HTML, CSS, one script; no framework, no inline code, no third-party
requests) that calls the existing `/api/v1/admin/**` API. The page itself holds no data and no secret.

## Signing in
Paste an administrator token (the one from `AdminTokenTool`). It is held in the page's memory only: no cookie, no localStorage/sessionStorage,
never in a URL, and a reload or closing the tab signs you out. The token is sent as `Authorization: Bearer`. The scopes of the credential decide
what works: `LICENSE_ISSUE` (issue), `LICENSE_READ` (list, detail, dashboard counts), `LICENSE_LIFECYCLE` (suspend/reinstate/revoke/renew),
`AUDIT_READ` (history and activity figures). A missing scope is reported as such, and activity figures are shown as **unavailable**, not zero.
Use a credential with only the scopes the person needs.

## Issuing a subscription (manual payment)
1. Enter the customer's e-mail, a duration (30/90/180/365 days preset, custom days, a fixed end date at 23:59:59 UTC, or no end date), device limit,
   activation window, rights and an optional payment reference.
2. Tick the box confirming **you** verified the payment outside the application. Nothing in this application verifies payment.
3. Review, then Confirm. **Only now is anything written.** The page sends one request with a fresh idempotency key; double clicks and retries of the
   same confirmation return the same license and never a second one.
4. The activation key is shown once, with a Copy button and a warning to send it privately. It is wiped from the page on Done or on leaving the view.
   Only a keyed hash of it is stored; it cannot be shown again (revoke and reissue if it is lost).

"Duration in days" counts from the customer's activation; a "fixed end date" is the exact end regardless of when they activate.

## Managing licenses
Licenses: search by e-mail fragment and/or effective status; open a row for details, devices (count of limit) and history. Suspend, reinstate, revoke
and renew each ask for confirmation and an optional reason; the server re-checks the state transition and the scope, so the buttons are a convenience,
not the control. Renew changes only the end date (explicit "extend by N days" or "set exact end date"); device bindings are untouched, a suspended license
stays suspended, a revoked or never-activated license cannot be renewed. Renewal payment is verified outside the app, like issuance.

## Dashboard
Counts come straight from the database at the moment you open or refresh it. Activity figures come from the audit trail and say since when events exist.

## Not included
No payment gateway, customer accounts, referral logic or device reset. Per-row "last activity" is shown on the detail page (newest history event), not in the list.
