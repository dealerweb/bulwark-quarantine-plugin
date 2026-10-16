# Quarantine Release

A Bulwark Webmail plugin that delivers mail held in a quarantine account to its original recipients again. It is
meant for setups where a filter in front of the mail server (ASSP, for example) copies suspected spam into a dedicated
mailbox: an operator opens that mailbox in Bulwark, checks a message and releases it with one click.

## What it does

- A banner on every message in a configured quarantine account names the original recipients and offers **Deliver
  again**. In any other account the plugin does nothing.
- Recipients come only from envelope headers the quarantine wrote (by default `X-Assp-Intended-For`,
  `X-Envelope-To`, `X-Original-To`, `Envelope-To`, in that order; the first header with addresses wins). To, Cc and
  Delivered-To are never used. Only addresses in the allowed domains can be picked, and never a quarantine account.
  Without a recipient header an address can be typed in, again limited to the allowed domains.
- Before sending, the copy is restored to what the sender sent: the quarantine's headers are dropped and the
  `[tag] ` it put in front of the subject is removed. Everything else stays byte for byte, so a DKIM signature over
  the original subject verifies again.
- The copy goes out with the identity of the open quarantine account and an explicit envelope that lists only the
  picked recipients. An empty envelope is refused, because the server would then deliver to the To and Cc headers.
- Before anything is sent, the Message-ID (or, without one, the Date) of the loaded source must match the message on
  screen.
- Afterwards the copy gets a keyword, and releasing it again asks first. Once the server has accepted every
  recipient, the copy moves to the account's trash.

With ASSP, a message to several local recipients can arrive as one copy per recipient; each copy is released on its
own.

## Requirements

- Bulwark 1.15.0 or later.
- Installed by an admin. The plugin runs in the privileged tier, because reading the source of a message of any size
  (`api.jmap.fetchBlob`) and submitting it unchanged (`api.jmap.submitRaw`) are only offered there. Admin installs
  need no separate approval or per-user consent.

| Permission | Used for |
|---|---|
| `crypto:full` | required for the privileged tier |
| `email:read` | folder refreshes, the folder list and the check after the move (`onMailboxesRefresh`, `api.mailboxes.list`, `api.email.get`) |
| `email:write` | the keyword after release and the move to the trash |
| `email:blob-read` | the message source |
| `email:raw-send` | submitting the restored message |
| `email:render-takeover` | the message's blobId, which only the list rows and the opened message carry (`onEmailsFetched`, `onRenderEmailBody`); the plugin returns nothing and changes neither |
| `identity:read` | the identity of the quarantine account |
| `account:read` | which account is open |
| `ui:email-banner` | the banner |
| `admin:config` | the settings |

## Settings (Admin > Plugins)

| Setting | Default |
|---|---|
| `quarantineAccount` | required: comma-separated addresses of the quarantine accounts; each needs an identity with its address |
| `allowedDomains` | required: comma-separated recipient domains |
| `recipientHeaders` | `X-Assp-Intended-For, X-Envelope-To, X-Original-To, Envelope-To` |
| `tagHeader` | `X-Assp-Tag` |
| `removeHeaders` | `X-Assp-*, X-Spam-*, X-Original-Authentication-Results, Authentication-Results, Delivered-To, Return-Path` |
| `releasedKeyword` | `$label:released` |
| `allowManualRecipients` | on |
| `trashAfterRelease` | on |

`Authentication-Results` also matches a copy of that header written by the sender's server; DKIM and ARC do not sign
it, so signatures stay valid. Structural headers (From, To, Cc, Subject, Date, Message-ID, MIME-Version,
Content-Type, Content-Transfer-Encoding, DKIM-Signature) are never removed, not even by a broad pattern.

## Good to know

- Tested with Stalwart. Stalwart does not spam-filter authenticated submissions, so released mail is not caught
  again. The envelope sender is the quarantine account, so a later bounce lands there.
- Stalwart reports per recipient only "accepted and queued" or "rejected"; it keeps no final "delivered". The move
  to the trash therefore waits until every recipient is accepted.
- The plugin API gives up after 30 seconds. A release that times out stays in the quarantine but is marked, so a
  second attempt asks first.
- The background part reads the settings once per page load; reload the page after changing them.

## Development

There is no build step: `manifest.json` and `index.js` are the bundle. `node --test` runs the tests (Node 20 or
later, no dependencies). They load the bundle the way Bulwark's sandbox does.

## License

AGPL-3.0, like Bulwark's own plugins. The icons are path data from [Tabler Icons](https://tabler.io/icons) (MIT).