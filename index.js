'use strict';

/*
 * Quarantine Release
 *
 * Delivers quarantine copies (e.g. the copies ASSP sends to a dedicated
 * quarantine account) to their original recipients:
 *
 * - Recipients come only from envelope headers the quarantine wrote, in the
 *   configured order; To, Cc and Delivered-To are never used. Only addresses
 *   in the allowed domains can be selected.
 * - The copy is cleaned first: the configured headers are dropped and the
 *   "[<tag>] " prefix the quarantine put in front of the subject is removed.
 *   Everything else stays byte-identical, so a DKIM signature over the
 *   original subject verifies again.
 * - It goes out with the quarantine account's identity and an explicit
 *   envelope (rcptTo = the selected recipients), never an empty one: without
 *   an envelope the server would deliver to the To/Cc headers instead.
 * - The copy is marked with a keyword; releasing it again asks first. Once
 *   the server accepted every recipient it moves to the trash, where Bulwark
 *   lets plugins move mail.
 *
 * The background iframe keeps a small state so shouldShow() can gate the
 * banner synchronously, and remembers the blobIds of the quarantine account's
 * messages (the email view handed to the banner carries none), so the banner
 * can load a message of any size. The banner runs in its own iframe without
 * activate(), so it loads config, accounts and identities itself.
 */

// Not `const React`: the sandbox passes React in as a parameter of the bundle
// function (like module, exports, require, ReactDOM, JsxRuntime, console), so
// redeclaring that name is a parse error.
const { createElement: h, useEffect, useRef, useState } = require('react');

// --- Configuration -----------------------------------------------------------

const DEFAULTS = {
  quarantineAccount: '',
  allowedDomains: '',
  recipientHeaders: 'X-Assp-Intended-For, X-Envelope-To, X-Original-To, Envelope-To',
  tagHeader: 'X-Assp-Tag',
  removeHeaders:
    'X-Assp-*, X-Spam-*, X-Original-Authentication-Results, Authentication-Results, Delivered-To, Return-Path',
  releasedKeyword: '$label:released',
  allowManualRecipients: true,
  trashAfterRelease: true,
};

// Message headers, not envelope headers: never a release target, whatever the
// configuration says. Delivered-To names the quarantine mailbox itself.
const NEVER_RECIPIENT_HEADERS = [
  'to', 'cc', 'bcc', 'from', 'sender', 'reply-to',
  'delivered-to', 'resent-to', 'resent-cc', 'resent-bcc',
];

// Structural headers an over-broad removal pattern must not take away.
const PROTECTED_HEADERS = [
  'from', 'to', 'cc', 'subject', 'date', 'message-id', 'mime-version',
  'content-type', 'content-transfer-encoding', 'dkim-signature',
];

function splitList(value) {
  return String(value == null ? '' : value)
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function isTrue(value) {
  return value === true || value === 'true';
}

// The server returns only the keys an admin saved, and clearing a field
// deletes its key, so a missing key means "use the default".
function normalizeConfig(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const text = (key) =>
    typeof src[key] === 'string' && src[key].trim() ? src[key].trim() : DEFAULTS[key];
  return {
    // One or more quarantine accounts, comma-separated in the one field.
    quarantineAccounts: splitList(text('quarantineAccount')).map((address) => address.toLowerCase()),
    allowedDomains: splitList(text('allowedDomains')).map((domain) =>
      domain.toLowerCase().replace(/^[@.]+/, ''),
    ),
    recipientHeaders: splitList(text('recipientHeaders')).filter(
      (name) => !NEVER_RECIPIENT_HEADERS.includes(name.toLowerCase()),
    ),
    tagHeader: text('tagHeader'),
    removeHeaders: splitList(text('removeHeaders')),
    releasedKeyword: text('releasedKeyword'),
    allowManualRecipients:
      src.allowManualRecipients == null
        ? DEFAULTS.allowManualRecipients
        : isTrue(src.allowManualRecipients),
    trashAfterRelease:
      src.trashAfterRelease == null ? DEFAULTS.trashAfterRelease : isTrue(src.trashAfterRelease),
  };
}

// The configured quarantine address an account signs in with, or null.
function quarantineAddressOf(config, account) {
  if (!account) return null;
  for (const value of [account.email, account.username]) {
    const address = typeof value === 'string' ? value.trim().toLowerCase() : '';
    if (address && config.quarantineAccounts.includes(address)) return address;
  }
  return null;
}

// --- Recipients --------------------------------------------------------------

// Header values arrive as Record<name, string | string[]> with the names as
// written in the message, so look them up case-insensitively.
function headerValues(headers, name) {
  const wanted = String(name).toLowerCase();
  const values = [];
  if (!headers || typeof headers !== 'object') return values;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const value = headers[key];
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item != null) values.push(String(item));
    }
  }
  return values;
}

const ADDRESS_RE = /[^\s<>,;:"'()[\]]+@[^\s<>,;:"'()[\]]+\.[^\s<>,;:"'()[\]]+/g;
const SINGLE_ADDRESS_RE = /^[^\s@<>,;:"'()[\]]+@[^\s@<>,;:"'()[\]]+\.[^\s@<>,;:"'()[\]]+$/;

function extractAddresses(text) {
  const addresses = [];
  for (const match of String(text).match(ADDRESS_RE) || []) {
    const address = match.replace(/\.+$/, '').toLowerCase();
    if (!addresses.includes(address)) addresses.push(address);
  }
  return addresses;
}

// The first configured header that yields addresses wins.
function findRecipients(headers, headerNames) {
  for (const name of headerNames || []) {
    if (NEVER_RECIPIENT_HEADERS.includes(String(name).toLowerCase())) continue;
    const addresses = [];
    for (const value of headerValues(headers, name)) {
      for (const address of extractAddresses(value)) {
        if (!addresses.includes(address)) addresses.push(address);
      }
    }
    if (addresses.length > 0) return { header: name, addresses };
  }
  return { header: null, addresses: [] };
}

function isAllowedAddress(address, allowedDomains) {
  const value = String(address).toLowerCase();
  if (!SINGLE_ADDRESS_RE.test(value)) return false;
  return (allowedDomains || []).includes(value.slice(value.lastIndexOf('@') + 1));
}

// A release target lies in an allowed domain and is never a quarantine
// account: that would only drop the mail back into a quarantine inbox.
function isReleaseTarget(address, config) {
  return (
    isAllowedAddress(address, config.allowedDomains) &&
    !config.quarantineAccounts.includes(String(address).toLowerCase())
  );
}

function hasKeyword(keywords, keyword) {
  const wanted = String(keyword).toLowerCase();
  return Array.isArray(keywords) && keywords.some((item) => String(item).toLowerCase() === wanted);
}

// --- Message cleaning --------------------------------------------------------
//
// Works on the raw bytes. Only the header block is decoded (one char per byte,
// so nothing gets re-encoded) and the body is copied through untouched.

function bytesToBinary(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return text;
}

function binaryToBytes(text) {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
  return bytes;
}

// Offset of the empty line that ends the header block (CRLF or LF), or the
// message length when there is no body.
function headerBlockEnd(bytes) {
  const LF = 0x0a;
  const CR = 0x0d;
  if (bytes[0] === LF || (bytes[0] === CR && bytes[1] === LF)) return 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== LF) continue;
    if (bytes[i + 1] === LF || (bytes[i + 1] === CR && bytes[i + 2] === LF)) return i + 1;
  }
  return bytes.length;
}

// One entry per header field; continuation lines (starting with a space or a
// tab) stay with their field, line endings included.
function parseHeaderFields(head) {
  const fields = [];
  for (const line of head.match(/[^\n]*\n|[^\n]+$/g) || []) {
    if ((line[0] === ' ' || line[0] === '\t') && fields.length > 0) {
      fields[fields.length - 1].raw += line;
      continue;
    }
    const colon = line.indexOf(':');
    fields.push({ name: colon > 0 ? line.slice(0, colon).trim().toLowerCase() : '', raw: line });
  }
  return fields;
}

function fieldValue(field) {
  return field.raw
    .slice(field.raw.indexOf(':') + 1)
    .replace(/\r?\n(?=[ \t])/g, '')
    .trim();
}

function matchesHeaderPattern(name, pattern) {
  const wanted = pattern.toLowerCase();
  return wanted.endsWith('*') ? name.startsWith(wanted.slice(0, -1)) : name === wanted;
}

/**
 * Restores the message as it was before the quarantine got it: drops the
 * configured header fields and removes the "[<tag>] " prefix the quarantine
 * put in front of the subject (at most once per tag header, so a tag that was
 * already part of the original subject survives). Everything else stays
 * byte-identical.
 */
function cleanMessage(bytes, options) {
  const end = headerBlockEnd(bytes);
  const fields = parseHeaderFields(bytesToBinary(bytes.subarray(0, end)));

  const tagName = String(options.tagHeader || '').toLowerCase();
  const pendingTags = tagName
    ? fields.filter((field) => field.name === tagName).map(fieldValue).filter(Boolean)
    : [];

  // A lone "*" would match every header; ignore it.
  const patterns = (options.removeHeaders || []).filter((pattern) => pattern.replace(/\*$/, '') !== '');
  const removed = [];
  const kept = fields.filter((field) => {
    const drop =
      field.name !== '' &&
      !PROTECTED_HEADERS.includes(field.name) &&
      patterns.some((pattern) => matchesHeaderPattern(field.name, pattern));
    if (drop) removed.push(field.name);
    return !drop;
  });

  const strippedTags = [];
  const subject = kept.find((field) => field.name === 'subject');
  if (subject && pendingTags.length > 0) {
    const prefix = /^[^:]*:[ \t]*/.exec(subject.raw)[0];
    let value = subject.raw.slice(prefix.length);
    let index;
    while ((index = pendingTags.findIndex((tag) => value.startsWith('[' + tag + '] '))) !== -1) {
      value = value.slice(pendingTags[index].length + 3);
      strippedTags.push(pendingTags.splice(index, 1)[0]);
    }
    subject.raw = prefix + value;
  }

  const head = binaryToBytes(kept.map((field) => field.raw).join(''));
  const out = new Uint8Array(head.length + bytes.length - end);
  out.set(head, 0);
  out.set(bytes.subarray(end), head.length);
  return { bytes: out, removed, strippedTags };
}

// --- Release -----------------------------------------------------------------

const BLOB_KEY = 'blobIds';
// About 70 bytes each in the plugin's storage, which holds 1 MB per account.
const BLOB_LIMIT = 1000;

function messageOf(err) {
  return err && err.message ? String(err.message) : String(err);
}

function releaseError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function storedBlobId(api, emailId) {
  const stored = await api.storage.get(BLOB_KEY);
  const hit = Array.isArray(stored)
    ? stored.find((entry) => Array.isArray(entry) && entry[0] === emailId)
    : null;
  return hit && typeof hit[1] === 'string' ? hit[1] : null;
}

/**
 * The message as the server stores it. jmap.fetchBlob has no size limit of
 * its own, so it is the way in whenever the background iframe has seen the
 * message's blobId (list rows, the opened message). Without one,
 * api.email.getRaw is used, which stops at 25 MB; a larger message then gets a
 * moment for its blobId to arrive.
 */
async function loadMessage(api, emailId) {
  let blobId = await storedBlobId(api, emailId);
  if (!blobId && api.email && typeof api.email.getRaw === 'function') {
    try {
      return new Uint8Array(await api.email.getRaw(emailId));
    } catch (err) {
      if (!/larger than/i.test(messageOf(err))) throw err;
    }
  }
  for (let attempt = 0; !blobId && attempt < 5; attempt++) {
    await sleep(300);
    blobId = await storedBlobId(api, emailId);
  }
  if (!blobId) throw releaseError('NO_BLOB', 'The message source is not available');
  return api.jmap.fetchBlob(blobId);
}

function compact(value) {
  return String(value == null ? '' : value).replace(/\s+/g, '');
}

/**
 * What identifies the message the banner shows: its Message-ID, or its Date
 * when it has none. Checked against the loaded bytes before anything is sent,
 * so the source of another message (an id of another account in a view over
 * several accounts, say) never goes out under this one's recipients.
 */
function shownMessageKey(headers) {
  for (const name of ['Message-ID', 'Date']) {
    const value = compact(headerValues(headers, name)[0]);
    if (value) return { name: name.toLowerCase(), value };
  }
  return null;
}

function rawHeaderValue(bytes, name) {
  const fields = parseHeaderFields(bytesToBinary(bytes.subarray(0, headerBlockEnd(bytes))));
  const field = fields.find((item) => item.name === name);
  return field ? compact(fieldValue(field)) : '';
}

/**
 * Moves the copy into its account's trash. mailboxes.list also names the trash
 * folders of shared accounts, which email.move refuses without moving
 * anything, so each is tried in turn. email.move resolves even when another
 * plugin stopped the move, so the message is looked up afterwards.
 */
async function moveToTrash(api, emailId, outcome) {
  let failure = new Error('no trash folder');
  try {
    const mailboxes = await api.mailboxes.list();
    const trashes = (Array.isArray(mailboxes) ? mailboxes : []).filter((mailbox) => mailbox && mailbox.role === 'trash');
    for (const trash of trashes) {
      try {
        await api.email.move([emailId], trash.id);
      } catch (err) {
        failure = err;
        continue;
      }
      const after = typeof api.email.get === 'function' ? await api.email.get(emailId) : null;
      if (after && !(Array.isArray(after.mailboxIds) && after.mailboxIds.includes(trash.id))) {
        failure = new Error('the move was stopped');
        break;
      }
      outcome.trashed = true;
      return;
    }
  } catch (err) {
    failure = err;
  }
  outcome.trashError = messageOf(failure);
}

function canMoveMail(api) {
  return Boolean(
    api.mailboxes && typeof api.mailboxes.list === 'function' && api.email && typeof api.email.move === 'function',
  );
}

/**
 * Sends the cleaned copy to `recipients` and marks the original. Throws when
 * nothing went out; otherwise resolves to what happened:
 *   status 'released': every recipient accepted and queued by the server
 *   status 'partial':  some recipients rejected (listed in `rejected`)
 *   status 'unclear':  the call timed out while the host may still be sending
 */
async function releaseCopy(api, { emailId, expect, identityId, recipients, config }) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    // An empty envelope would make the server deliver to the To/Cc headers.
    throw releaseError('NO_RECIPIENTS', 'No recipients selected');
  }
  const notAllowed = recipients.filter((address) => !isReleaseTarget(address, config));
  if (notAllowed.length > 0) {
    throw releaseError('NOT_ALLOWED', 'Recipients not allowed: ' + notAllowed.join(', '));
  }
  if (!identityId) throw releaseError('NO_IDENTITY', 'No identity for the quarantine account');

  const original = await loadMessage(api, emailId);
  if (expect && rawHeaderValue(original, expect.name) !== expect.value) {
    throw releaseError('MISMATCH', 'The loaded message is not the one shown');
  }
  const cleaned = cleanMessage(original, config);

  let status = 'released';
  let rejected = [];
  try {
    const result = await api.jmap.submitRaw(cleaned.bytes, identityId, { envelopeRecipients: recipients });
    rejected = Array.isArray(result && result.rejectedRecipients) ? result.rejectedRecipients : [];
    if (rejected.length > 0) status = 'partial';
  } catch (err) {
    // The sandbox stops waiting after 30 s while the host goes on sending, so
    // the outcome is unknown. The copy still gets marked: a second attempt
    // then asks first instead of silently delivering twice.
    if (!/timed out/i.test(messageOf(err))) throw err;
    status = 'unclear';
  }

  const outcome = {
    status,
    rejected,
    removed: cleaned.removed,
    strippedTags: cleaned.strippedTags,
    markError: null,
    trashed: false,
    trashError: null,
  };

  try {
    await api.jmap.setKeyword(emailId, config.releasedKeyword);
  } catch (err) {
    outcome.markError = messageOf(err);
  }

  // Only when the server accepted every recipient.
  if (status === 'released' && config.trashAfterRelease && canMoveMail(api)) {
    await moveToTrash(api, emailId, outcome);
  }

  return outcome;
}

function formatRejected(rejected) {
  return rejected
    .map((entry) => (entry && entry.smtpReply ? entry.email + ' (' + entry.smtpReply + ')' : entry && entry.email))
    .filter(Boolean)
    .join(', ');
}

function describeOutcome(outcome, recipientList, t) {
  let tone = 'success';
  const parts = [];
  if (outcome.status === 'unclear') {
    tone = 'warning';
    parts.push(t('resultUnclear'));
  } else if (outcome.status === 'partial') {
    tone = 'warning';
    parts.push(t('partlyRejected', { rejected: formatRejected(outcome.rejected) }));
  } else if (outcome.trashed) {
    parts.push(t('releasedAndTrashed', { recipients: recipientList }));
  } else {
    parts.push(t('released', { recipients: recipientList }));
  }
  if (outcome.trashError) {
    tone = 'warning';
    parts.push(t('trashFailed', { error: outcome.trashError }));
  }
  if (outcome.markError) {
    tone = 'warning';
    parts.push(t('markFailed', { error: outcome.markError }));
  }
  return { tone, text: parts.join(' ') };
}

// --- Banner (slot iframe) ----------------------------------------------------
//
// Looks like Bulwark's own notices above a message (sender check, external
// content): a full-width strip, a round icon badge, a small uppercase label and
// outlined buttons. The slot iframe gets the host theme as CSS variables
// (including --font-size-base); the style block maps Bulwark's Tailwind
// classes onto them.

// Glyphs from Tabler Icons (MIT), the set Bulwark draws its own icons with.
const ICONS = {
  shieldAlert: [
    'M15.04 19.745c-.942 .551 -1.964 .976 -3.04 1.255a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 .195 6.015',
    'M19 16v3',
    'M19 22v.01',
  ],
  shieldCheck: [
    'M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06',
    'M15 19l2 2l4 -4',
  ],
  send: ['M10 14l11 -11', 'M21 3l-6.5 18a.55 .55 0 0 1 -1 0l-3.5 -7l-7 -3.5a.55 .55 0 0 1 0 -1l18 -6.5'],
  check: ['M5 12l5 5l10 -10'],
  loader: ['M12 3a9 9 0 1 0 9 9'],
  alert: ['M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0', 'M12 8v4', 'M12 16h.01'],
};

const CSS = [
  ':root { font-size: var(--font-size-base, 16px); }',
  'body { margin: 0; }',
  '.qr-strip { border-bottom: 1px solid var(--color-border); background: color-mix(in oklab, var(--color-muted) 30%, transparent);',
  '  padding: 0.375rem 1.5rem; color: var(--color-foreground); font-size: 0.875rem; line-height: 1.25rem; }',
  '.qr-item { display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.25rem 0; }',
  '.qr-badge { width: 2.5rem; height: 2.5rem; flex-shrink: 0; display: flex; align-items: center; justify-content: center;',
  '  border-radius: 9999px; box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);',
  '  background: color-mix(in oklab, var(--color-warning) 15%, transparent); color: var(--color-warning); }',
  '.qr-badge.is-released { background: color-mix(in oklab, var(--color-success) 15%, transparent); color: var(--color-success); }',
  '.qr-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 0.5rem; }',
  '.qr-label { font-size: 10px; line-height: 1.5; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;',
  '  color: var(--color-muted-foreground); }',
  '.qr-ok { color: var(--color-success); }',
  '.qr-main { font-weight: 500; overflow-wrap: anywhere; }',
  '.qr-muted { color: var(--color-muted-foreground); overflow-wrap: anywhere; }',
  '.qr-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.375rem; }',
  '.qr-actions { padding-top: 0.125rem; }',
  '.qr-button, .qr-chip { display: inline-flex; align-items: center; gap: 0.375rem; border: 1px solid var(--color-border);',
  '  background: transparent; color: var(--color-muted-foreground); font: inherit; cursor: pointer;',
  '  transition: color 150ms, background-color 150ms, border-color 150ms; }',
  '.qr-button { min-height: 36px; padding: 0.375rem 0.75rem; border-radius: 0.375rem; }',
  '.qr-chip { max-width: 100%; padding: 0.25rem 0.625rem; border-radius: 9999px; text-align: left; }',
  '.qr-button:hover:not(:disabled), .qr-chip:hover:not(:disabled) { color: var(--color-foreground); background: var(--color-muted); }',
  '.qr-chip.is-on { color: var(--color-foreground); border-color: color-mix(in oklab, var(--color-primary) 40%, transparent);',
  '  background: color-mix(in oklab, var(--color-primary) 10%, transparent); }',
  '.qr-button:disabled { opacity: 0.5; cursor: default; }',
  '.qr-chip:disabled { opacity: 0.5; cursor: not-allowed; text-decoration: line-through; }',
  '.qr-chip > span { overflow-wrap: anywhere; }',
  '.qr-input { box-sizing: border-box; width: 100%; max-width: 22rem; height: 2.25rem; padding: 0 0.75rem;',
  '  border: 1px solid var(--color-input); border-radius: 0.375rem; background: var(--color-background);',
  '  color: var(--color-foreground); font: inherit; }',
  '.qr-button:focus-visible, .qr-chip:focus-visible, .qr-input:focus-visible { outline: 2px solid var(--color-ring); outline-offset: 2px; }',
  '.qr-notice { display: flex; align-items: flex-start; gap: 0.375rem; overflow-wrap: anywhere; }',
  '.qr-notice .qr-icon { flex-shrink: 0; margin-top: 0.125rem; }',
  '.qr-tone-success { color: var(--color-success); }',
  '.qr-tone-warning { color: var(--color-warning); }',
  '.qr-tone-error { color: var(--color-destructive); }',
  '.qr-spin { animation: qr-spin 1s linear infinite; }',
  '@keyframes qr-spin { to { transform: rotate(360deg); } }',
].join('\n');

function hostApi() {
  return require('@plugin-host');
}

function Icon(props) {
  return h(
    'svg',
    {
      xmlns: 'http://www.w3.org/2000/svg',
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 2,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
      className: props.className ? 'qr-icon ' + props.className : 'qr-icon',
      style: { width: props.size, height: props.size },
      'aria-hidden': 'true',
    },
    ICONS[props.name].map((d) => h('path', { key: d, d })),
  );
}

function Notice(props) {
  return h(
    'div',
    { className: 'qr-notice', role: props.tone === 'error' ? 'alert' : 'status' },
    h(Icon, { name: props.tone === 'success' ? 'check' : 'alert', size: '1rem', className: 'qr-tone-' + props.tone }),
    h('span', null, props.text),
  );
}

function Strip(props) {
  return h(
    'div',
    { className: 'qr-strip' },
    h('style', null, CSS),
    h(
      'div',
      { className: 'qr-item' },
      h(
        'div',
        { className: props.released ? 'qr-badge is-released' : 'qr-badge' },
        h(Icon, { name: props.released ? 'shieldCheck' : 'shieldAlert', size: '1.25rem' }),
      ),
      h('div', { className: 'qr-body' }, props.children),
    ),
  );
}

async function loadBannerContext(api) {
  const [rawConfig, accounts, identities] = await Promise.all([
    api.admin.getAllConfig(),
    api.user.getAccounts(),
    api.user.getIdentities(),
  ]);
  const config = normalizeConfig(rawConfig);
  const active = Array.isArray(accounts) ? accounts.find((account) => account && account.isActive) : null;
  // Released mail goes out with the identity of the quarantine account that is open.
  const quarantineAddress = quarantineAddressOf(config, active);
  const identity = quarantineAddress && Array.isArray(identities)
    ? identities.find(
        (item) => item && typeof item.email === 'string' && item.email.trim().toLowerCase() === quarantineAddress,
      )
    : null;
  return {
    config,
    quarantineAddress,
    isQuarantine: Boolean(quarantineAddress),
    identityId: identity ? identity.id : null,
  };
}

function ReleasePanel(props) {
  const { api, email, context } = props;
  const { config, identityId } = context;
  const t = (key, vars) => api.i18n.t(key, vars);
  const allowed = (address) => isReleaseTarget(address, config);
  const isSelf = (address) => config.quarantineAccounts.includes(address);
  const found = findRecipients(email.headers, config.recipientHeaders);
  const blocked = found.addresses.filter((address) => !allowed(address));

  // Derived on every render instead of captured at mount, so the selection and
  // the released state follow the mail when Bulwark updates it.
  const [deselected, setDeselected] = useState([]);
  const selected = found.addresses.filter((address) => allowed(address) && !deselected.includes(address));
  const [manual, setManual] = useState('');
  const [busy, setBusy] = useState(false);
  const [releasedHere, setReleasedHere] = useState(false);
  const released = releasedHere || hasKeyword(email.keywords, config.releasedKeyword);
  const [notice, setNotice] = useState(null);
  const running = useRef(false);

  const useManual = found.addresses.length === 0 && config.allowManualRecipients;
  const manualAddresses = splitList(manual).map((address) => address.toLowerCase());
  const manualRejected = manualAddresses.filter((address) => !allowed(address));
  const recipients = useManual ? (manualRejected.length === 0 ? manualAddresses : []) : selected;
  const canRelease = !busy && recipients.length > 0 && Boolean(identityId);

  function toggle(address) {
    setDeselected((current) =>
      current.includes(address) ? current.filter((item) => item !== address) : current.concat(address),
    );
  }

  async function onRelease() {
    if (!canRelease || running.current) return;
    running.current = true;
    try {
      const list = recipients.join(', ');
      const confirmed = await api.ui.confirm({
        title: t(released ? 'confirmAgainTitle' : 'confirmTitle'),
        message: t(released ? 'confirmAgainMessage' : 'confirmMessage', { recipients: list }),
        confirmLabel: t('confirmLabel'),
        cancelLabel: t('cancelLabel'),
        danger: released,
      });
      if (!confirmed) return;
      setBusy(true);
      setNotice(null);
      try {
        const outcome = await releaseCopy(api, {
          emailId: email.id,
          expect: shownMessageKey(email.headers),
          identityId,
          recipients,
          config,
        });
        setReleasedHere(true);
        const result = describeOutcome(outcome, list, t);
        setNotice(result);
        api.toast[result.tone === 'success' ? 'success' : 'warning'](result.text);
        api.log.info('released', {
          status: outcome.status,
          recipients,
          dropped: outcome.removed,
          strippedTags: outcome.strippedTags,
        });
      } catch (err) {
        const known = { NO_BLOB: 'noBlob', MISMATCH: 'mismatch' };
        const text = err && known[err.code] ? t(known[err.code]) : t('releaseFailed', { error: messageOf(err) });
        setNotice({ tone: 'error', text });
        api.toast.error(text);
      } finally {
        setBusy(false);
      }
    } finally {
      running.current = false;
    }
  }

  let main;
  let detail = null;
  if (found.addresses.length > 0) {
    main = found.addresses.length === 1
      ? t('intendedForOne', { address: found.addresses[0] })
      : t('intendedForMany', { count: found.addresses.length });
    detail = t('intendedSource', { header: found.header });
  } else {
    main = t('noRecipientHeader');
    if (!useManual) detail = t('noManual');
    else if (config.allowedDomains.length > 0) detail = t('manualHint', { domains: config.allowedDomains.join(', ') });
  }

  const children = [
    h(
      'div',
      { key: 'head' },
      h(
        'div',
        { className: 'qr-label' },
        t('bannerTitle'),
        released ? h('span', { className: 'qr-ok' }, ' \u00b7 ' + t('alreadyReleased')) : null,
      ),
      h('div', { className: 'qr-main' }, main),
      detail ? h('div', { className: 'qr-muted' }, detail) : null,
    ),
  ];

  // One recipient is named in the main line; several (or a blocked one) get
  // chips to pick from.
  if (found.addresses.length > 1 || blocked.length > 0) {
    children.push(
      h(
        'div',
        { key: 'chips', className: 'qr-row' },
        found.addresses.map((address) => {
          const ok = allowed(address);
          const on = ok && selected.includes(address);
          return h(
            'button',
            {
              key: address,
              type: 'button',
              className: on ? 'qr-chip is-on' : 'qr-chip',
              disabled: !ok || busy,
              title: ok ? undefined : t(isSelf(address) ? 'quarantineAccountChip' : 'domainNotAllowed'),
              'aria-pressed': on,
              onClick: () => toggle(address),
            },
            on ? h(Icon, { name: 'check', size: '0.875rem' }) : null,
            h('span', null, address),
          );
        }),
      ),
    );
    if (blocked.some(isSelf)) {
      children.push(h('div', { key: 'blocked-self', className: 'qr-muted' }, t('quarantineAccountHint')));
    }
    if (blocked.some((address) => !isSelf(address))) {
      children.push(h('div', { key: 'blocked-domain', className: 'qr-muted' }, t('someNotAllowed')));
    }
  }

  if (useManual) {
    children.push(
      h('input', {
        key: 'manual',
        type: 'text',
        className: 'qr-input',
        value: manual,
        disabled: busy,
        placeholder: t('manualPlaceholder'),
        'aria-label': t('manualPlaceholder'),
        onChange: (event) => setManual(event.target.value),
      }),
    );
    if (manualRejected.length > 0) {
      children.push(
        h(Notice, { key: 'manual-rejected', tone: 'warning', text: t('manualNotAllowed', { addresses: manualRejected.join(', ') }) }),
      );
    }
  }

  if (config.allowedDomains.length === 0) {
    children.push(h(Notice, { key: 'domains', tone: 'warning', text: t('noAllowedDomains') }));
  }
  if (!identityId) {
    children.push(h(Notice, { key: 'identity', tone: 'warning', text: t('noIdentity', { account: context.quarantineAddress }) }));
  }

  children.push(
    h(
      'div',
      { key: 'actions', className: 'qr-row qr-actions' },
      h(
        'button',
        { type: 'button', className: 'qr-button', onClick: onRelease, disabled: !canRelease },
        h(Icon, { name: busy ? 'loader' : 'send', size: '0.875rem', className: busy ? 'qr-spin' : '' }),
        busy ? t('releasing') : t('releaseButton'),
      ),
    ),
  );

  if (notice) children.push(h(Notice, { key: 'notice', tone: notice.tone, text: notice.text }));

  return h(Strip, { released }, children);
}

function QuarantineBanner(props) {
  const api = hostApi();
  const email = props && props.email;
  const [context, setContext] = useState(null);

  useEffect(() => {
    let cancelled = false;
    loadBannerContext(api).then(
      (value) => {
        if (!cancelled) setContext(value);
      },
      (err) => {
        if (!cancelled) setContext({ loadError: messageOf(err) });
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  if (!email || !email.id || !context) return null;
  if (context.loadError) {
    return h(
      Strip,
      null,
      h('div', { className: 'qr-label' }, api.i18n.t('bannerTitle')),
      h(Notice, { tone: 'error', text: api.i18n.t('loadFailed', { error: context.loadError }) }),
    );
  }
  if (!context.isQuarantine) return null;
  // After a delete or move Bulwark first shows the next mail as its list row,
  // which carries no headers, and swaps in the full mail a moment later. Wait
  // for the headers instead of showing "no recipient header" in between.
  if (!email.headers) return null;
  // The slot iframe outlives a change of the opened mail; a fresh panel per
  // mail resets selection, input and result.
  return h(ReleasePanel, { key: email.id, api, email, context });
}

// --- Background iframe -------------------------------------------------------

let backgroundApi = null;
let backgroundConfig = null;
let quarantineActive = false;
let refreshing = Promise.resolve();
// blobIds of messages seen while the quarantine account was active, oldest
// first; mirrored to api.storage, the only thing the banner's iframe shares.
const blobIds = new Map();
let flushTimer = null;

function refreshState() {
  if (!backgroundApi) return refreshing;
  refreshing = (async () => {
    try {
      // The config only changes when an admin saves it: keep it once a
      // quarantine account is set (a page reload picks up later changes).
      if (!backgroundConfig || backgroundConfig.quarantineAccounts.length === 0) {
        backgroundConfig = normalizeConfig(await backgroundApi.admin.getAllConfig());
      }
      const accounts = (await backgroundApi.user.getAccounts()) || [];
      quarantineActive = accounts.some(
        (account) => account && account.isActive && Boolean(quarantineAddressOf(backgroundConfig, account)),
      );
      if (!quarantineActive) blobIds.clear();
    } catch (err) {
      backgroundApi.log.warn('state refresh failed:', messageOf(err));
    }
  })();
  return refreshing;
}

function flushBlobIds() {
  flushTimer = null;
  backgroundApi.storage
    .set(BLOB_KEY, [...blobIds])
    .catch((err) => backgroundApi.log.warn('could not store blobIds:', messageOf(err)));
}

// Records blobIds only while the quarantine account is the active one. Rows of
// a view over several accounts carry their account and are skipped: message
// ids are only unique within one account.
function noteBlobIds(items) {
  if (!quarantineActive) return;
  let changed = false;
  for (const item of items) {
    if (!item || typeof item.id !== 'string' || typeof item.blobId !== 'string') continue;
    if (item.accountId || item.sourceAccountId) continue;
    if (blobIds.get(item.id) === item.blobId) continue;
    blobIds.set(item.id, item.blobId);
    changed = true;
  }
  if (!changed) return;
  if (blobIds.size > BLOB_LIMIT) {
    const recent = [...blobIds].slice(-BLOB_LIMIT);
    blobIds.clear();
    for (const [id, blobId] of recent) blobIds.set(id, blobId);
  }
  if (flushTimer === null) flushTimer = setTimeout(flushBlobIds, 250);
}

const hooks = {
  // Every row of a loaded message list, one by one: the list groups messages
  // into conversations only on screen, so this covers those too.
  onEmailsFetched(emails) {
    const rows = Array.isArray(emails) ? emails : [];
    refreshing.then(() => noteBlobIds(rows));
    // Leave the list as it is.
    return undefined;
  },
  // The opened message; its context carries the blobId.
  onRenderEmailBody(body, context) {
    refreshing.then(() => noteBlobIds([context]));
    // Leave the body to the host.
    return undefined;
  },
  onMailboxesRefresh() {
    // Runs after every folder fetch, also right after an account switch and
    // before the list loads. Not awaited: the host waits for hook handlers
    // before it goes on loading.
    void refreshState();
  },
};

function shouldShow(context) {
  const email = context && context.email;
  return Boolean(email && email.id) && quarantineActive;
}

async function activate(api) {
  backgroundApi = api;
  // Not awaited: activation must not hang on a slow config request.
  void refreshState();
}

module.exports = {
  activate,
  hooks,
  slots: {
    'email-banner': { component: QuarantineBanner, shouldShow, order: 50 },
  },
  // Pure helpers, exported for test/release.test.js.
  internals: {
    normalizeConfig,
    findRecipients,
    isAllowedAddress,
    isReleaseTarget,
    shownMessageKey,
    loadBannerContext,
    cleanMessage,
    releaseCopy,
    describeOutcome,
  },
};