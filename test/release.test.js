'use strict';

// Run from the plugin folder: node --test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Evaluate the bundle exactly the way the Bulwark sandbox does (evaluateBundle
// in lib/plugin-sandbox/runtime.tsx, same parameter list), so load-time
// mistakes such as redeclaring an injected name fail here too.
function loadPlugin() {
  const code = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  const mod = { exports: {} };
  const react = { createElement: () => null };
  const shim = (name) => {
    if (name === 'react') return react;
    throw new Error('unexpected require: ' + name);
  };
  new Function('module', 'exports', 'require', 'React', 'ReactDOM', 'JsxRuntime', 'console', code)(
    mod, mod.exports, shim, react, {}, {}, console,
  );
  return mod.exports;
}

const plugin = loadPlugin();
const {
  normalizeConfig, findRecipients, isAllowedAddress, isReleaseTarget, shownMessageKey, loadBannerContext, cleanMessage,
  releaseCopy, describeOutcome,
} = plugin.internals;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const lines = (list) => list.join('\r\n') + '\r\n';

// The message as the sender's server signed it.
const ORIGINAL_HEAD = lines([
  'DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=mail;',
  '\th=From:To:Subject:Date:Message-ID; bh=placeholder; b=placeholder',
  'From: Sender <sender@example.net>',
  'To: user@example.com',
  'Subject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?= aus dem Lager',
  'Date: Tue, 14 Oct 2026 09:30:00 +0200',
  'Message-ID: <original-1@example.net>',
  'authentication-results: relay.example.net; spf=pass',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=UTF-8',
  'Content-Transfer-Encoding: 8bit',
]);
// Bytes that are no valid UTF-8 prove the body is copied, not re-encoded.
const BODY = Buffer.concat([Buffer.from('\r\nHallo, Grüße\r\n', 'utf8'), Buffer.from([0xff, 0xfe, 0x0d, 0x0a])]);

// What the quarantine delivery put on top, and the tag in front of the subject.
const QUARANTINE_TOP = lines([
  'Delivered-To: quarantine@example.com',
  'Received: from relay.example.com (relay.example.com [192.0.2.10])',
  '\tby mail.example.com with ESMTPS; Tue, 14 Oct 2026 09:30:05 +0200',
  'Authentication-Results: mail.example.com; dkim=fail (verification failed) header.d=example.net',
  'Return-Path: <sender@example.net>',
  'X-Assp-Envelope-From: sender@example.net',
  'X-Original-Authentication-Results: relay.example.com; dkim=pass; spf=pass;',
  '\t dmarc=pass',
  'X-Assp-Tag: PTRinvalid',
  'X-Assp-Spam: YES',
  'X-Spam-Status: yes',
  "X-Assp-Spam-Reason: PTR invalid 'host.example.net'",
  'X-ASSP-Intended-For: user@example.com',
  'X-Assp-Copy-Spam: Yes',
]);
const KEPT_TOP = lines([
  'Received: from relay.example.com (relay.example.com [192.0.2.10])',
  '\tby mail.example.com with ESMTPS; Tue, 14 Oct 2026 09:30:05 +0200',
]);
const TAGGED_HEAD = ORIGINAL_HEAD.replace('Subject: ', 'Subject: [PTRinvalid] ');

const quarantineCopy = Buffer.concat([Buffer.from(QUARANTINE_TOP + TAGGED_HEAD, 'latin1'), BODY]);
// The default list also drops the sender-side authentication-results (not
// signed, so DKIM is unaffected).
const expectedRelease = Buffer.concat([
  Buffer.from(KEPT_TOP + ORIGINAL_HEAD.replace('authentication-results: relay.example.net; spf=pass\r\n', ''), 'latin1'),
  BODY,
]);

const CONFIG = normalizeConfig({ quarantineAccount: 'Quarantine@example.com', allowedDomains: 'example.com, @example.org' });
// What the banner passes along: the shown message's Message-ID as JMAP returns it.
const EXPECT = shownMessageKey({ 'Message-ID': ' <original-1@example.net>' });

function fakeApi(options = {}) {
  const calls = { submit: [], keyword: [], trash: [], getRaw: [] };
  const stored = options.stored || [['other', 'blob-other'], ['m1', 'blob-1']];
  const api = {
    storage: { get: async () => stored },
    jmap: {
      fetchBlob: async (blobId) => {
        assert.equal(blobId, 'blob-1');
        return new Uint8Array(quarantineCopy);
      },
      submitRaw: async (bytes, identityId, opts) => {
        calls.submit.push({ bytes: Buffer.from(bytes), identityId, opts });
        if (options.submitError) throw options.submitError;
        return { scheduled: false, rejectedRecipients: options.rejected };
      },
      setKeyword: async (emailId, keyword) => {
        calls.keyword.push([emailId, keyword]);
      },
    },
  };
  if (options.withMove || options.withGetRaw) api.email = {};
  if (options.withMove) {
    // A shared account's trash comes first; email.move refuses it, as Bulwark does.
    let where = 'mb-inbox';
    api.mailboxes = {
      list: async () => [{ id: 'mb-inbox', role: 'inbox' }, { id: 'shared-trash', role: 'trash' }, { id: 'mb-trash', role: 'trash' }],
    };
    api.email.move = async (emailIds, mailboxId) => {
      if (mailboxId === 'shared-trash') throw new Error(`email.move: no folder with id "${mailboxId}" in this account`);
      calls.trash.push([emailIds, mailboxId]);
      // Another plugin may stop the move; email.move still resolves.
      if (!options.moveStopped) where = mailboxId;
    };
    api.email.get = async (emailId) => ({ id: emailId, mailboxIds: [where] });
  }
  if (options.withGetRaw) {
    api.email.getRaw = async (emailId) => {
      calls.getRaw.push(emailId);
      return Uint8Array.from(quarantineCopy).buffer;
    };
  }
  return { api, calls };
}

const t = (key, vars) => key + (vars ? ' ' + JSON.stringify(vars) : '');
const release = (api, extra = {}) =>
  releaseCopy(api, Object.assign(
    { emailId: 'm1', expect: EXPECT, identityId: 'identity-q', recipients: ['user@example.com'], config: CONFIG },
    extra,
  ));

test('releases the quarantine copy byte-exact to the envelope recipients, marks it and moves it to the trash', async () => {
  const headers = {
    'X-ASSP-Intended-For': 'user@example.com',
    'X-Original-To': 'ignored@example.com',
    To: 'user@example.com',
  };
  const found = findRecipients(headers, CONFIG.recipientHeaders);
  assert.deepEqual(found, { header: 'X-Assp-Intended-For', addresses: ['user@example.com'] });
  assert.deepEqual(EXPECT, { name: 'message-id', value: '<original-1@example.net>' });

  const cleaned = cleanMessage(new Uint8Array(quarantineCopy), CONFIG);
  assert.ok(Buffer.from(cleaned.bytes).equals(expectedRelease), 'cleaned copy differs from the original');
  assert.deepEqual(cleaned.strippedTags, ['PTRinvalid']);

  const { api, calls } = fakeApi({ withMove: true });
  const outcome = await release(api, { recipients: found.addresses });
  assert.equal(outcome.status, 'released');
  assert.equal(calls.submit.length, 1);
  assert.ok(calls.submit[0].bytes.equals(expectedRelease));
  assert.equal(calls.submit[0].identityId, 'identity-q');
  assert.deepEqual(calls.submit[0].opts, { envelopeRecipients: ['user@example.com'] });
  assert.deepEqual(calls.keyword, [['m1', '$label:released']]);
  // Every recipient accepted: the copy goes to the account's trash folder.
  assert.equal(outcome.trashed, true);
  assert.deepEqual(calls.trash, [[['m1'], 'mb-trash']]);
  assert.equal(describeOutcome(outcome, 'user@example.com', t).tone, 'success');

  // Bulwark without api.email.move (1.14), or the option switched off: the copy stays.
  const off = normalizeConfig({ quarantineAccount: 'quarantine@example.com', allowedDomains: 'example.com', trashAfterRelease: false });
  for (const [options, config] of [[{}, CONFIG], [{ withMove: true }, off]]) {
    const run = fakeApi(options);
    const result = await release(run.api, { config });
    assert.equal(result.status, 'released');
    assert.equal(result.trashed, false);
    assert.deepEqual(run.calls.trash, []);
  }

  // Another plugin stopped the move: the outcome says so instead of claiming the trash.
  const stopped = fakeApi({ withMove: true, moveStopped: true });
  const kept = await release(stopped.api);
  assert.equal(kept.status, 'released');
  assert.equal(kept.trashed, false);
  assert.equal(kept.trashError, 'the move was stopped');
  assert.equal(describeOutcome(kept, 'user@example.com', t).tone, 'warning');

  // A rejected recipient keeps the copy where it is.
  const partly = fakeApi({ withMove: true, rejected: [{ email: 'user@example.com', smtpReply: '550 5.1.1 unknown' }] });
  const partial = await release(partly.api);
  assert.equal(partial.status, 'partial');
  assert.deepEqual(partly.calls.trash, []);
  assert.equal(describeOutcome(partial, 'user@example.com', t).tone, 'warning');

  // A timeout leaves the outcome open: marked, so a second attempt asks first, but not moved.
  const slow = fakeApi({ withMove: true, submitError: new Error('API call jmap.submitRaw timed out after 30s') });
  const unclear = await release(slow.api);
  assert.equal(unclear.status, 'unclear');
  assert.deepEqual(slow.calls.keyword, [['m1', '$label:released']]);
  assert.deepEqual(slow.calls.trash, []);

  // Any other submit error means nothing went out.
  const broken = fakeApi({ withMove: true, submitError: new Error('Server rejected DATA') });
  await assert.rejects(release(broken.api), /Server rejected DATA/);
  assert.deepEqual(broken.calls.keyword, []);
  assert.deepEqual(broken.calls.trash, []);

  // No blobId seen yet: newer Bulwark hands over the source through api.email.getRaw.
  const viaRaw = fakeApi({ stored: [], withGetRaw: true });
  const rawOutcome = await release(viaRaw.api);
  assert.equal(rawOutcome.status, 'released');
  assert.deepEqual(viaRaw.calls.getRaw, ['m1']);
  assert.ok(viaRaw.calls.submit[0].bytes.equals(expectedRelease));
});

test('only envelope recipients in allowed domains, never an empty envelope, never another message', async () => {
  // To, Cc and Delivered-To are ignored even when configured.
  const config = normalizeConfig({
    quarantineAccount: 'quarantine@example.com',
    allowedDomains: 'example.com',
    recipientHeaders: 'To, Delivered-To, X-Envelope-To',
  });
  assert.deepEqual(config.recipientHeaders, ['X-Envelope-To']);
  assert.deepEqual(findRecipients({ To: 'user@example.com', 'Delivered-To': 'user@example.com' }, ['To', 'Delivered-To']), {
    header: null,
    addresses: [],
  });

  // Folded values, several addresses, repeated headers, mixed case.
  const found = findRecipients(
    { 'x-envelope-to': ['<One@Example.com>,\r\n\ttwo@example.com', 'three@sub.example.com'] },
    config.recipientHeaders,
  );
  assert.deepEqual(found.addresses, ['one@example.com', 'two@example.com', 'three@sub.example.com']);

  // Exact domain match only.
  assert.equal(isAllowedAddress('one@example.com', config.allowedDomains), true);
  assert.equal(isAllowedAddress('ONE@EXAMPLE.COM', config.allowedDomains), true);
  assert.equal(isAllowedAddress('three@sub.example.com', config.allowedDomains), false);
  assert.equal(isAllowedAddress('user@example.com.example.net', config.allowedDomains), false);
  assert.equal(isAllowedAddress('user@example.com>@example.net', config.allowedDomains), false);
  assert.equal(isAllowedAddress('user@example.com', []), false);

  // The quarantine account itself is never a target, though its domain is allowed.
  assert.equal(isReleaseTarget('Quarantine@Example.com', config), false);
  assert.equal(isReleaseTarget('one@example.com', config), true);

  // Several quarantine accounts: none of them is ever a target.
  const two = normalizeConfig({ quarantineAccount: 'quarantine@example.com, Quarantine2@example.org', allowedDomains: 'example.com, example.org' });
  assert.deepEqual(two.quarantineAccounts, ['quarantine@example.com', 'quarantine2@example.org']);
  assert.equal(isReleaseTarget('quarantine2@example.org', two), false);
  assert.equal(isReleaseTarget('user@example.org', two), true);

  const { api, calls } = fakeApi({ withMove: true });
  for (const recipients of [[], ['three@sub.example.com'], ['one@example.com', 'x@example.net'], ['quarantine@example.com']]) {
    await assert.rejects(release(api, { recipients, config }));
  }
  await assert.rejects(release(api, { identityId: null, recipients: ['one@example.com'], config }));

  // The loaded source belongs to another message (an id of another account,
  // say): nothing goes out under this message's recipients.
  await assert.rejects(
    release(api, { expect: shownMessageKey({ 'Message-Id': '<another@example.net>' }), recipients: ['one@example.com'], config }),
    (err) => err.code === 'MISMATCH',
  );
  // Without a Message-ID the Date identifies the message.
  assert.deepEqual(shownMessageKey({ Date: ' Tue, 14 Oct 2026\r\n 09:30:00 +0200' }), {
    name: 'date',
    value: 'Tue,14Oct202609:30:00+0200',
  });
  assert.equal(calls.submit.length, 0);
  assert.deepEqual(calls.trash, []);
});

test('the background learns blobIds only while a quarantine account is active', async () => {
  const fresh = loadPlugin();
  let active = 'user@example.com';
  const stored = {};
  const bgApi = {
    admin: {
      getAllConfig: async () => ({ quarantineAccount: 'quarantine@example.com, quarantine2@example.org', allowedDomains: 'example.com' }),
    },
    user: {
      getAccounts: async () =>
        ['user@example.com', 'quarantine@example.com', 'quarantine2@example.org'].map((email) => ({ email, isActive: email === active })),
      getIdentities: async () => [
        { id: 'id-1', email: 'quarantine@example.com' },
        { id: 'id-2', email: 'quarantine2@example.org' },
      ],
    },
    storage: {
      get: async (key) => stored[key],
      set: async (key, value) => {
        stored[key] = value;
      },
    },
    log: { warn: () => {}, info: () => {} },
  };
  const rows = [{ id: 'm1', blobId: 'b1' }, { id: 'm2', blobId: 'b2', accountId: 'other-account' }];
  const shouldShow = fresh.slots['email-banner'].shouldShow;

  await fresh.activate(bgApi);
  assert.equal(fresh.hooks.onEmailsFetched(rows), undefined);
  fresh.hooks.onRenderEmailBody({ html: '' }, { id: 'm3', blobId: 'b3' });
  await sleep(400);
  assert.equal(stored.blobIds, undefined, 'another account is active: nothing recorded');
  assert.equal(shouldShow({ email: { id: 'm1' } }), false);

  active = 'quarantine2@example.org';
  fresh.hooks.onMailboxesRefresh();
  // The list and the body are left to the host.
  assert.equal(fresh.hooks.onEmailsFetched(rows), undefined);
  assert.equal(fresh.hooks.onRenderEmailBody({ html: '' }, { id: 'm3', blobId: 'b3' }), undefined);
  await sleep(400);
  assert.deepEqual(stored.blobIds, [['m1', 'b1'], ['m3', 'b3']]);
  assert.equal(shouldShow({ email: { id: 'm1' } }), true);

  // The banner sends with the identity of the quarantine account that is open.
  const context = await loadBannerContext(bgApi);
  assert.equal(context.isQuarantine, true);
  assert.equal(context.quarantineAddress, 'quarantine2@example.org');
  assert.equal(context.identityId, 'id-2');
  active = 'user@example.com';
  assert.equal((await loadBannerContext(bgApi)).isQuarantine, false);
});

test('the subject loses only the tag the quarantine added', () => {
  const message = (head) => new Uint8Array(Buffer.from(head + '\nbody\n', 'latin1'));
  const config = normalizeConfig({});

  // The original subject already carried the tag: only one copy goes.
  const twice = cleanMessage(
    message('X-Assp-Tag: PTRinvalid\nSubject: [PTRinvalid] [PTRinvalid] Re: offer\n'),
    config,
  );
  assert.equal(Buffer.from(twice.bytes).toString('latin1'), 'Subject: [PTRinvalid] Re: offer\n\nbody\n');

  // Two tag headers, in either order.
  const both = cleanMessage(
    message('X-Assp-Tag: A\nX-Assp-Tag: B\nSubject: [A] [B] text\n'),
    config,
  );
  assert.equal(Buffer.from(both.bytes).toString('latin1'), 'Subject: text\n\nbody\n');

  // Tag not at the start, or no tag header: subject untouched.
  for (const head of ['X-Assp-Tag: SPAM\nSubject: Re: [SPAM] text\n', 'Subject: [SPAM] text\n']) {
    const out = cleanMessage(message(head), config);
    assert.equal(Buffer.from(out.bytes).toString('latin1').split('\n').find((l) => l.startsWith('Subject')),
      head.split('\n').find((l) => l.startsWith('Subject')));
  }

  // A removal pattern must not take structural headers along.
  const greedy = cleanMessage(message('From: a@example.com\nX-Assp-ID: 1\nSubject: s\n'), normalizeConfig({ removeHeaders: '*, F*, X-Assp-*' }));
  assert.equal(Buffer.from(greedy.bytes).toString('latin1'), 'From: a@example.com\nSubject: s\n\nbody\n');
});