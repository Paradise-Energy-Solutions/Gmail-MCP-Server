/**
 * Gmail Draft Integration Test
 *
 * Creates REAL Gmail drafts via the Gmail API and verifies their MIME
 * structure.  Three scenarios are covered:
 *   1. Inline CID image only
 *   2. File attachment only
 *   3. Inline CID image + file attachment together
 *
 * Each draft is deleted in the after() hook so no artefacts are left in
 * the mailbox.
 *
 * ── Opt-in guard ─────────────────────────────────────────────────────────────
 * These tests are SKIPPED by default to prevent accidental side-effects in CI
 * environments that lack Gmail credentials.  To run them:
 *
 *   GMAIL_INTEGRATION=1 node --test dist/__tests__/gmail-draft-integration.test.js
 *
 * The test also checks for the two credential files at the paths used by the
 * production server (overrideable with the same env vars):
 *   • GMAIL_CREDENTIALS_PATH  (default: ~/.gmail-mcp/credentials.json)
 *   • GMAIL_OAUTH_PATH        (default: ~/.gmail-mcp/gcp-oauth.keys.json)
 *
 * Account under test: aegbert@paradiseenergysolutions.com
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { google, gmail_v1 } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import { createEmailWithNodemailer } from '../utl.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const ACCOUNT = 'aegbert@paradiseenergysolutions.com';
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const CREDENTIALS_PATH =
    process.env.GMAIL_CREDENTIALS_PATH ?? path.join(CONFIG_DIR, 'credentials.json');
const OAUTH_PATH =
    process.env.GMAIL_OAUTH_PATH ?? path.join(CONFIG_DIR, 'gcp-oauth.keys.json');

// ── Opt-in skip check ─────────────────────────────────────────────────────────

function resolveSkipReason(): string | false {
    if (process.env.GMAIL_INTEGRATION !== '1') {
        return 'Set GMAIL_INTEGRATION=1 to run live Gmail API integration tests';
    }
    if (!fs.existsSync(CREDENTIALS_PATH)) {
        return `OAuth credentials not found at: ${CREDENTIALS_PATH}`;
    }
    if (!fs.existsSync(OAUTH_PATH)) {
        return `OAuth keys not found at: ${OAUTH_PATH}`;
    }
    return false;
}

const SKIP_REASON = resolveSkipReason();

// ── Fixture data ──────────────────────────────────────────────────────────────

/**
 * Minimal 1×1 transparent PNG (valid per the PNG spec; useful as the smallest
 * possible image fixture without depending on an external file at rest).
 */
const TINY_TRANSPARENT_PNG_B64 =
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

const HTML_BODY_WITH_CID = `<!DOCTYPE html>
<html>
<body>
  <p>Integration test email — inline image below (safe to delete):</p>
  <img src="cid:test-logo" alt="Logo" width="1" height="1" />
</body>
</html>`;

const TEXT_ATTACHMENT_CONTENT = '[INTEGRATION TEST] This attachment was created by an automated test and is safe to delete.';

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Build an authenticated OAuth2Client from the local credential files.
 */
function buildOAuth2Client(): OAuth2Client {
    const keysFile = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
    const keys = keysFile.installed ?? keysFile.web;
    const client = new OAuth2Client(
        keys.client_id,
        keys.client_secret,
        'http://localhost:3000/oauth2callback',
    );
    const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
    client.setCredentials(credentials);
    return client;
}

/**
 * Base64url-encode a raw RFC 2822 message string for the Gmail API.
 */
function base64UrlEncode(raw: string): string {
    return Buffer.from(raw)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Upload a raw MIME message as a Gmail draft and return the new draft ID.
 * Asserts that the API returned a non-empty ID.
 */
async function createDraft(
    gmail: gmail_v1.Gmail,
    rawMessage: string,
): Promise<string> {
    const response = await gmail.users.drafts.create({
        userId: 'me',
        requestBody: { message: { raw: base64UrlEncode(rawMessage) } },
    });
    const draftId = response.data.id;
    assert.ok(draftId, 'gmail.users.drafts.create must return a non-empty draft ID');
    return draftId!;
}

/**
 * Delete a draft by ID.  Errors are swallowed so cleanup never masks test failures.
 */
async function deleteDraftSafely(gmail: gmail_v1.Gmail, draftId: string): Promise<void> {
    try {
        await gmail.users.drafts.delete({ userId: 'me', id: draftId });
    } catch {
        // Best-effort cleanup — test results already determined at this point
    }
}

/**
 * Recursively collect all non-empty `filename` values from a MIME part tree.
 * Used to verify that specific attachment filenames appear in a draft's payload.
 */
function collectPartFilenames(
    parts: gmail_v1.Schema$MessagePart[],
): string[] {
    const names: string[] = [];
    for (const part of parts) {
        if (part.filename) {
            names.push(part.filename);
        }
        if (part.parts?.length) {
            names.push(...collectPartFilenames(part.parts));
        }
    }
    return names;
}

// ── Test Suite ────────────────────────────────────────────────────────────────

describe(
    'Gmail Draft Integration — inline images and attachments',
    { skip: SKIP_REASON || undefined },
    () => {
        let gmail: gmail_v1.Gmail;
        let tempDir: string;
        let pngPath: string;
        let attachmentPath: string;

        /** IDs of every draft created during this run, collected for cleanup. */
        const createdDraftIds: string[] = [];

        before(() => {
            // Build the authenticated Gmail client
            const oauth2Client = buildOAuth2Client();
            gmail = google.gmail({ version: 'v1', auth: oauth2Client });

            // Write fixture files to a fresh temp directory
            tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-draft-integration-'));

            pngPath = path.join(tempDir, 'test-logo.png');
            fs.writeFileSync(pngPath, Buffer.from(TINY_TRANSPARENT_PNG_B64, 'base64'));

            attachmentPath = path.join(tempDir, 'test-attachment.txt');
            fs.writeFileSync(attachmentPath, TEXT_ATTACHMENT_CONTENT, 'utf8');

            // Allow createEmailWithNodemailer to read from the temp dir
            process.env.GMAIL_MCP_ALLOWED_READ_PATH = tempDir;
        });

        after(async () => {
            // Delete every draft created in this run
            for (const id of createdDraftIds) {
                await deleteDraftSafely(gmail, id);
            }

            // Remove fixture files
            if (tempDir) {
                fs.rmSync(tempDir, { recursive: true, force: true });
            }
        });

        // ── Test 1: inline CID image ─────────────────────────────────────────

        it('creates a draft embedding an inline CID image', async () => {
            const rawMessage = await createEmailWithNodemailer({
                to: [ACCOUNT],
                subject: '[INTEGRATION TEST] Inline image draft — safe to delete',
                body: 'This email should contain an inline image (plain-text fallback).',
                htmlBody: HTML_BODY_WITH_CID,
                mimeType: 'multipart/alternative',
                inline_images: [
                    { source: pngPath, content_id: 'test-logo', mime_type: 'image/png' },
                ],
            });

            const draftId = await createDraft(gmail, rawMessage);
            createdDraftIds.push(draftId);

            // Fetch the stored draft and inspect its top-level MIME type
            const { data } = await gmail.users.drafts.get({ userId: 'me', id: draftId });
            const topMimeType = data.message?.payload?.mimeType ?? '';
            assert.ok(
                topMimeType.startsWith('multipart/'),
                `Expected a multipart/* top-level MIME type; got: '${topMimeType}'`,
            );
        });

        // ── Test 2: file attachment ──────────────────────────────────────────

        it('creates a draft with a plain-text file attachment', async () => {
            const rawMessage = await createEmailWithNodemailer({
                to: [ACCOUNT],
                subject: '[INTEGRATION TEST] Attachment draft — safe to delete',
                body: 'This email has a plain-text file attachment.',
                mimeType: 'multipart/mixed',
                attachments: [attachmentPath],
            });

            const draftId = await createDraft(gmail, rawMessage);
            createdDraftIds.push(draftId);

            const { data } = await gmail.users.drafts.get({ userId: 'me', id: draftId });
            const topMimeType = data.message?.payload?.mimeType ?? '';
            assert.ok(
                topMimeType.startsWith('multipart/'),
                `Expected a multipart/* top-level MIME type; got: '${topMimeType}'`,
            );

            const parts = data.message?.payload?.parts ?? [];
            const filenames = collectPartFilenames(parts);
            assert.ok(
                filenames.includes('test-attachment.txt'),
                `Expected 'test-attachment.txt' among draft part filenames; found: [${filenames.join(', ')}]`,
            );
        });

        // ── Test 3: inline image + file attachment ───────────────────────────

        it('creates a draft with both an inline CID image and a file attachment', async () => {
            const rawMessage = await createEmailWithNodemailer({
                to: [ACCOUNT],
                subject: '[INTEGRATION TEST] Inline + attachment draft — safe to delete',
                body: 'This email has both an inline image and a file attachment.',
                htmlBody: HTML_BODY_WITH_CID,
                mimeType: 'multipart/alternative',
                inline_images: [
                    { source: pngPath, content_id: 'test-logo', mime_type: 'image/png' },
                ],
                attachments: [attachmentPath],
            });

            const draftId = await createDraft(gmail, rawMessage);
            createdDraftIds.push(draftId);

            const { data } = await gmail.users.drafts.get({ userId: 'me', id: draftId });
            const topMimeType = data.message?.payload?.mimeType ?? '';
            assert.ok(
                topMimeType.startsWith('multipart/'),
                `Expected a multipart/* top-level MIME type; got: '${topMimeType}'`,
            );

            const parts = data.message?.payload?.parts ?? [];
            const filenames = collectPartFilenames(parts);
            assert.ok(
                filenames.includes('test-attachment.txt'),
                `Expected 'test-attachment.txt' among draft part filenames; found: [${filenames.join(', ')}]`,
            );
        });
    },
);
