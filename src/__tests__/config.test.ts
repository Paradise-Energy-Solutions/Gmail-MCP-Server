/**
 * Config Module Test Suite
 *
 * Verifies that CONFIG_DIR, OAUTH_PATH, and CREDENTIALS_PATH are exported as
 * non-empty strings and follow the expected naming conventions when no
 * environment variable overrides are active.
 *
 * Note: env-var override behaviour (GMAIL_CONFIG_DIR, GMAIL_OAUTH_PATH,
 * GMAIL_CREDENTIALS_PATH) is covered by the server integration tests.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import { CONFIG_DIR, OAUTH_PATH, CREDENTIALS_PATH } from '../config.js';

// ============================================================================
// CONFIG_DIR
// ============================================================================

describe('CONFIG_DIR', () => {
    it('should be a non-empty string', () => {
        assert.strictEqual(typeof CONFIG_DIR, 'string');
        assert.ok(CONFIG_DIR.length > 0, 'CONFIG_DIR must not be empty');
    });

    it('should end with .gmail-mcp when GMAIL_CONFIG_DIR is not set', () => {
        if (!process.env.GMAIL_CONFIG_DIR) {
            assert.strictEqual(
                path.basename(CONFIG_DIR),
                '.gmail-mcp',
                `Expected basename ".gmail-mcp", got "${path.basename(CONFIG_DIR)}"`,
            );
        }
    });
});

// ============================================================================
// OAUTH_PATH
// ============================================================================

describe('OAUTH_PATH', () => {
    it('should be a non-empty string', () => {
        assert.strictEqual(typeof OAUTH_PATH, 'string');
        assert.ok(OAUTH_PATH.length > 0, 'OAUTH_PATH must not be empty');
    });

    it('should end with gcp-oauth.keys.json when GMAIL_OAUTH_PATH is not set', () => {
        if (!process.env.GMAIL_OAUTH_PATH) {
            assert.strictEqual(
                path.basename(OAUTH_PATH),
                'gcp-oauth.keys.json',
                `Expected basename "gcp-oauth.keys.json", got "${path.basename(OAUTH_PATH)}"`,
            );
        }
    });
});

// ============================================================================
// CREDENTIALS_PATH
// ============================================================================

describe('CREDENTIALS_PATH', () => {
    it('should be a non-empty string', () => {
        assert.strictEqual(typeof CREDENTIALS_PATH, 'string');
        assert.ok(CREDENTIALS_PATH.length > 0, 'CREDENTIALS_PATH must not be empty');
    });

    it('should end with credentials.json when GMAIL_CREDENTIALS_PATH is not set', () => {
        if (!process.env.GMAIL_CREDENTIALS_PATH) {
            assert.strictEqual(
                path.basename(CREDENTIALS_PATH),
                'credentials.json',
                `Expected basename "credentials.json", got "${path.basename(CREDENTIALS_PATH)}"`,
            );
        }
    });

    it('should reside inside CONFIG_DIR when neither override env var is active', () => {
        if (!process.env.GMAIL_CREDENTIALS_PATH && !process.env.GMAIL_CONFIG_DIR) {
            assert.ok(
                CREDENTIALS_PATH.startsWith(CONFIG_DIR + path.sep) ||
                    CREDENTIALS_PATH.startsWith(CONFIG_DIR + '/'),
                `CREDENTIALS_PATH "${CREDENTIALS_PATH}" should be inside CONFIG_DIR "${CONFIG_DIR}"`,
            );
        }
    });
});
