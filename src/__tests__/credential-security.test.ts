/**
 * Credential Security Module Test Suite
 * Tests for credential handling and OAuth security in credential-security.ts
 */

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
    enforceCredentialPermissions,
    checkCredentialPermissions,
    auditCredentialFilePermissions,
    validateOAuthKeysStructure,
    validateCredentialsStructure,
    loadCredentialsFromEnv,
    checkEnvVarsPresent,
    loadCredentialsSecurely,
    checkTokenExpiration,
    shouldRefreshToken,
    sanitizeErrorMessage,
    sanitizePathForLogging,
    createSafeAuthError,
    handleAuthError,
    performSecurityAudit,
    validateScopes,
    getScopesForPreset,
    ENV_VAR_NAMES,
    OAUTH_SCOPES,
    GMAIL_SCOPES,
    DEFAULT_REFRESH_THRESHOLD_MS,
} from '../credential-security.js';

// ============================================================================
// Test Fixtures and Helpers
// ============================================================================

let testDir: string;
let testOAuthKeysPath: string;
let testCredentialsPath: string;

// Helper to save and restore env vars
function withEnvVars(vars: Record<string, string | undefined>, fn: () => void): void {
    const saved: Record<string, string | undefined> = {};
    
    // Save current values
    for (const key of Object.keys(vars)) {
        saved[key] = process.env[key];
    }
    
    // Set test values
    for (const [key, value] of Object.entries(vars)) {
        if (value === undefined) {
            delete process.env[key];
        } else {
            process.env[key] = value;
        }
    }
    
    try {
        fn();
    } finally {
        // Restore original values
        for (const [key, value] of Object.entries(saved)) {
            if (value === undefined) {
                delete process.env[key];
            } else {
                process.env[key] = value;
            }
        }
    }
}

// ============================================================================
// File Permission Tests
// ============================================================================

describe('File Permission Management', () => {
    before(() => {
        testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-test-'));
        testOAuthKeysPath = path.join(testDir, 'oauth_keys.json');
        testCredentialsPath = path.join(testDir, 'credentials.json');
    });

    after(() => {
        // Cleanup test directory
        if (fs.existsSync(testDir)) {
            fs.rmSync(testDir, { recursive: true });
        }
    });

    describe('checkCredentialPermissions', () => {
        it('should return true for non-existent file', () => {
            const result = checkCredentialPermissions('/nonexistent/path/file.json');
            assert.strictEqual(result, true);
        });

        it('should return true for file with 0600 permissions', () => {
            const testFile = path.join(testDir, 'secure-file.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o600 });
            
            const result = checkCredentialPermissions(testFile);
            assert.strictEqual(result, true);
            
            fs.unlinkSync(testFile);
        });

        it('should return false for file with group read permissions', () => {
            const testFile = path.join(testDir, 'insecure-file.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o640 });
            
            const result = checkCredentialPermissions(testFile);
            assert.strictEqual(result, false);
            
            fs.unlinkSync(testFile);
        });

        it('should return false for world-readable file', () => {
            const testFile = path.join(testDir, 'world-readable.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o644 });
            
            const result = checkCredentialPermissions(testFile);
            assert.strictEqual(result, false);
            
            fs.unlinkSync(testFile);
        });
    });

    describe('enforceCredentialPermissions', () => {
        it('should return false for non-existent file', () => {
            const result = enforceCredentialPermissions('/nonexistent/path/file.json');
            assert.strictEqual(result, false);
        });

        it('should set permissions to 0600', () => {
            const testFile = path.join(testDir, 'to-fix.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o644 });
            
            const result = enforceCredentialPermissions(testFile);
            assert.strictEqual(result, true);
            
            const stats = fs.statSync(testFile);
            assert.strictEqual(stats.mode & 0o777, 0o600);
            
            fs.unlinkSync(testFile);
        });
    });

    describe('auditCredentialFilePermissions', () => {
        it('should return empty array for non-existent file', () => {
            const warnings = auditCredentialFilePermissions('/nonexistent/file.json');
            assert.strictEqual(warnings.length, 0);
        });

        it('should return empty array for secure file', () => {
            const testFile = path.join(testDir, 'audit-secure.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o600 });
            
            const warnings = auditCredentialFilePermissions(testFile);
            assert.strictEqual(warnings.length, 0);
            
            fs.unlinkSync(testFile);
        });

        it('should warn about group permissions', () => {
            const testFile = path.join(testDir, 'audit-group.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o640 });
            
            const warnings = auditCredentialFilePermissions(testFile);
            assert.ok(warnings.some(w => w.includes('group')));
            
            fs.unlinkSync(testFile);
        });

        it('should warn critically about world-readable files', () => {
            const testFile = path.join(testDir, 'audit-world.json');
            fs.writeFileSync(testFile, '{}', { mode: 0o644 });
            
            const warnings = auditCredentialFilePermissions(testFile);
            assert.ok(warnings.some(w => w.includes('world-readable') || w.includes('CRITICAL')));
            
            fs.unlinkSync(testFile);
        });
    });
});

// ============================================================================
// OAuth Keys Structure Validation Tests
// ============================================================================

describe('OAuth Keys Validation', () => {
    describe('validateOAuthKeysStructure', () => {
        it('should accept valid installed credentials', () => {
            const content = {
                installed: {
                    client_id: 'test-id.apps.googleusercontent.com',
                    client_secret: 'test-secret',
                    redirect_uris: ['http://localhost:8080'],
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.errors.length, 0);
        });

        it('should accept valid web credentials', () => {
            const content = {
                web: {
                    client_id: 'test-id.apps.googleusercontent.com',
                    client_secret: 'test-secret',
                    redirect_uris: ['https://example.com/callback'],
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, true);
        });

        it('should reject null content', () => {
            const result = validateOAuthKeysStructure(null);
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(e => e.includes('empty')));
        });

        it('should reject missing installed/web object', () => {
            const content = { other: {} };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(e => e.includes('installed') || e.includes('web')));
        });

        it('should reject missing client_id', () => {
            const content = {
                installed: {
                    client_secret: 'test-secret',
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(e => e.includes('client_id')));
        });

        it('should reject missing client_secret', () => {
            const content = {
                installed: {
                    client_id: 'test-id.apps.googleusercontent.com',
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, false);
            assert.ok(result.errors.some(e => e.includes('client_secret')));
        });

        it('should warn about invalid client_id format', () => {
            const content = {
                installed: {
                    client_id: 'invalid-format',
                    client_secret: 'test-secret',
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.strictEqual(result.valid, true); // Still valid but with warning
            assert.ok(result.warnings.some(w => w.includes('client_id')));
        });

        it('should warn about missing redirect_uris', () => {
            const content = {
                installed: {
                    client_id: 'test-id.apps.googleusercontent.com',
                    client_secret: 'test-secret',
                },
            };
            
            const result = validateOAuthKeysStructure(content);
            assert.ok(result.warnings.some(w => w.includes('redirect_uris')));
        });
    });

    describe('validateCredentialsStructure', () => {
        it('should accept valid credentials with all tokens', () => {
            const content = {
                access_token: 'ya29.test-access-token',
                refresh_token: '1//test-refresh-token',
                expiry_date: Date.now() + 3600000,
            };
            
            const result = validateCredentialsStructure(content);
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.errors.length, 0);
        });

        it('should reject null content', () => {
            const result = validateCredentialsStructure(null);
            assert.strictEqual(result.valid, false);
        });

        it('should warn about missing refresh_token', () => {
            const content = {
                access_token: 'ya29.test-access-token',
            };
            
            const result = validateCredentialsStructure(content);
            assert.ok(result.warnings.some(w => w.includes('refresh_token')));
        });

        it('should warn about missing access_token', () => {
            const content = {
                refresh_token: '1//test-refresh-token',
            };
            
            const result = validateCredentialsStructure(content);
            assert.ok(result.warnings.some(w => w.includes('access_token')));
        });

        it('should warn about expired token', () => {
            const content = {
                access_token: 'ya29.test-access-token',
                refresh_token: '1//test-refresh-token',
                expiry_date: Date.now() - 3600000, // 1 hour ago
            };
            
            const result = validateCredentialsStructure(content);
            assert.ok(result.warnings.some(w => w.includes('expired')));
        });

        it('should warn about invalid expiry_date type', () => {
            const content = {
                access_token: 'ya29.test-access-token',
                expiry_date: 'not-a-number',
            };
            
            const result = validateCredentialsStructure(content);
            assert.ok(result.warnings.some(w => w.includes('expiry_date')));
        });
    });
});

// ============================================================================
// Environment Variable Loading Tests
// ============================================================================

describe('Environment Variable Loading', () => {
    describe('loadCredentialsFromEnv', () => {
        afterEach(() => {
            // Clean up env vars after each test
            delete process.env[ENV_VAR_NAMES.CLIENT_ID];
            delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
            delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
            delete process.env[ENV_VAR_NAMES.ACCESS_TOKEN];
            delete process.env[ENV_VAR_NAMES.EXPIRY_DATE];
        });

        it('should return null when required vars are missing', () => {
            const result = loadCredentialsFromEnv();
            assert.strictEqual(result, null);
        });

        it('should load credentials when all required vars present', () => {
            withEnvVars({
                [ENV_VAR_NAMES.CLIENT_ID]: 'test-client-id',
                [ENV_VAR_NAMES.CLIENT_SECRET]: 'test-secret',
                [ENV_VAR_NAMES.REFRESH_TOKEN]: 'test-refresh',
            }, () => {
                const result = loadCredentialsFromEnv();
                assert.ok(result);
                assert.strictEqual(result.clientId, 'test-client-id');
                assert.strictEqual(result.clientSecret, 'test-secret');
                assert.strictEqual(result.refreshToken, 'test-refresh');
            });
        });

        it('should include optional access token when present', () => {
            withEnvVars({
                [ENV_VAR_NAMES.CLIENT_ID]: 'test-client-id',
                [ENV_VAR_NAMES.CLIENT_SECRET]: 'test-secret',
                [ENV_VAR_NAMES.REFRESH_TOKEN]: 'test-refresh',
                [ENV_VAR_NAMES.ACCESS_TOKEN]: 'test-access',
            }, () => {
                const result = loadCredentialsFromEnv();
                assert.ok(result);
                assert.strictEqual(result.accessToken, 'test-access');
            });
        });

        it('should parse expiry date as number', () => {
            const expiryDate = Date.now() + 3600000;
            withEnvVars({
                [ENV_VAR_NAMES.CLIENT_ID]: 'test-client-id',
                [ENV_VAR_NAMES.CLIENT_SECRET]: 'test-secret',
                [ENV_VAR_NAMES.REFRESH_TOKEN]: 'test-refresh',
                [ENV_VAR_NAMES.EXPIRY_DATE]: expiryDate.toString(),
            }, () => {
                const result = loadCredentialsFromEnv();
                assert.ok(result);
                assert.strictEqual(result.expiryDate, expiryDate);
            });
        });

        it('should ignore invalid expiry date', () => {
            withEnvVars({
                [ENV_VAR_NAMES.CLIENT_ID]: 'test-client-id',
                [ENV_VAR_NAMES.CLIENT_SECRET]: 'test-secret',
                [ENV_VAR_NAMES.REFRESH_TOKEN]: 'test-refresh',
                [ENV_VAR_NAMES.EXPIRY_DATE]: 'not-a-number',
            }, () => {
                const result = loadCredentialsFromEnv();
                assert.ok(result);
                assert.strictEqual(result.expiryDate, undefined);
            });
        });
    });

    describe('checkEnvVarsPresent', () => {
        afterEach(() => {
            delete process.env[ENV_VAR_NAMES.CLIENT_ID];
            delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
            delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
        });

        it('should return object with boolean values', () => {
            const result = checkEnvVarsPresent();
            assert.strictEqual(typeof result[ENV_VAR_NAMES.CLIENT_ID], 'boolean');
            assert.strictEqual(typeof result[ENV_VAR_NAMES.CLIENT_SECRET], 'boolean');
        });

        it('should correctly detect present vars', () => {
            withEnvVars({
                [ENV_VAR_NAMES.CLIENT_ID]: 'test-id',
            }, () => {
                const result = checkEnvVarsPresent();
                assert.strictEqual(result[ENV_VAR_NAMES.CLIENT_ID], true);
                assert.strictEqual(result[ENV_VAR_NAMES.CLIENT_SECRET], false);
            });
        });
    });
});

// ============================================================================
// Token Expiration Tests
// ============================================================================

describe('Token Expiration Checking', () => {
    describe('checkTokenExpiration', () => {
        it('should return expired for undefined expiry', () => {
            const result = checkTokenExpiration(undefined);
            assert.strictEqual(result.isExpired, true);
            assert.strictEqual(result.isNearExpiry, true);
            assert.strictEqual(result.msUntilExpiry, null);
        });

        it('should return expired for past date', () => {
            const pastDate = Date.now() - 3600000; // 1 hour ago
            const result = checkTokenExpiration(pastDate);
            assert.strictEqual(result.isExpired, true);
            assert.strictEqual(result.msUntilExpiry, 0);
        });

        it('should return not expired for future date', () => {
            const futureDate = Date.now() + 3600000; // 1 hour from now
            const result = checkTokenExpiration(futureDate);
            assert.strictEqual(result.isExpired, false);
            assert.ok(result.msUntilExpiry! > 0);
        });

        it('should detect near expiry within threshold', () => {
            const nearExpiry = Date.now() + 60000; // 1 minute from now
            const result = checkTokenExpiration(nearExpiry, DEFAULT_REFRESH_THRESHOLD_MS);
            assert.strictEqual(result.isExpired, false);
            assert.strictEqual(result.isNearExpiry, true);
        });

        it('should not flag near expiry when well within threshold', () => {
            const safeExpiry = Date.now() + 3600000; // 1 hour from now
            const result = checkTokenExpiration(safeExpiry, DEFAULT_REFRESH_THRESHOLD_MS);
            assert.strictEqual(result.isExpired, false);
            assert.strictEqual(result.isNearExpiry, false);
        });
    });

    describe('shouldRefreshToken', () => {
        it('should return true for undefined expiry', () => {
            assert.strictEqual(shouldRefreshToken(undefined), true);
        });

        it('should return true for expired token', () => {
            const expired = Date.now() - 1000;
            assert.strictEqual(shouldRefreshToken(expired), true);
        });

        it('should return true for near-expiry token', () => {
            const nearExpiry = Date.now() + 60000; // 1 minute
            assert.strictEqual(shouldRefreshToken(nearExpiry, 5 * 60 * 1000), true);
        });

        it('should return false for valid token with time remaining', () => {
            const valid = Date.now() + 3600000; // 1 hour
            assert.strictEqual(shouldRefreshToken(valid, 5 * 60 * 1000), false);
        });

        it('should respect custom threshold', () => {
            const token = Date.now() + 120000; // 2 minutes
            assert.strictEqual(shouldRefreshToken(token, 60000), false); // 1 min threshold
            assert.strictEqual(shouldRefreshToken(token, 180000), true); // 3 min threshold
        });
    });
});

// ============================================================================
// Error Message Sanitization Tests
// ============================================================================

describe('Error Message Sanitization', () => {
    describe('sanitizeErrorMessage', () => {
        it('should sanitize file paths', () => {
            const message = 'Error loading /home/user/.credentials/oauth.json';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('/home/user'));
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should sanitize Bearer tokens', () => {
            const message = 'Authorization failed: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.signature';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('eyJ'));
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should sanitize Google access tokens (ya29.*)', () => {
            const message = 'Token ya29.a0ARrdaM8xyz123 is invalid';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('ya29.'));
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should sanitize refresh tokens', () => {
            const message = 'Refresh token 1//0xyz-abc_123 expired';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('1//'));
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should sanitize client secrets (GOCSPX-*)', () => {
            const message = 'Invalid client_secret: GOCSPX-abc123xyz456';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('GOCSPX-'));
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should sanitize API keys', () => {
            // API key pattern requires exactly 35 chars after 'AIza' (AIza[4] + 35 = 39 total)
            const message = 'API key AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ123456789 is invalid';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('AIza'), `Expected API key to be sanitized, got: ${sanitized}`);
            assert.ok(sanitized.includes('[REDACTED]'));
        });

        it('should preserve non-sensitive parts of message', () => {
            const message = 'Error occurred while processing request';
            const sanitized = sanitizeErrorMessage(message);
            assert.strictEqual(sanitized, message);
        });

        it('should handle Windows paths', () => {
            const message = 'Cannot read file C:\\Users\\Admin\\credentials.json';
            const sanitized = sanitizeErrorMessage(message);
            assert.ok(!sanitized.includes('C:\\Users'));
        });
    });

    describe('sanitizePathForLogging', () => {
        it('should extract filename from path', () => {
            const result = sanitizePathForLogging('/home/user/docs/file.txt');
            assert.ok(result.includes('file.txt'));
        });

        it('should mark credential files specially', () => {
            const result = sanitizePathForLogging('/home/user/.credentials/oauth.json');
            assert.ok(result.includes('credential-file'));
            assert.ok(result.includes('oauth.json'));
        });

        it('should handle .key files', () => {
            const result = sanitizePathForLogging('/etc/ssl/private.key');
            assert.ok(result.includes('credential-file'));
        });

        it('should handle .pem files', () => {
            const result = sanitizePathForLogging('/certs/server.pem');
            assert.ok(result.includes('credential-file'));
        });

        it('should return placeholder for empty path', () => {
            // path.basename('') returns '' so result is '[file:]'
            const result = sanitizePathForLogging('');
            assert.strictEqual(result, '[file:]');
        });
    });

    describe('createSafeAuthError', () => {
        it('should return both external and internal messages', () => {
            const error = new Error('Failed to load /home/user/secret.json');
            const result = createSafeAuthError(error, 'token_refresh');
            
            assert.ok(result.external);
            assert.ok(result.internal);
            assert.ok(!result.external.includes('/home/user'));
            assert.ok(result.internal.includes('token_refresh'));
        });

        it('should handle non-Error objects', () => {
            const result = createSafeAuthError('string error', 'test_context');
            assert.ok(result.external.includes('test_context'));
        });

        it('should include context in external message', () => {
            const error = new Error('Test error');
            const result = createSafeAuthError(error, 'credential_load');
            assert.ok(result.external.includes('credential_load'));
        });
    });

    describe('handleAuthError', () => {
        it('should return sanitized message', () => {
            const error = new Error('Token ya29.secret123 is invalid');
            const result = handleAuthError(error, 'test');
            assert.ok(!result.includes('ya29.'));
            assert.ok(result.includes('[REDACTED]'));
        });
    });
});

// ============================================================================
// OAuth Scope Validation Tests
// ============================================================================

describe('OAuth Scope Management', () => {
    describe('validateScopes', () => {
        it('should accept known Gmail scopes', () => {
            const result = validateScopes([
                GMAIL_SCOPES.READONLY,
                GMAIL_SCOPES.SEND,
            ]);
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.unknownScopes.length, 0);
        });

        it('should reject unknown scopes', () => {
            const result = validateScopes([
                GMAIL_SCOPES.READONLY,
                'https://www.googleapis.com/auth/unknown.scope',
            ]);
            assert.strictEqual(result.valid, false);
            assert.strictEqual(result.unknownScopes.length, 1);
            assert.ok(result.unknownScopes.includes('https://www.googleapis.com/auth/unknown.scope'));
        });

        it('should accept empty array', () => {
            const result = validateScopes([]);
            assert.strictEqual(result.valid, true);
        });
    });

    describe('getScopesForPreset', () => {
        it('should return MINIMAL scopes', () => {
            const scopes = getScopesForPreset('MINIMAL');
            assert.ok(Array.isArray(scopes));
            assert.ok(scopes.includes(GMAIL_SCOPES.READONLY));
        });

        it('should return STANDARD scopes', () => {
            const scopes = getScopesForPreset('STANDARD');
            assert.ok(scopes.includes(GMAIL_SCOPES.READONLY));
            assert.ok(scopes.includes(GMAIL_SCOPES.SEND));
        });

        it('should return FULL scopes', () => {
            const scopes = getScopesForPreset('FULL');
            assert.ok(scopes.includes(GMAIL_SCOPES.MODIFY));
        });

        it('should return copy of scopes (not reference)', () => {
            const scopes1 = getScopesForPreset('MINIMAL');
            const scopes2 = getScopesForPreset('MINIMAL');
            assert.notStrictEqual(scopes1, scopes2);
        });
    });

    describe('OAUTH_SCOPES constants', () => {
        it('should have valid Gmail API URLs', () => {
            for (const preset of Object.values(OAUTH_SCOPES)) {
                for (const scope of preset) {
                    assert.ok(scope.startsWith('https://www.googleapis.com/auth/gmail'));
                }
            }
        });
    });
});

// ============================================================================
// Security Audit Tests
// ============================================================================

describe('Security Audit', () => {
    let auditTestDir: string;

    before(() => {
        // Use __dirname to avoid /tmp which is flagged as insecure
        auditTestDir = fs.mkdtempSync(path.join(path.dirname(import.meta.url.replace('file://', '')), '.audit-test-'));
    });

    after(() => {
        if (fs.existsSync(auditTestDir)) {
            fs.rmSync(auditTestDir, { recursive: true });
        }
    });

    describe('performSecurityAudit', () => {
        it('should pass for secure configuration', () => {
            const oauthPath = path.join(auditTestDir, 'secure-oauth.json');
            const credPath = path.join(auditTestDir, 'secure-cred.json');
            
            fs.writeFileSync(oauthPath, '{}', { mode: 0o600 });
            fs.writeFileSync(credPath, '{}', { mode: 0o600 });
            
            const result = performSecurityAudit(oauthPath, credPath);
            // Files are in a safe location with correct permissions
            assert.strictEqual(result.secure, true, `Expected secure=true, got warnings: ${JSON.stringify(result.warnings)}`);
            assert.strictEqual(result.warnings.length, 0, `Unexpected warnings: ${JSON.stringify(result.warnings)}`);
        });

        it('should warn about insecure OAuth keys permissions', () => {
            const oauthPath = path.join(auditTestDir, 'insecure-oauth.json');
            const credPath = path.join(auditTestDir, 'secure-cred2.json');
            
            fs.writeFileSync(oauthPath, '{}', { mode: 0o644 });
            fs.writeFileSync(credPath, '{}', { mode: 0o600 });
            
            const result = performSecurityAudit(oauthPath, credPath);
            assert.strictEqual(result.secure, false);
            assert.ok(result.warnings.some(w => w.includes('OAuth')));
        });

        it('should recommend environment variables', () => {
            const oauthPath = path.join(auditTestDir, 'oauth3.json');
            const credPath = path.join(auditTestDir, 'cred3.json');
            
            fs.writeFileSync(oauthPath, '{}', { mode: 0o600 });
            fs.writeFileSync(credPath, '{}', { mode: 0o600 });
            
            // Ensure env vars are not set
            delete process.env[ENV_VAR_NAMES.CLIENT_ID];
            delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
            delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
            
            const result = performSecurityAudit(oauthPath, credPath);
            assert.ok(result.recommendations.some(r => r.includes('environment')));
        });

        it('should handle non-existent files gracefully', () => {
            const result = performSecurityAudit('/nonexistent/oauth.json', '/nonexistent/cred.json');
            assert.strictEqual(result.secure, true);
        });
    });
});

// ============================================================================
// Secure Credential Loading Integration Tests
// ============================================================================

describe('Secure Credential Loading', () => {
    let loadTestDir: string;

    before(() => {
        loadTestDir = fs.mkdtempSync(path.join(os.tmpdir(), 'load-test-'));
    });

    after(() => {
        if (fs.existsSync(loadTestDir)) {
            fs.rmSync(loadTestDir, { recursive: true });
        }
        // Clean up env vars
        delete process.env[ENV_VAR_NAMES.CLIENT_ID];
        delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
        delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
    });

    it('should prefer environment variables over files', () => {
        const oauthPath = path.join(loadTestDir, 'oauth-load.json');
        const credPath = path.join(loadTestDir, 'cred-load.json');
        
        // Create valid files
        fs.writeFileSync(oauthPath, JSON.stringify({
            installed: {
                client_id: 'file-id.apps.googleusercontent.com',
                client_secret: 'file-secret',
            },
        }), { mode: 0o600 });
        
        // Set env vars
        process.env[ENV_VAR_NAMES.CLIENT_ID] = 'env-id';
        process.env[ENV_VAR_NAMES.CLIENT_SECRET] = 'env-secret';
        process.env[ENV_VAR_NAMES.REFRESH_TOKEN] = 'env-refresh';
        
        const result = loadCredentialsSecurely(oauthPath, credPath);
        
        assert.strictEqual(result.source, 'environment');
        assert.strictEqual(result.credentials?.clientId, 'env-id');
        
        // Clean up
        delete process.env[ENV_VAR_NAMES.CLIENT_ID];
        delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
        delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
    });

    it('should fall back to files when env vars missing', () => {
        const oauthPath = path.join(loadTestDir, 'oauth-fallback.json');
        const credPath = path.join(loadTestDir, 'cred-fallback.json');
        
        // Ensure env vars are not set
        delete process.env[ENV_VAR_NAMES.CLIENT_ID];
        delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
        delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
        
        // Create valid files
        fs.writeFileSync(oauthPath, JSON.stringify({
            installed: {
                client_id: 'file-id.apps.googleusercontent.com',
                client_secret: 'file-secret',
            },
        }), { mode: 0o600 });
        
        fs.writeFileSync(credPath, JSON.stringify({
            refresh_token: 'file-refresh',
        }), { mode: 0o600 });
        
        const result = loadCredentialsSecurely(oauthPath, credPath);
        
        assert.strictEqual(result.source, 'file');
        assert.strictEqual(result.credentials?.clientId, 'file-id.apps.googleusercontent.com');
        assert.strictEqual(result.credentials?.refreshToken, 'file-refresh');
    });

    it('should return none when files missing and no env vars', () => {
        delete process.env[ENV_VAR_NAMES.CLIENT_ID];
        delete process.env[ENV_VAR_NAMES.CLIENT_SECRET];
        delete process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
        
        const result = loadCredentialsSecurely('/nonexistent/oauth.json', '/nonexistent/cred.json');
        
        assert.strictEqual(result.source, 'none');
        assert.strictEqual(result.credentials, null);
    });
});
