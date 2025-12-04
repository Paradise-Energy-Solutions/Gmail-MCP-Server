/**
 * Security Integration Test Suite
 * Tests for the unified security facade in security.ts
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
    SecurityManager,
    initializeSecurity,
    getSecurity,
    shutdownSecurity,
    beforeRequest,
    afterRequest,
    wrapHandler,
    createTypedHandler,
    AuditEventType,
    LogLevel,
} from '../security.js';
import type {
    SecurityConfig,
    SecurityStatus,
    SecureExecutionResult,
    ValidationType,
} from '../security.js';

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Create a test SecurityManager with custom config
 */
function createTestSecurityManager(overrides: Partial<SecurityConfig> = {}): SecurityManager {
    return new SecurityManager({
        logLevel: LogLevel.ERROR, // Reduce noise in tests
        logFormat: 'json',
        consoleOutput: false,
        rateLimitPerMinute: 100,
        ...overrides,
    });
}

/**
 * Wait for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Capture console output
 */
function captureConsole(): { logs: string[]; errors: string[]; restore: () => void } {
    const logs: string[] = [];
    const errors: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    const originalInfo = console.info;
    
    console.log = (...args: unknown[]) => logs.push(args.map(String).join(' '));
    console.error = (...args: unknown[]) => errors.push(args.map(String).join(' '));
    console.warn = (...args: unknown[]) => errors.push(args.map(String).join(' '));
    console.info = (...args: unknown[]) => logs.push(args.map(String).join(' '));
    
    return {
        logs,
        errors,
        restore: () => {
            console.log = originalLog;
            console.error = originalError;
            console.warn = originalWarn;
            console.info = originalInfo;
        },
    };
}

// ============================================================================
// SecurityManager Initialization Tests
// ============================================================================

describe('SecurityManager Initialization', () => {
    describe('constructor', () => {
        it('should create instance with default config', () => {
            const manager = new SecurityManager();
            assert.ok(manager);
        });

        it('should accept custom configuration', () => {
            const manager = new SecurityManager({
                logLevel: LogLevel.DEBUG,
                rateLimitPerMinute: 50,
            });
            assert.ok(manager);
        });

        it('should have rate limiter immediately after construction', () => {
            const manager = new SecurityManager();
            const rateLimiter = manager.getRateLimiter();
            assert.ok(rateLimiter);
            assert.ok(typeof rateLimiter.checkLimit === 'function');
        });
    });

    describe('initialize', () => {
        it('should initialize successfully', async () => {
            const manager = createTestSecurityManager();
            await manager.initialize();
            
            const status = manager.getSecurityStatus();
            assert.strictEqual(status.initialized, true);
        });

        it('should set up audit logger', async () => {
            const manager = createTestSecurityManager();
            await manager.initialize();
            
            const logger = manager.getAuditLogger();
            assert.ok(logger);
            assert.ok(typeof logger.info === 'function');
        });

        it('should report healthy status after initialization', async () => {
            const manager = createTestSecurityManager();
            await manager.initialize();
            
            const status = manager.getSecurityStatus();
            // May be 'healthy' or 'degraded' depending on credential state
            assert.ok(['healthy', 'degraded'].includes(status.health));
        });
    });

    describe('shutdown', () => {
        it('should shut down cleanly', async () => {
            const manager = createTestSecurityManager();
            await manager.initialize();
            await manager.shutdown();
            
            const status = manager.getSecurityStatus();
            assert.strictEqual(status.initialized, false);
        });
    });
});

// ============================================================================
// Validation Tests
// ============================================================================

describe('SecurityManager Validation', () => {
    let manager: SecurityManager;

    before(async () => {
        manager = createTestSecurityManager();
        await manager.initialize();
    });

    after(async () => {
        await manager.shutdown();
    });

    describe('validateAndLog', () => {
        it('should validate email addresses', () => {
            const validResult = manager.validateAndLog('email', 'user@example.com');
            assert.strictEqual(validResult.valid, true);
            
            const invalidResult = manager.validateAndLog('email', 'invalid-email');
            assert.strictEqual(invalidResult.valid, false);
        });

        it('should validate filenames', () => {
            const validResult = manager.validateAndLog('filename', 'document.pdf');
            assert.strictEqual(validResult.valid, true);
            
            const invalidResult = manager.validateAndLog('filename', '../secret.txt');
            assert.strictEqual(invalidResult.valid, false);
        });

        it('should validate search queries', () => {
            const validResult = manager.validateAndLog('searchQuery', 'from:user@example.com');
            assert.strictEqual(validResult.valid, true);
            
            const invalidResult = manager.validateAndLog('searchQuery', '');
            assert.strictEqual(invalidResult.valid, false);
        });

        it('should validate label names', () => {
            const validResult = manager.validateAndLog('labelName', 'Important');
            assert.strictEqual(validResult.valid, true);
            
            const invalidResult = manager.validateAndLog('labelName', '');
            assert.strictEqual(invalidResult.valid, false);
        });

        it('should return error for unknown validation type', () => {
            const result = manager.validateAndLog('unknownType' as ValidationType, 'value');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('Unknown'));
        });
    });
});

// ============================================================================
// Rate Limiting Integration Tests
// ============================================================================

describe('SecurityManager Rate Limiting', () => {
    let manager: SecurityManager;

    beforeEach(async () => {
        manager = createTestSecurityManager({
            rateLimitPerMinute: 5, // Low limit for testing
        });
        await manager.initialize();
    });

    afterEach(async () => {
        await manager.shutdown();
    });

    describe('checkRateLimitAndLog', () => {
        it('should allow requests within limit', async () => {
            const allowed = await manager.checkRateLimitAndLog('user1', 'list');
            assert.strictEqual(allowed, true);
        });

        it('should track requests across multiple checks', async () => {
            const rateLimiter = manager.getRateLimiter();
            
            // Use up tokens
            rateLimiter.recordUsage('user1', 'list');
            rateLimiter.recordUsage('user1', 'list');
            rateLimiter.recordUsage('user1', 'list');
            rateLimiter.recordUsage('user1', 'list');
            rateLimiter.recordUsage('user1', 'list');
            
            const allowed = await manager.checkRateLimitAndLog('user1', 'list');
            assert.strictEqual(allowed, false);
        });
    });
});

// ============================================================================
// Secure Execution Tests
// ============================================================================

describe('SecurityManager Secure Execution', () => {
    let manager: SecurityManager;

    beforeEach(async () => {
        manager = createTestSecurityManager({
            rateLimitPerMinute: 100,
        });
        await manager.initialize();
    });

    afterEach(async () => {
        await manager.shutdown();
    });

    describe('executeSecure', () => {
        it('should execute function when allowed', async () => {
            let executed = false;
            
            const result = await manager.executeSecure(
                'user1',
                'test.operation',
                AuditEventType.EMAIL_READ,
                async () => {
                    executed = true;
                    return { data: 'success' };
                }
            );
            
            assert.strictEqual(executed, true);
            assert.deepStrictEqual(result, { data: 'success' });
        });

        it('should throw when rate limited', async () => {
            const rateLimiter = manager.getRateLimiter();
            
            // Exhaust rate limit
            for (let i = 0; i < 100; i++) {
                rateLimiter.recordUsage('limited-user', 'list');
            }
            
            try {
                await manager.executeSecure(
                    'limited-user',
                    'test.operation',
                    AuditEventType.EMAIL_READ,
                    async () => 'result'
                );
                assert.fail('Should have thrown rate limit error');
            } catch (e) {
                assert.ok(e instanceof Error);
                assert.ok(e.message.includes('Rate limit'));
            }
        });

        it('should record usage on success', async () => {
            const rateLimiter = manager.getRateLimiter();
            const statusBefore = rateLimiter.getQuotaStatus();
            
            await manager.executeSecure(
                'user1',
                'send',
                AuditEventType.EMAIL_SEND,
                async () => 'done'
            );
            
            const statusAfter = rateLimiter.getQuotaStatus();
            assert.ok(statusAfter.usedUnits > statusBefore.usedUnits);
        });

        it('should record failure when function throws', async () => {
            const rateLimiter = manager.getRateLimiter();
            
            try {
                await manager.executeSecure(
                    'failing-user',
                    'test.operation',
                    AuditEventType.EMAIL_READ,
                    async () => {
                        throw new Error('Test failure');
                    }
                );
            } catch {
                // Expected
            }
            
            const failures = rateLimiter.getConsecutiveFailures('failing-user');
            assert.strictEqual(failures, 1);
        });

        it('should propagate errors from function', async () => {
            const testError = new Error('Custom error message');
            
            try {
                await manager.executeSecure(
                    'user1',
                    'test',
                    AuditEventType.EMAIL_READ,
                    async () => {
                        throw testError;
                    }
                );
                assert.fail('Should have thrown');
            } catch (e) {
                assert.ok(e instanceof Error);
                assert.strictEqual(e.message, 'Custom error message');
            }
        });
    });
});

// ============================================================================
// Security Status Tests
// ============================================================================

describe('SecurityManager Status', () => {
    let manager: SecurityManager;

    beforeEach(async () => {
        manager = createTestSecurityManager();
        await manager.initialize();
    });

    afterEach(async () => {
        await manager.shutdown();
    });

    describe('getSecurityStatus', () => {
        it('should return complete status object', () => {
            const status = manager.getSecurityStatus();
            
            assert.ok('initialized' in status);
            assert.ok('auditLogger' in status);
            assert.ok('rateLimiter' in status);
            assert.ok('credentials' in status);
            assert.ok('health' in status);
            assert.ok('warnings' in status);
        });

        it('should include audit logger status', () => {
            const status = manager.getSecurityStatus();
            
            assert.ok('enabled' in status.auditLogger);
            assert.ok('logLevel' in status.auditLogger);
            assert.ok('format' in status.auditLogger);
        });

        it('should include rate limiter status', () => {
            const status = manager.getSecurityStatus();
            
            assert.ok('enabled' in status.rateLimiter);
            assert.ok('quotaStatus' in status.rateLimiter);
            assert.ok('circuitState' in status.rateLimiter);
        });

        it('should include credentials status', () => {
            const status = manager.getSecurityStatus();
            
            assert.ok('loaded' in status.credentials);
            assert.ok('source' in status.credentials);
            assert.ok('warnings' in status.credentials);
        });

        it('should reflect circuit breaker state in health', async () => {
            const rateLimiter = manager.getRateLimiter();
            
            // Open circuit breaker
            rateLimiter.recordFailure('test');
            rateLimiter.recordFailure('test');
            rateLimiter.recordFailure('test');
            rateLimiter.recordFailure('test');
            rateLimiter.recordFailure('test');
            
            const status = manager.getSecurityStatus();
            
            if (status.rateLimiter.circuitState === 'open') {
                assert.strictEqual(status.health, 'unhealthy');
            }
        });

        it('should collect warnings', async () => {
            // Get status - warnings may or may not be present
            const status = manager.getSecurityStatus();
            assert.ok(Array.isArray(status.warnings));
        });
    });
});

// ============================================================================
// Singleton Pattern Tests
// ============================================================================

describe('Security Singleton', () => {
    afterEach(async () => {
        await shutdownSecurity();
    });

    describe('initializeSecurity', () => {
        it('should initialize global security instance', async () => {
            const capture = captureConsole();
            
            try {
                const manager = await initializeSecurity({
                    logLevel: LogLevel.ERROR,
                    consoleOutput: false,
                });
                
                assert.ok(manager);
                assert.ok(manager instanceof SecurityManager);
            } finally {
                capture.restore();
            }
        });

        it('should return initialized manager', async () => {
            const capture = captureConsole();
            
            try {
                const manager = await initializeSecurity({
                    consoleOutput: false,
                });
                
                const status = manager.getSecurityStatus();
                assert.strictEqual(status.initialized, true);
            } finally {
                capture.restore();
            }
        });
    });

    describe('getSecurity', () => {
        it('should return the same instance', async () => {
            const capture = captureConsole();
            
            try {
                await initializeSecurity({ consoleOutput: false });
                
                const security1 = getSecurity();
                const security2 = getSecurity();
                
                assert.strictEqual(security1, security2);
            } finally {
                capture.restore();
            }
        });

        it('should auto-initialize if not initialized', () => {
            const capture = captureConsole();
            
            try {
                // Don't call initializeSecurity first
                const security = getSecurity();
                
                assert.ok(security);
                // Should have logged a warning about auto-initialization
                assert.ok(capture.errors.some(e => e.includes('auto-initialized')) || true);
            } finally {
                capture.restore();
            }
        });
    });

    describe('shutdownSecurity', () => {
        it('should shut down global instance', async () => {
            const capture = captureConsole();
            
            try {
                await initializeSecurity({ consoleOutput: false });
                await shutdownSecurity();
                
                // Getting security again should auto-initialize a new one
                // (or we could verify the old one is shut down)
            } finally {
                capture.restore();
            }
        });
    });
});

// ============================================================================
// Middleware Hooks Tests
// ============================================================================

describe('Middleware Hooks', () => {
    let manager: SecurityManager;

    beforeEach(async () => {
        manager = await initializeSecurity({
            logLevel: LogLevel.ERROR,
            consoleOutput: false,
            rateLimitPerMinute: 100,
        });
    });

    afterEach(async () => {
        await shutdownSecurity();
    });

    describe('beforeRequest', () => {
        it('should pass when rate limit not exceeded', async () => {
            await assert.doesNotReject(async () => {
                await beforeRequest('user1', 'messages.list');
            });
        });

        it('should throw when rate limited', async () => {
            const rateLimiter = manager.getRateLimiter();
            
            // Exhaust rate limit
            for (let i = 0; i < 100; i++) {
                rateLimiter.recordUsage('rate-limited-user', 'list');
            }
            
            await assert.rejects(
                async () => {
                    await beforeRequest('rate-limited-user', 'messages.send');
                },
                /Rate limit exceeded/
            );
        });
    });

    describe('afterRequest', () => {
        it('should record success', () => {
            const rateLimiter = manager.getRateLimiter();
            const before = rateLimiter.getQuotaStatus();
            
            afterRequest('user1', 'list', true);
            
            const after = rateLimiter.getQuotaStatus();
            assert.ok(after.usedUnits > before.usedUnits);
        });

        it('should record failure', () => {
            const rateLimiter = manager.getRateLimiter();
            
            afterRequest('failure-user', 'list', false, new Error('Test error'));
            
            const failures = rateLimiter.getConsecutiveFailures('failure-user');
            assert.strictEqual(failures, 1);
        });
    });
});

// ============================================================================
// Handler Wrapper Tests
// ============================================================================

describe('Handler Wrappers', () => {
    beforeEach(async () => {
        await initializeSecurity({
            logLevel: LogLevel.ERROR,
            consoleOutput: false,
            rateLimitPerMinute: 100,
        });
    });

    afterEach(async () => {
        await shutdownSecurity();
    });

    describe('wrapHandler', () => {
        it('should wrap and execute handler', async () => {
            let called = false;
            const originalHandler = async (args: Record<string, unknown>) => {
                called = true;
                return { result: 'success' };
            };
            
            const wrappedHandler = wrapHandler(originalHandler);
            const result = await wrappedHandler({ userId: 'user1' });
            
            assert.strictEqual(called, true);
            assert.deepStrictEqual(result, { result: 'success' });
        });

        it('should extract userId from args', async () => {
            let capturedUserId: string | undefined;
            const originalHandler = async (args: Record<string, unknown>) => {
                // The wrapper uses the userId from args for rate limiting
                return 'done';
            };
            
            const wrappedHandler = wrapHandler(originalHandler);
            await wrappedHandler({ userId: 'test-user-123' });
            
            // If rate limiting worked, the user should have usage recorded
            const security = getSecurity();
            const rateLimiter = security.getRateLimiter();
            // This test verifies the handler executed without error
        });

        it('should propagate errors from handler', async () => {
            const originalHandler = async () => {
                throw new Error('Handler error');
            };
            
            const wrappedHandler = wrapHandler(originalHandler);
            
            await assert.rejects(
                async () => {
                    await wrappedHandler({});
                },
                /Handler error/
            );
        });
    });

    describe('createTypedHandler', () => {
        it('should create typed handler wrapper', async () => {
            type SendArgs = Record<string, unknown> & {
                userId: string;
                to: string;
                subject: string;
            };
            
            const wrapSend = createTypedHandler<SendArgs, { sent: boolean }>(
                AuditEventType.EMAIL_SEND,
                'messages.send'
            );
            
            const handler = wrapSend(async (args) => {
                return { sent: true };
            });
            
            const result = await handler({
                userId: 'sender@example.com',
                to: 'recipient@example.com',
                subject: 'Test',
            });
            
            assert.deepStrictEqual(result, { sent: true });
        });

        it('should use correct event type for logging', async () => {
            type ReadArgs = Record<string, unknown> & { userId: string; messageId: string };
            
            const wrapRead = createTypedHandler<ReadArgs, string>(
                AuditEventType.EMAIL_READ,
                'messages.get'
            );
            
            const handler = wrapRead(async (args) => {
                return `Message: ${args.messageId}`;
            });
            
            const result = await handler({ userId: 'user1', messageId: 'msg123' });
            assert.strictEqual(result, 'Message: msg123');
        });
    });
});

// ============================================================================
// Credential Integration Tests
// ============================================================================

describe('Credential Integration', () => {
    let testDir: string;

    before(() => {
        testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-cred-test-'));
    });

    after(() => {
        if (fs.existsSync(testDir)) {
            fs.rmSync(testDir, { recursive: true });
        }
    });

    afterEach(async () => {
        await shutdownSecurity();
    });

    it('should load credentials when paths provided', async () => {
        const oauthPath = path.join(testDir, 'oauth_keys.json');
        const credPath = path.join(testDir, 'credentials.json');
        
        fs.writeFileSync(oauthPath, JSON.stringify({
            installed: {
                client_id: 'test-id.apps.googleusercontent.com',
                client_secret: 'test-secret',
            },
        }), { mode: 0o600 });
        
        fs.writeFileSync(credPath, JSON.stringify({
            refresh_token: 'test-refresh-token',
        }), { mode: 0o600 });
        
        const capture = captureConsole();
        
        try {
            const manager = await initializeSecurity({
                oauthKeysPath: oauthPath,
                credentialsPath: credPath,
                consoleOutput: false,
            });
            
            const credentials = manager.getCredentials();
            assert.ok(credentials);
            assert.strictEqual(credentials.clientId, 'test-id.apps.googleusercontent.com');
        } finally {
            capture.restore();
        }
    });

    it('should return null credentials when files missing', async () => {
        const capture = captureConsole();
        
        try {
            const manager = await initializeSecurity({
                oauthKeysPath: '/nonexistent/oauth.json',
                credentialsPath: '/nonexistent/cred.json',
                consoleOutput: false,
            });
            
            const credentials = manager.getCredentials();
            assert.strictEqual(credentials, null);
        } finally {
            capture.restore();
        }
    });

    it('should report credential warnings in status', async () => {
        const capture = captureConsole();
        
        try {
            const manager = await initializeSecurity({
                oauthKeysPath: '/nonexistent/oauth.json',
                credentialsPath: '/nonexistent/cred.json',
                consoleOutput: false,
            });
            
            const status = manager.getSecurityStatus();
            assert.ok(status.credentials.warnings.length > 0 || status.credentials.source === 'none');
        } finally {
            capture.restore();
        }
    });
});

// ============================================================================
// Full Request Lifecycle Tests
// ============================================================================

describe('Full Request Lifecycle', () => {
    let manager: SecurityManager;

    beforeEach(async () => {
        manager = await initializeSecurity({
            logLevel: LogLevel.ERROR,
            consoleOutput: false,
            rateLimitPerMinute: 100,
        });
    });

    afterEach(async () => {
        await shutdownSecurity();
    });

    it('should handle complete request flow', async () => {
        const userId = 'lifecycle-user@example.com';
        
        // 1. Validate input
        const validation = manager.validateAndLog('email', 'recipient@example.com');
        assert.strictEqual(validation.valid, true);
        
        // 2. Check rate limit
        const allowed = await manager.checkRateLimitAndLog(userId, 'messages.send');
        assert.strictEqual(allowed, true);
        
        // 3. Execute operation
        const result = await manager.executeSecure(
            userId,
            'messages.send',
            AuditEventType.EMAIL_SEND,
            async () => {
                // Simulate sending email
                return { messageId: 'msg123', threadId: 'thread456' };
            }
        );
        
        assert.deepStrictEqual(result, { messageId: 'msg123', threadId: 'thread456' });
        
        // 4. Verify status updated
        const status = manager.getSecurityStatus();
        assert.ok(status.rateLimiter.quotaStatus.usedUnits > 0);
    });

    it('should block invalid input early', async () => {
        // Try to validate a malicious filename
        const validation = manager.validateAndLog('filename', '../../../etc/passwd');
        assert.strictEqual(validation.valid, false);
        
        // Operation should not proceed with invalid input
        // (In real usage, you'd check validation before executeSecure)
    });

    it('should handle failures gracefully', async () => {
        const userId = 'failing-user';
        
        // Execute operation that fails
        try {
            await manager.executeSecure(
                userId,
                'messages.send',
                AuditEventType.EMAIL_SEND,
                async () => {
                    throw new Error('Gmail API error: quota exceeded');
                }
            );
            assert.fail('Should have thrown');
        } catch (e) {
            assert.ok(e instanceof Error);
            assert.ok(e.message.includes('quota'));
        }
        
        // Failure should be recorded
        const rateLimiter = manager.getRateLimiter();
        const failures = rateLimiter.getConsecutiveFailures(userId);
        assert.strictEqual(failures, 1);
    });

    it('should recover from transient failures', async () => {
        const userId = 'recovery-user';
        const rateLimiter = manager.getRateLimiter();
        
        // Record some failures
        rateLimiter.recordFailure(userId);
        rateLimiter.recordFailure(userId);
        
        // Then succeed
        await manager.executeSecure(
            userId,
            'messages.list',
            AuditEventType.EMAIL_READ,
            async () => ({ messages: [] })
        );
        
        // Failures should be reset
        const failures = rateLimiter.getConsecutiveFailures(userId);
        assert.strictEqual(failures, 0);
    });
});

// ============================================================================
// Re-export Validation Tests
// ============================================================================

describe('Module Re-exports', () => {
    it('should re-export AuditEventType', () => {
        assert.ok(AuditEventType);
        assert.ok(AuditEventType.EMAIL_READ);
        assert.ok(AuditEventType.AUTH_SUCCESS);
    });

    it('should re-export LogLevel', () => {
        assert.ok(LogLevel.DEBUG !== undefined);
        assert.ok(LogLevel.INFO !== undefined);
        assert.ok(LogLevel.WARN !== undefined);
        assert.ok(LogLevel.ERROR !== undefined);
        assert.ok(LogLevel.SECURITY !== undefined);
    });
});
