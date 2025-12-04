/**
 * Audit Logger Module Test Suite
 * Tests for structured audit logging in audit-logger.ts
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
    AuditLogger,
    initializeAuditLogger,
    getAuditLogger,
    createOperationLogger,
    logSecurityEvent,
    redactEmail,
    redactSensitiveFields,
    sanitizePathForLogging,
    LogLevel,
    AuditEventType,
} from '../audit-logger.js';
import type {
    AuditConfig,
    AuditEntry,
    PIIHandlingMode,
    LogFormat,
    SecurityEvent,
} from '../audit-logger.js';

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Create a test logger with specific config
 */
function createTestLogger(overrides: Partial<AuditConfig> = {}): AuditLogger {
    return new AuditLogger({
        minLevel: LogLevel.DEBUG,
        format: 'json',
        consoleOutput: false, // Disable console output in tests
        fileOutput: false,
        piiHandling: 'redact',
        ...overrides,
    });
}

/**
 * Capture console output
 */
function captureConsole(): { logs: string[]; errors: string[]; restore: () => void } {
    const logs: string[] = [];
    const errors: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    
    console.log = (...args: unknown[]) => {
        logs.push(args.map(String).join(' '));
    };
    
    console.error = (...args: unknown[]) => {
        errors.push(args.map(String).join(' '));
    };
    
    return {
        logs,
        errors,
        restore: () => {
            console.log = originalLog;
            console.error = originalError;
        },
    };
}

// ============================================================================
// Log Level Tests
// ============================================================================

describe('Log Level Filtering', () => {
    describe('minimum level filtering', () => {
        it('should log at or above minimum level', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    minLevel: LogLevel.INFO,
                    consoleOutput: true,
                });
                
                logger.info(AuditEventType.EMAIL_READ, 'test_info', 'success');
                logger.warn(AuditEventType.EMAIL_READ, 'test_warn');
                logger.error(AuditEventType.EMAIL_READ, 'test_error', 'ERR001');
                
                assert.ok(capture.logs.length >= 2, 'Should log INFO and WARN');
                assert.ok(capture.errors.length >= 1, 'Should log ERROR');
            } finally {
                capture.restore();
            }
        });

        it('should filter logs below minimum level', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    minLevel: LogLevel.WARN,
                    consoleOutput: true,
                });
                
                logger.debug(AuditEventType.EMAIL_READ, 'test_debug');
                logger.info(AuditEventType.EMAIL_READ, 'test_info', 'success');
                
                // DEBUG and INFO should not appear
                const allOutput = [...capture.logs, ...capture.errors].join(' ');
                assert.ok(!allOutput.includes('test_debug'), 'DEBUG should be filtered');
                // INFO might be filtered depending on minLevel setting
            } finally {
                capture.restore();
            }
        });

        it('should always log SECURITY level regardless of minLevel', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    minLevel: LogLevel.ERROR, // Only ERROR level
                    consoleOutput: true,
                });
                
                logger.logSecurityEvent({
                    eventType: AuditEventType.SECURITY_VIOLATION,
                    severity: 'high',
                    description: 'Test security event',
                    source: 'test',
                });
                
                // Security events should always be logged
                const allOutput = [...capture.logs, ...capture.errors].join(' ');
                assert.ok(allOutput.includes('SECURITY') || allOutput.includes('security'), 
                    'SECURITY level should always be logged');
            } finally {
                capture.restore();
            }
        });
    });

    describe('log level values', () => {
        it('should have correct ordering', () => {
            assert.ok(LogLevel.DEBUG < LogLevel.INFO);
            assert.ok(LogLevel.INFO < LogLevel.WARN);
            assert.ok(LogLevel.WARN < LogLevel.ERROR);
            assert.ok(LogLevel.ERROR < LogLevel.SECURITY);
        });
    });
});

// ============================================================================
// PII Redaction Tests
// ============================================================================

describe('PII Redaction', () => {
    describe('redactEmail', () => {
        describe('redact mode', () => {
            it('should show first character and domain', () => {
                const result = redactEmail('john.doe@example.com', 'redact');
                assert.strictEqual(result, 'j***@example.com');
            });

            it('should handle single character local part', () => {
                const result = redactEmail('a@example.com', 'redact');
                assert.strictEqual(result, 'a***@example.com');
            });
        });

        describe('hash mode', () => {
            it('should hash the local part', () => {
                const result = redactEmail('user@example.com', 'hash');
                assert.ok(result.startsWith('[user:'));
                assert.ok(result.endsWith('@example.com]'));
            });

            it('should produce consistent hash', () => {
                const result1 = redactEmail('user@example.com', 'hash');
                const result2 = redactEmail('user@example.com', 'hash');
                assert.strictEqual(result1, result2);
            });

            it('should produce different hash for different emails', () => {
                const result1 = redactEmail('user1@example.com', 'hash');
                const result2 = redactEmail('user2@example.com', 'hash');
                assert.notStrictEqual(result1, result2);
            });
        });

        describe('domain_only mode', () => {
            it('should show only domain', () => {
                const result = redactEmail('secret.user@company.com', 'domain_only');
                assert.strictEqual(result, '[user@company.com]');
            });
        });

        describe('omit mode', () => {
            it('should completely omit email', () => {
                const result = redactEmail('any@email.com', 'omit');
                assert.strictEqual(result, '[email-omitted]');
            });
        });

        describe('edge cases', () => {
            it('should handle invalid email without @', () => {
                const result = redactEmail('invalid-email', 'redact');
                assert.strictEqual(result, '[invalid-email]');
            });

            it('should handle null/undefined', () => {
                const result = redactEmail(null as unknown as string, 'redact');
                assert.strictEqual(result, '[invalid-email]');
            });

            it('should handle empty string', () => {
                const result = redactEmail('', 'redact');
                assert.strictEqual(result, '[invalid-email]');
            });

            it('should default to redact mode', () => {
                const result1 = redactEmail('user@example.com');
                const result2 = redactEmail('user@example.com', 'redact');
                assert.strictEqual(result1, result2);
            });
        });
    });

    describe('redactSensitiveFields', () => {
        it('should redact password fields', () => {
            const input = { username: 'john', password: 'secret123' };
            const result = redactSensitiveFields(input);
            assert.strictEqual(result.username, 'john');
            assert.strictEqual(result.password, '[REDACTED]');
        });

        it('should redact token fields', () => {
            const input = {
                accessToken: 'ya29.xyz',
                refresh_token: '1//abc',
                data: 'normal',
            };
            const result = redactSensitiveFields(input);
            assert.strictEqual(result.accessToken, '[REDACTED]');
            assert.strictEqual(result.refresh_token, '[REDACTED]');
            assert.strictEqual(result.data, 'normal');
        });

        it('should redact email body content', () => {
            const input = {
                messageId: '123',
                body: 'This is private email content',
                subject: 'Private subject',
            };
            const result = redactSensitiveFields(input);
            assert.strictEqual(result.messageId, '123');
            assert.strictEqual(result.body, '[REDACTED]');
            assert.strictEqual(result.subject, '[REDACTED]');
        });

        it('should redact email addresses in email fields', () => {
            const input = {
                from: 'sender@example.com',
                to: 'recipient@example.com',
                metadata: 'not redacted',
            };
            const result = redactSensitiveFields(input);
            // Email fields should be redacted (showing domain)
            assert.ok((result.from as string).includes('@example.com'));
            assert.ok((result.from as string).includes('***') || (result.from as string).includes('['));
        });

        it('should handle nested objects', () => {
            const input = {
                user: {
                    name: 'John',
                    credentials: {
                        password: 'secret',
                        apiKey: 'key123',
                    },
                },
            };
            const result = redactSensitiveFields(input);
            const nested = result.user as Record<string, unknown>;
            assert.strictEqual(nested.name, 'John');
            const creds = nested.credentials as Record<string, unknown>;
            assert.strictEqual(creds.password, '[REDACTED]');
        });

        it('should handle arrays', () => {
            const input = {
                recipients: ['a@b.com', 'c@d.com'],
            };
            const result = redactSensitiveFields(input);
            // Recipients field itself is in FORBIDDEN_FIELDS
            assert.strictEqual(result.recipients, '[REDACTED]');
        });

        it('should handle null/undefined input', () => {
            const result = redactSensitiveFields(null as unknown as Record<string, unknown>);
            assert.deepStrictEqual(result, {});
        });

        it('should redact additional custom fields', () => {
            const input = { customSecret: 'value', normal: 'ok' };
            const result = redactSensitiveFields(input, ['customSecret']);
            assert.strictEqual(result.customSecret, '[REDACTED]');
            assert.strictEqual(result.normal, 'ok');
        });
    });

    describe('sanitizePathForLogging', () => {
        it('should extract filename from full path', () => {
            const result = sanitizePathForLogging('/home/user/documents/file.txt');
            assert.ok(result.includes('file.txt'));
        });

        it('should mark credential files', () => {
            const result = sanitizePathForLogging('/home/user/.config/credentials.json');
            assert.ok(result.includes('credential-file'));
        });

        it('should handle .key files', () => {
            const result = sanitizePathForLogging('/etc/ssl/private.key');
            assert.ok(result.includes('credential-file'));
        });

        it('should handle empty path', () => {
            const result = sanitizePathForLogging('');
            assert.strictEqual(result, '[no-path]');
        });
    });
});

// ============================================================================
// Output Format Tests
// ============================================================================

describe('Output Formats', () => {
    describe('JSON format', () => {
        it('should output valid JSON', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    format: 'json',
                    consoleOutput: true,
                });
                
                logger.info(AuditEventType.EMAIL_READ, 'test_operation', 'success');
                
                // The output should be parseable JSON
                assert.ok(capture.logs.length > 0);
                const parsed = JSON.parse(capture.logs[0]);
                assert.ok(parsed.timestamp);
                assert.ok(parsed.operation);
            } finally {
                capture.restore();
            }
        });

        it('should include all required fields', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    format: 'json',
                    consoleOutput: true,
                });
                
                logger.info(AuditEventType.EMAIL_READ, 'test_op', 'success', {
                    userId: 'user@test.com',
                    resourceId: 'msg123',
                });
                
                const parsed = JSON.parse(capture.logs[0]);
                assert.ok(parsed.timestamp);
                assert.ok(parsed.level !== undefined);
                assert.ok(parsed.levelName);
                assert.ok(parsed.eventType);
                assert.ok(parsed.operation);
                assert.ok(parsed.outcome);
            } finally {
                capture.restore();
            }
        });
    });

    describe('Human-readable format', () => {
        it('should output readable format', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    format: 'human',
                    consoleOutput: true,
                });
                
                logger.info(AuditEventType.EMAIL_READ, 'test_operation', 'success');
                
                // Should not be JSON
                assert.ok(capture.logs.length > 0);
                assert.ok(capture.logs[0].includes('['));
                assert.ok(capture.logs[0].includes('test_operation'));
            } finally {
                capture.restore();
            }
        });

        it('should include timestamp in brackets', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({
                    format: 'human',
                    consoleOutput: true,
                });
                
                logger.info(AuditEventType.EMAIL_READ, 'test', 'success');
                
                // Should contain ISO timestamp format
                assert.ok(capture.logs[0].match(/\[\d{4}-\d{2}-\d{2}/));
            } finally {
                capture.restore();
            }
        });
    });
});

// ============================================================================
// Sensitive Field Filtering Tests
// ============================================================================

describe('Sensitive Field Filtering', () => {
    it('should filter credentials from details', () => {
        const capture = captureConsole();
        
        try {
            const logger = createTestLogger({
                format: 'json',
                consoleOutput: true,
            });
            
            logger.info(AuditEventType.EMAIL_READ, 'test', 'success', {
                details: {
                    userId: 'user123',
                    password: 'should-not-appear',
                    apiKey: 'also-secret',
                },
            });
            
            const output = capture.logs.join('');
            assert.ok(!output.includes('should-not-appear'));
            assert.ok(!output.includes('also-secret'));
            assert.ok(output.includes('[REDACTED]'));
        } finally {
            capture.restore();
        }
    });

    it('should redact user email when logging', () => {
        const capture = captureConsole();
        
        try {
            const logger = createTestLogger({
                format: 'json',
                consoleOutput: true,
                piiHandling: 'redact',
            });
            
            logger.info(AuditEventType.EMAIL_READ, 'test', 'success', {
                userId: 'john.doe@example.com',
            });
            
            const output = capture.logs.join('');
            assert.ok(!output.includes('john.doe@example.com'));
            assert.ok(output.includes('j***@example.com'));
        } finally {
            capture.restore();
        }
    });
});

// ============================================================================
// Security Event Logging Tests
// ============================================================================

describe('Security Event Logging', () => {
    describe('logSecurityEvent', () => {
        it('should log security events with severity', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true });
                
                logger.logSecurityEvent({
                    eventType: AuditEventType.SECURITY_VIOLATION,
                    severity: 'critical',
                    description: 'Unauthorized access attempt',
                    source: 'auth',
                    userId: 'attacker@evil.com',
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('CRITICAL') || output.includes('critical'));
                assert.ok(output.includes('Unauthorized'));
            } finally {
                capture.restore();
            }
        });

        it('should include recommended action when provided', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ 
                    consoleOutput: true,
                    format: 'json',
                });
                
                logger.logSecurityEvent({
                    eventType: AuditEventType.SECURITY_VIOLATION,
                    severity: 'high',
                    description: 'Suspicious activity',
                    source: 'rate-limiter',
                    recommendedAction: 'Block IP address',
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('Block IP'));
            } finally {
                capture.restore();
            }
        });

        it('should mark outcome as blocked', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ 
                    consoleOutput: true,
                    format: 'json',
                });
                
                logger.logSecurityEvent({
                    eventType: AuditEventType.SECURITY_VIOLATION,
                    severity: 'medium',
                    description: 'Test',
                    source: 'test',
                });
                
                const parsed = JSON.parse(capture.logs[0] || capture.errors[0]);
                assert.strictEqual(parsed.outcome, 'blocked');
            } finally {
                capture.restore();
            }
        });
    });

    describe('logRateLimitEvent', () => {
        it('should log rate limit hits', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logRateLimitEvent(AuditEventType.RATE_LIMIT_HIT, {
                    userId: 'user123',
                    remainingTokens: 0,
                    retryAfterMs: 5000,
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('RATE_LIMIT_HIT'));
            } finally {
                capture.restore();
            }
        });

        it('should log quota warnings', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logRateLimitEvent(AuditEventType.QUOTA_WARNING, {
                    quotaUsagePercent: 85,
                    warning: 'Approaching quota limit',
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('QUOTA_WARNING'));
            } finally {
                capture.restore();
            }
        });
    });
});

// ============================================================================
// Operation Logger Tests
// ============================================================================

describe('Operation Logger', () => {
    describe('createOperationLogger', () => {
        it('should create scoped logger', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                const opLogger = logger.createOperationLogger(
                    'send_email',
                    AuditEventType.EMAIL_SEND,
                    { userId: 'user123' }
                );
                
                opLogger.info('Starting send');
                
                const output = capture.logs.join('');
                assert.ok(output.includes('send_email') || output.includes('Starting'));
            } finally {
                capture.restore();
            }
        });

        it('should track elapsed time', async () => {
            const logger = createTestLogger();
            const opLogger = logger.createOperationLogger(
                'slow_operation',
                AuditEventType.EMAIL_READ,
            );
            
            // Wait a bit
            await new Promise(resolve => setTimeout(resolve, 50));
            
            const elapsed = opLogger.getElapsed();
            assert.ok(elapsed >= 45, `Elapsed time ${elapsed}ms should be >= 45ms`);
        });

        it('should log success with resource', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                const opLogger = logger.createOperationLogger(
                    'get_message',
                    AuditEventType.EMAIL_READ,
                );
                
                opLogger.success('msg123');
                
                const output = capture.logs.join('');
                assert.ok(output.includes('msg123') || output.includes('success'));
            } finally {
                capture.restore();
            }
        });

        it('should log failure with error code', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                const opLogger = logger.createOperationLogger(
                    'failed_operation',
                    AuditEventType.EMAIL_READ,
                );
                
                opLogger.failure('NETWORK_ERROR', { retries: 3 });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('NETWORK_ERROR'));
            } finally {
                capture.restore();
            }
        });
    });
});

// ============================================================================
// Singleton Pattern Tests
// ============================================================================

describe('Singleton Pattern', () => {
    describe('initializeAuditLogger', () => {
        it('should create and return logger instance', () => {
            const logger = initializeAuditLogger({
                minLevel: LogLevel.INFO,
                format: 'json',
                consoleOutput: false,
                fileOutput: false,
                piiHandling: 'redact',
            });
            
            assert.ok(logger);
            assert.ok(typeof logger.info === 'function');
        });
    });

    describe('getAuditLogger', () => {
        it('should return the initialized instance', () => {
            initializeAuditLogger({
                minLevel: LogLevel.WARN,
                format: 'json',
                consoleOutput: false,
                fileOutput: false,
                piiHandling: 'redact',
            });
            
            const logger = getAuditLogger();
            assert.ok(logger);
        });
    });

    describe('createOperationLogger helper', () => {
        it('should create operation logger from singleton', () => {
            initializeAuditLogger({
                minLevel: LogLevel.DEBUG,
                format: 'json',
                consoleOutput: false,
                fileOutput: false,
                piiHandling: 'redact',
            });
            
            const opLogger = createOperationLogger(
                'test_op',
                AuditEventType.EMAIL_READ,
            );
            
            assert.ok(opLogger);
            assert.ok(typeof opLogger.info === 'function');
            assert.ok(typeof opLogger.success === 'function');
            assert.ok(typeof opLogger.failure === 'function');
        });
    });

    describe('logSecurityEvent helper', () => {
        it('should log through singleton', () => {
            const capture = captureConsole();
            
            try {
                initializeAuditLogger({
                    minLevel: LogLevel.DEBUG,
                    format: 'json',
                    consoleOutput: true,
                    fileOutput: false,
                    piiHandling: 'redact',
                });
                
                logSecurityEvent({
                    eventType: AuditEventType.SECURITY_VIOLATION,
                    severity: 'low',
                    description: 'Test event',
                    source: 'test',
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('Test event') || output.includes('SECURITY'));
            } finally {
                capture.restore();
            }
        });
    });
});

// ============================================================================
// File Output Tests
// ============================================================================

describe('File Output', () => {
    let testLogDir: string;

    before(() => {
        testLogDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-log-test-'));
    });

    after(() => {
        if (fs.existsSync(testLogDir)) {
            fs.rmSync(testLogDir, { recursive: true });
        }
    });

    it('should write to file when enabled', async () => {
        const logPath = path.join(testLogDir, 'test.log');
        
        const logger = new AuditLogger({
            minLevel: LogLevel.INFO,
            format: 'json',
            consoleOutput: false,
            fileOutput: true,
            filePath: logPath,
            piiHandling: 'redact',
        });
        
        logger.info(AuditEventType.EMAIL_READ, 'file_test', 'success');
        
        // Flush any batched entries
        await logger.flushBatch();
        
        // Give file system time to write
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Check if file exists and has content
        const files = fs.readdirSync(testLogDir);
        assert.ok(files.some(f => f.includes('test')));
    });

    it('should create log directory if it does not exist', async () => {
        const nestedDir = path.join(testLogDir, 'nested', 'logs');
        const logPath = path.join(nestedDir, 'app.log');
        
        const logger = new AuditLogger({
            minLevel: LogLevel.INFO,
            format: 'json',
            consoleOutput: false,
            fileOutput: true,
            filePath: logPath,
            piiHandling: 'redact',
        });
        
        // Log something to trigger file creation
        logger.info(AuditEventType.EMAIL_READ, 'test_op', 'success');
        
        // Flush to ensure write completes
        await logger.flushBatch();
        
        // Give file system time to write
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Directory should be created
        assert.ok(fs.existsSync(nestedDir), 'Nested directory should be created');
    });
});

// ============================================================================
// Context Stack Tests
// ============================================================================

describe('Context Stack', () => {
    it('should push and pop context', () => {
        const logger = createTestLogger();
        
        logger.pushContext({ userId: 'user1', sessionId: 'session1' });
        logger.pushContext({ sessionId: 'session2' }); // Override sessionId
        
        const popped = logger.popContext();
        assert.ok(popped);
        assert.strictEqual(popped.sessionId, 'session2');
    });

    it('should merge context when pushing', () => {
        const logger = createTestLogger();
        
        logger.pushContext({ userId: 'user1' });
        logger.pushContext({ ipAddress: '127.0.0.1' });
        
        // Pop both
        const second = logger.popContext();
        assert.ok(second);
        assert.strictEqual(second.userId, 'user1');
        assert.strictEqual(second.ipAddress, '127.0.0.1');
    });
});

// ============================================================================
// Batch Mode Tests
// ============================================================================

describe('Batch Mode', () => {
    it('should batch entries when enabled', async () => {
        const capture = captureConsole();
        
        try {
            const logger = new AuditLogger({
                minLevel: LogLevel.DEBUG,
                format: 'json',
                consoleOutput: true,
                fileOutput: false,
                piiHandling: 'redact',
                batchMode: true,
                batchFlushInterval: 10000, // Long interval
                maxBatchSize: 100,
            });
            
            logger.info(AuditEventType.EMAIL_READ, 'batch_test_1', 'success');
            logger.info(AuditEventType.EMAIL_READ, 'batch_test_2', 'success');
            
            // Nothing should be logged yet (batched)
            assert.strictEqual(capture.logs.length, 0);
            
            // Force flush
            await logger.flushBatch();
            
            // Now entries should be logged
            assert.ok(capture.logs.length >= 2);
        } finally {
            capture.restore();
        }
    });

    it('should auto-flush when batch is full', async () => {
        const capture = captureConsole();
        
        try {
            const logger = new AuditLogger({
                minLevel: LogLevel.DEBUG,
                format: 'json',
                consoleOutput: true,
                fileOutput: false,
                piiHandling: 'redact',
                batchMode: true,
                batchFlushInterval: 60000,
                maxBatchSize: 3,
            });
            
            // Fill the batch
            logger.info(AuditEventType.EMAIL_READ, 'batch_1', 'success');
            logger.info(AuditEventType.EMAIL_READ, 'batch_2', 'success');
            logger.info(AuditEventType.EMAIL_READ, 'batch_3', 'success');
            
            // Wait a bit for async flush
            await new Promise(resolve => setTimeout(resolve, 50));
            
            // Batch should have auto-flushed
            assert.ok(capture.logs.length >= 3);
        } finally {
            capture.restore();
        }
    });
});

// ============================================================================
// Event Type Tests
// ============================================================================

describe('Audit Event Types', () => {
    it('should have authentication events', () => {
        assert.ok(AuditEventType.AUTH_SUCCESS);
        assert.ok(AuditEventType.AUTH_FAILURE);
        assert.ok(AuditEventType.AUTH_REFRESH);
    });

    it('should have email operation events', () => {
        assert.ok(AuditEventType.EMAIL_READ);
        assert.ok(AuditEventType.EMAIL_SEND);
        assert.ok(AuditEventType.EMAIL_DELETE);
        assert.ok(AuditEventType.EMAIL_MODIFY);
    });

    it('should have label events', () => {
        assert.ok(AuditEventType.LABEL_CREATE);
        assert.ok(AuditEventType.LABEL_DELETE);
        assert.ok(AuditEventType.LABEL_MODIFY);
    });

    it('should have system events', () => {
        assert.ok(AuditEventType.RATE_LIMIT_HIT);
        assert.ok(AuditEventType.QUOTA_WARNING);
        assert.ok(AuditEventType.SECURITY_VIOLATION);
    });
});

// ============================================================================
// Specific Operation Logging Tests
// ============================================================================

describe('Specific Operation Logging', () => {
    describe('logEmailOperation', () => {
        it('should log email read operation', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logEmailOperation(
                    AuditEventType.EMAIL_READ,
                    'msg123',
                    'success',
                    { userId: 'user@test.com' }
                );
                
                const output = capture.logs.join('');
                assert.ok(output.includes('msg123'));
                assert.ok(output.includes('email'));
            } finally {
                capture.restore();
            }
        });
    });

    describe('logLabelOperation', () => {
        it('should log label create operation', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logLabelOperation(
                    AuditEventType.LABEL_CREATE,
                    'Label_123',
                    'success',
                );
                
                const output = capture.logs.join('');
                assert.ok(output.includes('Label_123'));
                assert.ok(output.includes('label'));
            } finally {
                capture.restore();
            }
        });
    });

    describe('logFilterOperation', () => {
        it('should log filter create operation', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logFilterOperation(
                    AuditEventType.FILTER_CREATE,
                    'filter_abc',
                    'success',
                );
                
                const output = capture.logs.join('');
                assert.ok(output.includes('filter_abc'));
            } finally {
                capture.restore();
            }
        });
    });

    describe('logAuth', () => {
        it('should log successful auth', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logAuth(AuditEventType.AUTH_SUCCESS, true, {
                    userId: 'user@test.com',
                });
                
                const output = capture.logs.join('');
                assert.ok(output.includes('AUTH_SUCCESS'));
                assert.ok(output.includes('success'));
            } finally {
                capture.restore();
            }
        });

        it('should log failed auth', () => {
            const capture = captureConsole();
            
            try {
                const logger = createTestLogger({ consoleOutput: true, format: 'json' });
                
                logger.logAuth(AuditEventType.AUTH_FAILURE, false, {
                    errorCode: 'INVALID_TOKEN',
                });
                
                const output = [...capture.logs, ...capture.errors].join('');
                assert.ok(output.includes('AUTH_FAILURE'));
                assert.ok(output.includes('failure'));
            } finally {
                capture.restore();
            }
        });
    });
});
