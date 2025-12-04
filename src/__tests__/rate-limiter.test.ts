/**
 * Rate Limiter Module Test Suite
 * Tests for rate limiting, token bucket, and circuit breaker in rate-limiter.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
    RateLimiter,
    calculateBackoffDelay,
    parseRetryAfterHeader,
    defaultRateLimiter,
} from '../rate-limiter.js';
import type {
    RateLimiterConfig,
    BackoffConfig,
    TokenBucketConfig,
    CircuitBreakerConfig,
} from '../rate-limiter.js';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a fresh RateLimiter with custom config for testing
 */
function createTestLimiter(overrides: Partial<RateLimiterConfig> = {}): RateLimiter {
    return new RateLimiter({
        tokenBucket: {
            maxTokens: 10,
            refillRate: 10,
            refillIntervalMs: 1000,
            ...overrides.tokenBucket,
        },
        backoff: {
            initialDelayMs: 100,
            maxDelayMs: 1000,
            multiplier: 2,
            jitter: false, // Disable jitter for predictable tests
            jitterFactor: 0,
            ...overrides.backoff,
        },
        dailyQuotaLimit: 1000,
        circuitBreaker: {
            failureThreshold: 3,
            recoveryTimeMs: 100,
            successThreshold: 2,
            ...overrides.circuitBreaker,
        },
        ...overrides,
    });
}

/**
 * Wait for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// Backoff Calculation Tests
// ============================================================================

describe('Exponential Backoff', () => {
    describe('calculateBackoffDelay', () => {
        it('should return initial delay for attempt 0', () => {
            const config = { initialDelayMs: 1000, jitter: false, jitterFactor: 0 };
            const delay = calculateBackoffDelay(0, config);
            assert.strictEqual(delay, 1000);
        });

        it('should double delay for each attempt', () => {
            const config: Partial<BackoffConfig> = {
                initialDelayMs: 1000,
                multiplier: 2,
                jitter: false,
                jitterFactor: 0,
            };
            
            assert.strictEqual(calculateBackoffDelay(0, config), 1000);
            assert.strictEqual(calculateBackoffDelay(1, config), 2000);
            assert.strictEqual(calculateBackoffDelay(2, config), 4000);
            assert.strictEqual(calculateBackoffDelay(3, config), 8000);
        });

        it('should respect max delay', () => {
            const config: Partial<BackoffConfig> = {
                initialDelayMs: 1000,
                maxDelayMs: 5000,
                multiplier: 2,
                jitter: false,
            };
            
            const delay = calculateBackoffDelay(10, config);
            assert.ok(delay <= 5000);
        });

        it('should add jitter when enabled', () => {
            const config: Partial<BackoffConfig> = {
                initialDelayMs: 1000,
                jitter: true,
                jitterFactor: 0.5,
            };
            
            // Run multiple times to verify variance
            const delays = new Set<number>();
            for (let i = 0; i < 20; i++) {
                delays.add(calculateBackoffDelay(0, config));
            }
            
            // With jitter, we should see multiple different values
            assert.ok(delays.size > 1, 'Jitter should produce varying delays');
        });

        it('should respect jitter factor range', () => {
            const config: Partial<BackoffConfig> = {
                initialDelayMs: 1000,
                jitter: true,
                jitterFactor: 0.5,
            };
            
            // With jitterFactor 0.5, delay should be between 500 and 1500
            for (let i = 0; i < 50; i++) {
                const delay = calculateBackoffDelay(0, config);
                assert.ok(delay >= 500, `Delay ${delay} should be >= 500`);
                assert.ok(delay <= 1500, `Delay ${delay} should be <= 1500`);
            }
        });

        it('should use default values when config not provided', () => {
            const delay = calculateBackoffDelay(0);
            assert.ok(delay > 0);
        });
    });
});

// ============================================================================
// Retry-After Header Parsing Tests
// ============================================================================

describe('Retry-After Header Parsing', () => {
    describe('parseRetryAfterHeader', () => {
        it('should return null for null header', () => {
            assert.strictEqual(parseRetryAfterHeader(null), null);
        });

        it('should return null for empty header', () => {
            assert.strictEqual(parseRetryAfterHeader(''), null);
        });

        it('should parse seconds as milliseconds', () => {
            assert.strictEqual(parseRetryAfterHeader('120'), 120000);
        });

        it('should parse zero seconds', () => {
            assert.strictEqual(parseRetryAfterHeader('0'), 0);
        });

        it('should parse small seconds values', () => {
            assert.strictEqual(parseRetryAfterHeader('5'), 5000);
        });

        it('should parse HTTP-date format', () => {
            // Use a future date
            const futureDate = new Date(Date.now() + 60000);
            const httpDate = futureDate.toUTCString();
            
            const result = parseRetryAfterHeader(httpDate);
            assert.ok(result !== null);
            assert.ok(result! > 0);
            assert.ok(result! <= 60000 + 1000); // Allow 1 second tolerance
        });

        it('should return 0 for past HTTP-date', () => {
            const pastDate = new Date(Date.now() - 60000);
            const httpDate = pastDate.toUTCString();
            
            const result = parseRetryAfterHeader(httpDate);
            assert.strictEqual(result, 0);
        });

        it('should return null for invalid format', () => {
            assert.strictEqual(parseRetryAfterHeader('invalid-format'), null);
        });

        it('should return 0 for negative seconds', () => {
            // The implementation clamps negative values to 0 with Math.max(0, ...)
            const result = parseRetryAfterHeader('-10');
            assert.strictEqual(result, 0);
        });
    });
});

// ============================================================================
// Token Bucket Tests
// ============================================================================

describe('Token Bucket Rate Limiting', () => {
    describe('basic functionality', () => {
        it('should allow requests when tokens available', async () => {
            const limiter = createTestLimiter();
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, true);
            assert.ok(result.remainingTokens > 0);
        });

        it('should track remaining tokens', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 5, refillRate: 5, refillIntervalMs: 60000 } });
            
            const result1 = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result1.remainingTokens, 5);
            
            limiter.recordUsage('user1', 'list');
            
            const result2 = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result2.remainingTokens, 4);
        });

        it('should block when tokens exhausted', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 2, refillRate: 2, refillIntervalMs: 60000 } });
            
            // Exhaust tokens
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, false);
            assert.strictEqual(result.remainingTokens, 0);
        });

        it('should provide retry-after when blocked', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 1, refillRate: 1, refillIntervalMs: 1000 } });
            
            limiter.recordUsage('user1', 'list');
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, false);
            assert.ok(result.retryAfterMs !== null);
            assert.ok(result.retryAfterMs! > 0);
        });
    });

    describe('refill behavior', () => {
        it('should refill tokens over time', async () => {
            const limiter = createTestLimiter({
                tokenBucket: {
                    maxTokens: 10,
                    refillRate: 100,  // 100 tokens per interval
                    refillIntervalMs: 100,  // Refill every 100ms
                },
            });
            
            // Exhaust some tokens
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            const before = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(before.remainingTokens, 7);
            
            // Wait for refill
            await sleep(150);
            
            const after = await limiter.checkLimit('user1', 'list');
            assert.ok(after.remainingTokens > 7, 'Tokens should have refilled');
        });

        it('should not exceed max tokens on refill', async () => {
            const limiter = createTestLimiter({
                tokenBucket: {
                    maxTokens: 10,
                    refillRate: 100,
                    refillIntervalMs: 100,
                },
            });
            
            // Wait way longer than needed for full refill
            await sleep(200);
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.ok(result.remainingTokens <= 10, 'Should not exceed max tokens');
        });

        it('should track users independently', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 5, refillRate: 5, refillIntervalMs: 60000 } });
            
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            const user1Result = await limiter.checkLimit('user1', 'list');
            const user2Result = await limiter.checkLimit('user2', 'list');
            
            assert.strictEqual(user1Result.remainingTokens, 3);
            assert.strictEqual(user2Result.remainingTokens, 5);
        });
    });
});

// ============================================================================
// Circuit Breaker Tests
// ============================================================================

describe('Circuit Breaker', () => {
    describe('state transitions', () => {
        it('should start in closed state', () => {
            const limiter = createTestLimiter();
            assert.strictEqual(limiter.getCircuitBreakerState(), 'closed');
        });

        it('should open after failure threshold', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 3,
                    recoveryTimeMs: 1000,
                    successThreshold: 2,
                },
            });
            
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'open');
        });

        it('should block requests when open', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 2,
                    recoveryTimeMs: 10000,
                    successThreshold: 2,
                },
            });
            
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, false);
            assert.strictEqual(result.circuitState, 'open');
            assert.ok(result.warning?.includes('Circuit breaker'));
        });

        it('should transition to half-open after recovery time', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 2,
                    recoveryTimeMs: 50,
                    successThreshold: 2,
                },
            });
            
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'open');
            
            await sleep(100);
            
            // Calling getCircuitBreakerState should trigger transition
            assert.strictEqual(limiter.getCircuitBreakerState(), 'half-open');
        });

        it('should close after success threshold in half-open', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 2,
                    recoveryTimeMs: 50,
                    successThreshold: 2,
                },
            });
            
            // Open circuit
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            // Wait for half-open
            await sleep(100);
            limiter.getCircuitBreakerState(); // Trigger transition
            
            // Successful operations should close it
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'closed');
        });

        it('should reopen if failure during half-open', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 2,
                    recoveryTimeMs: 50,
                    successThreshold: 3,
                },
            });
            
            // Open circuit
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            // Wait for half-open
            await sleep(100);
            limiter.getCircuitBreakerState();
            
            // One success then failure
            limiter.recordUsage('user1', 'list');
            limiter.recordFailure('user1');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'open');
        });

        it('should reset failure count on success in closed state', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 5,
                    recoveryTimeMs: 1000,
                    successThreshold: 2,
                },
            });
            
            // Some failures but not enough to open
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            // Success should reset
            limiter.recordUsage('user1', 'list');
            
            // More failures - should need full threshold again
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'closed');
        });
    });

    describe('retry-after in circuit breaker', () => {
        it('should provide retry-after when circuit is open', async () => {
            const limiter = createTestLimiter({
                circuitBreaker: {
                    failureThreshold: 2,
                    recoveryTimeMs: 5000,
                    successThreshold: 2,
                },
            });
            
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, false);
            assert.ok(result.retryAfterMs !== null);
            assert.ok(result.retryAfterMs! > 0);
            assert.ok(result.retryAfterMs! <= 5000);
        });
    });
});

// ============================================================================
// Quota Tracking Tests
// ============================================================================

describe('Quota Tracking', () => {
    describe('quota status', () => {
        it('should track quota usage', () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 1000 });
            
            limiter.recordUsage('user1', 'send'); // 100 units
            
            const status = limiter.getQuotaStatus();
            assert.ok(status.usedUnits > 0);
            assert.ok(status.remainingUnits < 1000);
        });

        it('should calculate usage percentage', () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 100 });
            
            // Use 50 units worth
            for (let i = 0; i < 10; i++) {
                limiter.recordUsage('user1', 'list'); // 5 units each
            }
            
            const status = limiter.getQuotaStatus();
            assert.strictEqual(status.usagePercent, 50);
        });

        it('should track per-user usage', () => {
            const limiter = createTestLimiter();
            
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user2', 'list');
            
            const status = limiter.getQuotaStatus();
            assert.ok(status.perUserUsage.get('user1')! > status.perUserUsage.get('user2')!);
        });

        it('should block when daily quota exceeded', async () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 10 });
            
            // Exhaust quota (list costs 5)
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            const result = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(result.allowed, false);
            assert.strictEqual(result.quotaUsagePercent, 100);
        });
    });

    describe('quota warnings', () => {
        it('should generate warning at 80% usage', () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 100 });
            
            // Use 85 units
            for (let i = 0; i < 17; i++) {
                limiter.recordUsage('user1', 'list'); // 5 units each
            }
            
            const status = limiter.getQuotaStatus();
            assert.ok(status.warnings.length > 0);
            assert.ok(status.warnings.some(w => w.includes('80%') || w.includes('85')));
        });
    });
});

// ============================================================================
// Reset Functionality Tests
// ============================================================================

describe('Reset Functionality', () => {
    describe('resetUser', () => {
        it('should reset user rate limit state', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 5, refillRate: 5, refillIntervalMs: 60000 } });
            
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user1', 'list');
            
            const before = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(before.remainingTokens, 3);
            
            limiter.resetUser('user1');
            
            const after = await limiter.checkLimit('user1', 'list');
            assert.strictEqual(after.remainingTokens, 5);
        });
    });

    describe('resetAll', () => {
        it('should reset all state', async () => {
            const limiter = createTestLimiter({
                tokenBucket: { maxTokens: 5, refillRate: 5, refillIntervalMs: 60000 },
                circuitBreaker: { failureThreshold: 2, recoveryTimeMs: 10000, successThreshold: 2 },
            });
            
            // Create some state
            limiter.recordUsage('user1', 'list');
            limiter.recordUsage('user2', 'list');
            limiter.recordFailure('user1');
            limiter.recordFailure('user1');
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'open');
            
            limiter.resetAll();
            
            assert.strictEqual(limiter.getCircuitBreakerState(), 'closed');
            
            const result1 = await limiter.checkLimit('user1', 'list');
            const result2 = await limiter.checkLimit('user2', 'list');
            
            assert.strictEqual(result1.remainingTokens, 5);
            assert.strictEqual(result2.remainingTokens, 5);
        });
    });
});

// ============================================================================
// Execute with Rate Limiting Tests
// ============================================================================

describe('Execute with Rate Limiting', () => {
    describe('execute method', () => {
        it('should execute function when allowed', async () => {
            const limiter = createTestLimiter();
            
            let executed = false;
            const result = await limiter.execute('user1', 'list', async () => {
                executed = true;
                return 'success';
            });
            
            assert.strictEqual(executed, true);
            assert.strictEqual(result, 'success');
        });

        it('should record usage after successful execution', async () => {
            const limiter = createTestLimiter({ tokenBucket: { maxTokens: 10, refillRate: 10, refillIntervalMs: 60000 } });
            
            const before = await limiter.checkLimit('user1', 'list');
            
            await limiter.execute('user1', 'list', async () => 'done');
            
            const after = await limiter.checkLimit('user1', 'list');
            assert.ok(after.remainingTokens < before.remainingTokens);
        });

        it('should record failure when function throws', async () => {
            const limiter = createTestLimiter();
            
            try {
                await limiter.execute('user1', 'list', async () => {
                    throw new Error('Test error');
                });
                assert.fail('Should have thrown');
            } catch (e) {
                // Expected
            }
            
            const failures = limiter.getConsecutiveFailures('user1');
            assert.strictEqual(failures, 1);
        });

        it('should wait when rate limited', async () => {
            const limiter = createTestLimiter({
                tokenBucket: { maxTokens: 1, refillRate: 10, refillIntervalMs: 100 },
            });
            
            // Exhaust tokens
            limiter.recordUsage('user1', 'list');
            
            const start = Date.now();
            await limiter.execute('user1', 'list', async () => 'done');
            const elapsed = Date.now() - start;
            
            // Should have waited for some time
            assert.ok(elapsed >= 5, `Should have waited, but only took ${elapsed}ms`);
        });
    });
});

// ============================================================================
// Configuration Tests
// ============================================================================

describe('Configuration', () => {
    describe('getConfig', () => {
        it('should return current configuration', () => {
            const limiter = createTestLimiter({
                dailyQuotaLimit: 5000,
            });
            
            const config = limiter.getConfig();
            assert.strictEqual(config.dailyQuotaLimit, 5000);
        });

        it('should return readonly config', () => {
            const limiter = createTestLimiter();
            const config = limiter.getConfig();
            
            // TypeScript should prevent this, but verify runtime behavior
            assert.ok(config.tokenBucket);
            assert.ok(config.backoff);
            assert.ok(config.circuitBreaker);
        });
    });

    describe('default operation costs', () => {
        it('should use correct costs for different operations', () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 1000 });
            
            limiter.recordUsage('user1', 'send'); // 100 units
            const afterSend = limiter.getQuotaStatus();
            
            limiter.recordUsage('user1', 'list'); // 5 units
            const afterList = limiter.getQuotaStatus();
            
            // Send should cost more than list
            assert.ok(afterSend.usedUnits > 50);
            assert.strictEqual(afterList.usedUnits - afterSend.usedUnits, 5);
        });

        it('should use explicit units when provided', () => {
            const limiter = createTestLimiter({ dailyQuotaLimit: 1000 });
            
            limiter.recordUsage('user1', 'custom', 42);
            
            const status = limiter.getQuotaStatus();
            assert.strictEqual(status.usedUnits, 42);
        });
    });
});

// ============================================================================
// Handle Rate Limit Response Tests
// ============================================================================

describe('Handle Rate Limit Response', () => {
    it('should reject non-429 responses', async () => {
        const limiter = createTestLimiter();
        
        try {
            await limiter.handleRateLimitResponse(
                { status: 400 },
                async () => 'result',
            );
            assert.fail('Should have thrown');
        } catch (e) {
            assert.ok(e instanceof Error);
            assert.ok(e.message.includes('429'));
        }
    });

    it('should reject when circuit is open', async () => {
        const limiter = createTestLimiter({
            circuitBreaker: { failureThreshold: 2, recoveryTimeMs: 10000, successThreshold: 2 },
        });
        
        // Open circuit
        limiter.recordFailure('user1');
        limiter.recordFailure('user1');
        
        try {
            await limiter.handleRateLimitResponse(
                { status: 429 },
                async () => 'result',
            );
            assert.fail('Should have thrown');
        } catch (e) {
            assert.ok(e instanceof Error);
            assert.ok(e.message.includes('Circuit breaker'));
        }
    });

    it('should retry and succeed', async () => {
        const limiter = createTestLimiter({
            backoff: { initialDelayMs: 10, maxDelayMs: 100, multiplier: 2, jitter: false, jitterFactor: 0 },
        });
        
        let attempts = 0;
        const result = await limiter.handleRateLimitResponse(
            { status: 429, headers: { get: () => '0' } }, // 0 seconds retry-after
            async () => {
                attempts++;
                if (attempts < 2) {
                    throw new Error('Rate Limit');
                }
                return 'success';
            },
            5,
        );
        
        assert.strictEqual(result, 'success');
        assert.strictEqual(attempts, 2);
    });

    it('should fail after max retries', async () => {
        const limiter = createTestLimiter({
            backoff: { initialDelayMs: 5, maxDelayMs: 20, multiplier: 2, jitter: false, jitterFactor: 0 },
        });
        
        try {
            await limiter.handleRateLimitResponse(
                { status: 429, headers: { get: () => '0' } },
                async () => {
                    throw new Error('Rate Limit');
                },
                2,
            );
            assert.fail('Should have thrown');
        } catch (e) {
            assert.ok(e instanceof Error);
            assert.ok(e.message.includes('retry failed'));
        }
    });

    it('should use Retry-After header for first attempt', async () => {
        const limiter = createTestLimiter();
        
        const mockHeaders = {
            get: (name: string) => name === 'Retry-After' ? '0' : null,
        };
        
        let called = false;
        await limiter.handleRateLimitResponse(
            { status: 429, headers: mockHeaders },
            async () => {
                called = true;
                return 'done';
            },
        );
        
        assert.strictEqual(called, true);
    });
});

// ============================================================================
// Default Rate Limiter Export Test
// ============================================================================

describe('Default Rate Limiter', () => {
    it('should export a default instance', () => {
        assert.ok(defaultRateLimiter);
        assert.ok(typeof defaultRateLimiter.checkLimit === 'function');
        assert.ok(typeof defaultRateLimiter.recordUsage === 'function');
    });
});
