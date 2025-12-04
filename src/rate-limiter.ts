/**
 * Rate Limiting and Quota Management Module for Gmail MCP Server
 * 
 * Implements:
 * - Exponential backoff with jitter for failed requests
 * - Token bucket algorithm for per-user rate limiting
 * - Gmail API quota tracking and reporting
 * - Automatic retry with circuit breaker pattern
 * 
 * @module rate-limiter
 */

// ============================================================================
// Type Definitions and Interfaces
// ============================================================================

/**
 * Configuration for exponential backoff strategy
 */
export interface BackoffConfig {
    /** Initial delay in milliseconds (default: 1000) */
    initialDelayMs: number;
    /** Maximum delay in milliseconds (default: 32000) */
    maxDelayMs: number;
    /** Multiplier for each retry attempt (default: 2) */
    multiplier: number;
    /** Whether to add jitter to prevent thundering herd (default: true) */
    jitter: boolean;
    /** Maximum jitter factor (0-1, default: 0.5) */
    jitterFactor: number;
}

/**
 * Configuration for token bucket rate limiting
 */
export interface TokenBucketConfig {
    /** Maximum tokens in the bucket (burst capacity) */
    maxTokens: number;
    /** Tokens added per interval */
    refillRate: number;
    /** Refill interval in milliseconds */
    refillIntervalMs: number;
}

/**
 * Gmail API operation quota costs
 * Based on Gmail API documentation
 */
export interface OperationQuotaCosts {
    /** messages.list - 5 quota units */
    list: number;
    /** messages.get - 5 quota units */
    get: number;
    /** messages.send - 100 quota units */
    send: number;
    /** messages.insert - 25 quota units */
    insert: number;
    /** messages.modify - 5 quota units */
    modify: number;
    /** messages.trash - 5 quota units */
    trash: number;
    /** messages.untrash - 5 quota units */
    untrash: number;
    /** messages.delete - 10 quota units */
    delete: number;
    /** labels.list - 1 quota unit */
    labelsList: number;
    /** labels.get - 1 quota unit */
    labelsGet: number;
    /** labels.create - 5 quota units */
    labelsCreate: number;
    /** labels.update - 5 quota units */
    labelsUpdate: number;
    /** labels.delete - 5 quota units */
    labelsDelete: number;
    /** filters.list - 1 quota unit */
    filtersList: number;
    /** filters.get - 1 quota unit */
    filtersGet: number;
    /** filters.create - 5 quota units */
    filtersCreate: number;
    /** filters.delete - 5 quota units */
    filtersDelete: number;
    /** drafts.list - 5 quota units */
    draftsList: number;
    /** drafts.get - 5 quota units */
    draftsGet: number;
    /** drafts.create - 10 quota units */
    draftsCreate: number;
    /** drafts.update - 10 quota units */
    draftsUpdate: number;
    /** drafts.send - 100 quota units */
    draftsSend: number;
    /** drafts.delete - 10 quota units */
    draftsDelete: number;
    /** Default cost for unknown operations */
    default: number;
}

/**
 * Main configuration for the RateLimiter
 */
export interface RateLimiterConfig {
    /** Backoff configuration */
    backoff: BackoffConfig;
    /** Token bucket configuration for per-user limits */
    tokenBucket: TokenBucketConfig;
    /** Daily quota limit (default: 1,000,000,000 for most Gmail API users) */
    dailyQuotaLimit: number;
    /** Operation quota costs */
    operationCosts: OperationQuotaCosts;
    /** Quota warning thresholds (percentages) */
    quotaWarningThresholds: readonly number[];
    /** Circuit breaker configuration */
    circuitBreaker: CircuitBreakerConfig;
}

/**
 * Configuration for circuit breaker pattern
 */
export interface CircuitBreakerConfig {
    /** Number of failures before opening circuit */
    failureThreshold: number;
    /** Time in ms to wait before attempting recovery */
    recoveryTimeMs: number;
    /** Number of successful requests to close circuit */
    successThreshold: number;
}

/**
 * Result of a rate limit check
 */
export interface RateLimitResult {
    /** Whether the request is allowed */
    allowed: boolean;
    /** Remaining tokens for this user */
    remainingTokens: number;
    /** Time in ms until bucket refills (if not allowed) */
    retryAfterMs: number | null;
    /** Current quota usage percentage */
    quotaUsagePercent: number;
    /** Warning message if approaching limits */
    warning: string | null;
    /** Circuit breaker state */
    circuitState: CircuitState;
}

/**
 * Current quota status
 */
export interface QuotaStatus {
    /** Total daily quota limit */
    dailyLimit: number;
    /** Used quota units today */
    usedUnits: number;
    /** Remaining quota units */
    remainingUnits: number;
    /** Usage percentage */
    usagePercent: number;
    /** Timestamp when quota resets */
    resetTime: Date;
    /** Active warnings */
    warnings: string[];
    /** Per-user usage breakdown */
    perUserUsage: Map<string, number>;
}

/**
 * Circuit breaker states
 */
export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Token bucket state for a single user
 */
interface TokenBucket {
    tokens: number;
    lastRefillTime: number;
}

/**
 * Circuit breaker internal state
 */
interface CircuitBreakerState {
    state: CircuitState;
    failureCount: number;
    successCount: number;
    lastFailureTime: number;
    lastStateChange: number;
}

/**
 * User rate limit tracking data
 */
interface UserRateLimitData {
    bucket: TokenBucket;
    consecutiveFailures: number;
    lastRequestTime: number;
}

// ============================================================================
// Default Configuration
// ============================================================================

/**
 * Default quota costs for Gmail API operations
 */
const DEFAULT_OPERATION_COSTS: OperationQuotaCosts = {
    list: 5,
    get: 5,
    send: 100,
    insert: 25,
    modify: 5,
    trash: 5,
    untrash: 5,
    delete: 10,
    labelsList: 1,
    labelsGet: 1,
    labelsCreate: 5,
    labelsUpdate: 5,
    labelsDelete: 5,
    filtersList: 1,
    filtersGet: 1,
    filtersCreate: 5,
    filtersDelete: 5,
    draftsList: 5,
    draftsGet: 5,
    draftsCreate: 10,
    draftsUpdate: 10,
    draftsSend: 100,
    draftsDelete: 10,
    default: 5,
} as const;

/**
 * Default rate limiter configuration
 */
const DEFAULT_CONFIG: RateLimiterConfig = {
    backoff: {
        initialDelayMs: 1000,
        maxDelayMs: 32000,
        multiplier: 2,
        jitter: true,
        jitterFactor: 0.5,
    },
    tokenBucket: {
        maxTokens: 250,      // Gmail default: 250 requests per minute
        refillRate: 250,     // Full refill per minute
        refillIntervalMs: 60000, // 1 minute
    },
    dailyQuotaLimit: 1_000_000_000, // 1 billion quota units/day (Gmail default)
    operationCosts: DEFAULT_OPERATION_COSTS,
    quotaWarningThresholds: [80, 90, 95] as const,
    circuitBreaker: {
        failureThreshold: 5,
        recoveryTimeMs: 30000, // 30 seconds
        successThreshold: 2,
    },
} as const;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Calculate exponential backoff delay with optional jitter
 * 
 * @param attempt - The current attempt number (0-based)
 * @param config - Optional backoff configuration
 * @returns Delay in milliseconds before next retry
 * 
 * @example
 * ```typescript
 * const delay = calculateBackoffDelay(2); // ~4000ms with jitter
 * await sleep(delay);
 * ```
 */
export function calculateBackoffDelay(
    attempt: number,
    config: Partial<BackoffConfig> = {}
): number {
    const {
        initialDelayMs = DEFAULT_CONFIG.backoff.initialDelayMs,
        maxDelayMs = DEFAULT_CONFIG.backoff.maxDelayMs,
        multiplier = DEFAULT_CONFIG.backoff.multiplier,
        jitter = DEFAULT_CONFIG.backoff.jitter,
        jitterFactor = DEFAULT_CONFIG.backoff.jitterFactor,
    } = config;

    // Calculate base delay: initialDelay * multiplier^attempt
    const baseDelay = Math.min(
        initialDelayMs * Math.pow(multiplier, attempt),
        maxDelayMs
    );

    // Add jitter if enabled to prevent thundering herd
    if (jitter) {
        // Jitter range: [baseDelay * (1 - jitterFactor), baseDelay * (1 + jitterFactor)]
        const jitterRange = baseDelay * jitterFactor;
        const jitterValue = (Math.random() * 2 - 1) * jitterRange;
        return Math.max(0, Math.round(baseDelay + jitterValue));
    }

    return Math.round(baseDelay);
}

/**
 * Parse Retry-After header from HTTP response
 * 
 * Handles both formats:
 * - Seconds: "120" (wait 120 seconds)
 * - HTTP-date: "Wed, 21 Oct 2015 07:28:00 GMT"
 * 
 * @param header - The Retry-After header value
 * @returns Delay in milliseconds, or null if header is invalid/missing
 * 
 * @example
 * ```typescript
 * const delay = parseRetryAfterHeader("120"); // 120000ms
 * const delay2 = parseRetryAfterHeader(null); // null
 * ```
 */
export function parseRetryAfterHeader(header: string | null): number | null {
    if (!header) {
        return null;
    }

    // Try parsing as seconds (number)
    const seconds = parseInt(header, 10);
    if (!isNaN(seconds) && seconds >= 0) {
        return seconds * 1000;
    }

    // Try parsing as HTTP-date
    const date = new Date(header);
    if (!isNaN(date.getTime())) {
        const delayMs = date.getTime() - Date.now();
        return delayMs > 0 ? delayMs : 0;
    }

    return null;
}

/**
 * Get the quota cost for a given operation
 * 
 * @param operation - The Gmail API operation name
 * @param costs - The operation costs configuration
 * @returns The quota cost in units
 */
function getOperationCost(
    operation: string,
    costs: OperationQuotaCosts = DEFAULT_OPERATION_COSTS
): number {
    const normalizedOp = operation.toLowerCase().replace(/[^a-z]/g, '');
    
    // Map common operation names to cost keys
    const operationMap: Record<string, keyof OperationQuotaCosts> = {
        'messageslist': 'list',
        'list': 'list',
        'messagesget': 'get',
        'get': 'get',
        'messagessend': 'send',
        'send': 'send',
        'messagesinsert': 'insert',
        'insert': 'insert',
        'messagesmodify': 'modify',
        'modify': 'modify',
        'messagestrash': 'trash',
        'trash': 'trash',
        'messagesuntrash': 'untrash',
        'untrash': 'untrash',
        'messagesdelete': 'delete',
        'delete': 'delete',
        'labelslist': 'labelsList',
        'labelsget': 'labelsGet',
        'labelscreate': 'labelsCreate',
        'labelsupdate': 'labelsUpdate',
        'labelsdelete': 'labelsDelete',
        'filterslist': 'filtersList',
        'filtersget': 'filtersGet',
        'filterscreate': 'filtersCreate',
        'filtersdelete': 'filtersDelete',
        'draftslist': 'draftsList',
        'draftsget': 'draftsGet',
        'draftscreate': 'draftsCreate',
        'draftsupdate': 'draftsUpdate',
        'draftssend': 'draftsSend',
        'draftsdelete': 'draftsDelete',
    };

    const costKey = operationMap[normalizedOp];
    if (costKey && costKey in costs) {
        return costs[costKey];
    }

    return costs.default;
}

/**
 * Sleep for specified milliseconds
 * 
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after the delay
 */
function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Get the start of the current day in UTC
 * 
 * @returns Date object representing midnight UTC today
 */
function getUtcDayStart(): Date {
    const now = new Date();
    return new Date(Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate(),
        0, 0, 0, 0
    ));
}

/**
 * Get the start of the next day in UTC (quota reset time)
 * 
 * @returns Date object representing midnight UTC tomorrow
 */
function getUtcDayEnd(): Date {
    const dayStart = getUtcDayStart();
    return new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
}

// ============================================================================
// RateLimiter Class
// ============================================================================

/**
 * Comprehensive rate limiter for Gmail API requests
 * 
 * Features:
 * - Per-user token bucket rate limiting
 * - Daily quota tracking and warnings
 * - Exponential backoff with jitter
 * - Circuit breaker pattern for sustained failures
 * - Automatic retry with Retry-After header support
 * 
 * @example
 * ```typescript
 * const limiter = new RateLimiter();
 * 
 * // Check if request is allowed
 * const result = await limiter.checkLimit('user123', 'send');
 * if (!result.allowed) {
 *     console.log(`Rate limited. Retry after ${result.retryAfterMs}ms`);
 *     return;
 * }
 * 
 * // Make the API call and record usage
 * await makeApiCall();
 * limiter.recordUsage('user123', 'send');
 * ```
 */
export class RateLimiter {
    private readonly config: RateLimiterConfig;
    private readonly userBuckets: Map<string, UserRateLimitData>;
    private readonly circuitBreaker: CircuitBreakerState;
    private quotaUsedToday: number;
    private quotaDayStart: Date;
    private readonly perUserQuotaUsage: Map<string, number>;
    private readonly emittedWarnings: Set<number>;

    /**
     * Create a new RateLimiter instance
     * 
     * @param config - Partial configuration to override defaults
     */
    constructor(config: Partial<RateLimiterConfig> = {}) {
        this.config = this.mergeConfig(config);
        this.userBuckets = new Map();
        this.perUserQuotaUsage = new Map();
        this.quotaUsedToday = 0;
        this.quotaDayStart = getUtcDayStart();
        this.emittedWarnings = new Set();
        
        this.circuitBreaker = {
            state: 'closed',
            failureCount: 0,
            successCount: 0,
            lastFailureTime: 0,
            lastStateChange: Date.now(),
        };
    }

    /**
     * Merge user config with defaults
     */
    private mergeConfig(partial: Partial<RateLimiterConfig>): RateLimiterConfig {
        return {
            backoff: { ...DEFAULT_CONFIG.backoff, ...partial.backoff },
            tokenBucket: { ...DEFAULT_CONFIG.tokenBucket, ...partial.tokenBucket },
            dailyQuotaLimit: partial.dailyQuotaLimit ?? DEFAULT_CONFIG.dailyQuotaLimit,
            operationCosts: { ...DEFAULT_CONFIG.operationCosts, ...partial.operationCosts },
            quotaWarningThresholds: partial.quotaWarningThresholds ?? DEFAULT_CONFIG.quotaWarningThresholds,
            circuitBreaker: { ...DEFAULT_CONFIG.circuitBreaker, ...partial.circuitBreaker },
        };
    }

    /**
     * Get or create token bucket for a user
     */
    private getUserBucket(userId: string): UserRateLimitData {
        let userData = this.userBuckets.get(userId);
        
        if (!userData) {
            userData = {
                bucket: {
                    tokens: this.config.tokenBucket.maxTokens,
                    lastRefillTime: Date.now(),
                },
                consecutiveFailures: 0,
                lastRequestTime: 0,
            };
            this.userBuckets.set(userId, userData);
        }

        // Refill tokens based on elapsed time
        this.refillBucket(userData.bucket);
        
        return userData;
    }

    /**
     * Refill tokens in bucket based on elapsed time
     */
    private refillBucket(bucket: TokenBucket): void {
        const now = Date.now();
        const elapsedMs = now - bucket.lastRefillTime;
        const { refillRate, refillIntervalMs, maxTokens } = this.config.tokenBucket;
        
        // Calculate tokens to add based on elapsed time
        const tokensToAdd = Math.floor(
            (elapsedMs / refillIntervalMs) * refillRate
        );
        
        if (tokensToAdd > 0) {
            bucket.tokens = Math.min(bucket.tokens + tokensToAdd, maxTokens);
            bucket.lastRefillTime = now;
        }
    }

    /**
     * Reset daily quota if new day has started
     */
    private checkAndResetDailyQuota(): void {
        const currentDayStart = getUtcDayStart();
        
        if (currentDayStart.getTime() > this.quotaDayStart.getTime()) {
            this.quotaUsedToday = 0;
            this.quotaDayStart = currentDayStart;
            this.perUserQuotaUsage.clear();
            this.emittedWarnings.clear();
        }
    }

    /**
     * Get current quota warnings based on usage
     */
    private getQuotaWarnings(): string[] {
        const warnings: string[] = [];
        const usagePercent = (this.quotaUsedToday / this.config.dailyQuotaLimit) * 100;
        
        for (const threshold of this.config.quotaWarningThresholds) {
            if (usagePercent >= threshold) {
                const message = `WARNING: Gmail API quota usage at ${usagePercent.toFixed(1)}% (threshold: ${threshold}%)`;
                warnings.push(message);
                
                // Log warning only once per threshold
                if (!this.emittedWarnings.has(threshold)) {
                    this.emittedWarnings.add(threshold);
                    console.warn(`[RateLimiter] ${message}`);
                }
            }
        }
        
        return warnings;
    }

    /**
     * Update circuit breaker state based on request outcome
     */
    private updateCircuitBreaker(success: boolean): void {
        const { failureThreshold, recoveryTimeMs, successThreshold } = this.config.circuitBreaker;
        const now = Date.now();

        if (success) {
            if (this.circuitBreaker.state === 'half-open') {
                this.circuitBreaker.successCount++;
                if (this.circuitBreaker.successCount >= successThreshold) {
                    this.circuitBreaker.state = 'closed';
                    this.circuitBreaker.failureCount = 0;
                    this.circuitBreaker.successCount = 0;
                    this.circuitBreaker.lastStateChange = now;
                    console.info('[RateLimiter] Circuit breaker closed after successful recovery');
                }
            } else if (this.circuitBreaker.state === 'closed') {
                // Reset failure count on success
                this.circuitBreaker.failureCount = 0;
            }
        } else {
            this.circuitBreaker.lastFailureTime = now;
            this.circuitBreaker.failureCount++;
            this.circuitBreaker.successCount = 0;

            if (this.circuitBreaker.state === 'closed' && 
                this.circuitBreaker.failureCount >= failureThreshold) {
                this.circuitBreaker.state = 'open';
                this.circuitBreaker.lastStateChange = now;
                console.warn(`[RateLimiter] Circuit breaker opened after ${failureThreshold} failures`);
            } else if (this.circuitBreaker.state === 'half-open') {
                // Failed during recovery, reopen circuit
                this.circuitBreaker.state = 'open';
                this.circuitBreaker.lastStateChange = now;
                console.warn('[RateLimiter] Circuit breaker reopened after failed recovery attempt');
            }
        }

        // Check if it's time to try recovery
        if (this.circuitBreaker.state === 'open' &&
            (now - this.circuitBreaker.lastStateChange) >= recoveryTimeMs) {
            this.circuitBreaker.state = 'half-open';
            this.circuitBreaker.successCount = 0;
            this.circuitBreaker.lastStateChange = now;
            console.info('[RateLimiter] Circuit breaker entering half-open state for recovery');
        }
    }

    /**
     * Check if a request is allowed for a user and operation
     * 
     * Performs the following checks:
     * 1. Circuit breaker state
     * 2. Token bucket (per-user rate limit)
     * 3. Daily quota availability
     * 
     * @param userId - Unique identifier for the user/account
     * @param operation - The Gmail API operation (e.g., 'send', 'list', 'get')
     * @returns Promise resolving to rate limit check result
     * 
     * @example
     * ```typescript
     * const result = await limiter.checkLimit('user@example.com', 'send');
     * if (!result.allowed) {
     *     if (result.retryAfterMs) {
     *         console.log(`Retry after ${result.retryAfterMs}ms`);
     *     }
     *     if (result.warning) {
     *         console.warn(result.warning);
     *     }
     * }
     * ```
     */
    async checkLimit(userId: string, operation: string): Promise<RateLimitResult> {
        this.checkAndResetDailyQuota();
        
        // Update circuit breaker state (check for recovery)
        this.updateCircuitBreaker(true); // Just to check timing, no actual update

        const operationCost = getOperationCost(operation, this.config.operationCosts);
        const userData = this.getUserBucket(userId);
        const quotaUsagePercent = (this.quotaUsedToday / this.config.dailyQuotaLimit) * 100;
        
        // Get current warning message
        const warnings = this.getQuotaWarnings();
        const warning = warnings.length > 0 ? warnings[warnings.length - 1] : null;

        // Check circuit breaker first
        if (this.circuitBreaker.state === 'open') {
            const timeSinceOpen = Date.now() - this.circuitBreaker.lastStateChange;
            const retryAfterMs = this.config.circuitBreaker.recoveryTimeMs - timeSinceOpen;
            
            return {
                allowed: false,
                remainingTokens: userData.bucket.tokens,
                retryAfterMs: Math.max(0, retryAfterMs),
                quotaUsagePercent,
                warning: 'Circuit breaker is open due to sustained failures',
                circuitState: this.circuitBreaker.state,
            };
        }

        // Check token bucket (per-user rate limit)
        if (userData.bucket.tokens < 1) {
            // Calculate time until next token
            const tokensNeeded = 1 - userData.bucket.tokens;
            const msPerToken = this.config.tokenBucket.refillIntervalMs / this.config.tokenBucket.refillRate;
            const retryAfterMs = Math.ceil(tokensNeeded * msPerToken);

            return {
                allowed: false,
                remainingTokens: 0,
                retryAfterMs,
                quotaUsagePercent,
                warning: warning ?? `Rate limit exceeded for user ${userId}`,
                circuitState: this.circuitBreaker.state,
            };
        }

        // Check daily quota
        if (this.quotaUsedToday + operationCost > this.config.dailyQuotaLimit) {
            const resetTime = getUtcDayEnd();
            const retryAfterMs = resetTime.getTime() - Date.now();

            return {
                allowed: false,
                remainingTokens: userData.bucket.tokens,
                retryAfterMs,
                quotaUsagePercent: 100,
                warning: 'Daily quota limit exceeded',
                circuitState: this.circuitBreaker.state,
            };
        }

        // Request is allowed
        return {
            allowed: true,
            remainingTokens: userData.bucket.tokens,
            retryAfterMs: null,
            quotaUsagePercent,
            warning,
            circuitState: this.circuitBreaker.state,
        };
    }

    /**
     * Record API usage for a user and operation
     * 
     * Should be called after a successful API request to update:
     * - Token bucket (consume token)
     * - Daily quota usage
     * - Per-user quota tracking
     * 
     * @param userId - Unique identifier for the user/account
     * @param operation - The Gmail API operation that was performed
     * @param units - Optional explicit quota units (auto-calculated if not provided)
     * 
     * @example
     * ```typescript
     * // After successful API call
     * limiter.recordUsage('user@example.com', 'send');
     * 
     * // Or with explicit units
     * limiter.recordUsage('user@example.com', 'custom', 50);
     * ```
     */
    recordUsage(userId: string, operation: string, units?: number): void {
        this.checkAndResetDailyQuota();
        
        const operationCost = units ?? getOperationCost(operation, this.config.operationCosts);
        const userData = this.getUserBucket(userId);

        // Consume token from bucket
        userData.bucket.tokens = Math.max(0, userData.bucket.tokens - 1);
        userData.lastRequestTime = Date.now();
        
        // Reset consecutive failures on successful usage
        userData.consecutiveFailures = 0;

        // Update quota tracking
        this.quotaUsedToday += operationCost;
        
        const userQuota = this.perUserQuotaUsage.get(userId) ?? 0;
        this.perUserQuotaUsage.set(userId, userQuota + operationCost);

        // Update circuit breaker (success)
        this.updateCircuitBreaker(true);

        // Check for new warnings
        this.getQuotaWarnings();
    }

    /**
     * Record a failed request for a user
     * 
     * Updates:
     * - Consecutive failure count
     * - Circuit breaker state
     * 
     * @param userId - Unique identifier for the user/account
     */
    recordFailure(userId: string): void {
        const userData = this.getUserBucket(userId);
        userData.consecutiveFailures++;
        userData.lastRequestTime = Date.now();
        
        this.updateCircuitBreaker(false);
    }

    /**
     * Get current quota status
     * 
     * @returns Current quota usage information
     * 
     * @example
     * ```typescript
     * const status = limiter.getQuotaStatus();
     * console.log(`Quota: ${status.usagePercent.toFixed(1)}% used`);
     * console.log(`Remaining: ${status.remainingUnits} units`);
     * console.log(`Resets at: ${status.resetTime.toISOString()}`);
     * ```
     */
    getQuotaStatus(): QuotaStatus {
        this.checkAndResetDailyQuota();
        
        const remainingUnits = this.config.dailyQuotaLimit - this.quotaUsedToday;
        const usagePercent = (this.quotaUsedToday / this.config.dailyQuotaLimit) * 100;
        
        return {
            dailyLimit: this.config.dailyQuotaLimit,
            usedUnits: this.quotaUsedToday,
            remainingUnits: Math.max(0, remainingUnits),
            usagePercent,
            resetTime: getUtcDayEnd(),
            warnings: this.getQuotaWarnings(),
            perUserUsage: new Map(this.perUserQuotaUsage),
        };
    }

    /**
     * Get the number of consecutive failures for a user
     * 
     * @param userId - Unique identifier for the user/account
     * @returns Number of consecutive failures
     */
    getConsecutiveFailures(userId: string): number {
        return this.userBuckets.get(userId)?.consecutiveFailures ?? 0;
    }

    /**
     * Handle a rate limit response (429) and automatically retry
     * 
     * Implements automatic retry with:
     * - Retry-After header parsing
     * - Exponential backoff with jitter
     * - Circuit breaker protection
     * - Configurable max retries
     * 
     * @param response - The HTTP response object with status and headers
     * @param retryFn - Function to retry the request
     * @param maxRetries - Maximum number of retry attempts (default: 5)
     * @returns Promise resolving to the successful response
     * @throws Error if max retries exceeded or circuit breaker is open
     * 
     * @example
     * ```typescript
     * try {
     *     const result = await limiter.handleRateLimitResponse(
     *         response,
     *         async () => gmail.users.messages.list({ userId: 'me' })
     *     );
     * } catch (error) {
     *     console.error('Request failed after retries:', error);
     * }
     * ```
     */
    async handleRateLimitResponse<T>(
        response: { status: number; headers?: { get(name: string): string | null } },
        retryFn: () => Promise<T>,
        maxRetries: number = 5
    ): Promise<T> {
        // Check if this is actually a rate limit response
        if (response.status !== 429) {
            throw new Error(`Expected 429 status, got ${response.status}`);
        }

        // Check circuit breaker
        if (this.circuitBreaker.state === 'open') {
            throw new Error('Circuit breaker is open - request not attempted');
        }

        // Record the failure
        this.updateCircuitBreaker(false);

        // Parse Retry-After header
        const retryAfterHeader = response.headers?.get('Retry-After') ?? null;
        let baseDelay = parseRetryAfterHeader(retryAfterHeader);

        for (let attempt = 0; attempt < maxRetries; attempt++) {
            // Calculate delay
            let delay: number;
            if (baseDelay !== null && attempt === 0) {
                // Use Retry-After for first attempt
                delay = baseDelay;
            } else {
                // Use exponential backoff for subsequent attempts
                delay = calculateBackoffDelay(attempt, this.config.backoff);
            }

            console.info(`[RateLimiter] Rate limited. Waiting ${delay}ms before retry ${attempt + 1}/${maxRetries}`);
            await sleep(delay);

            // Check circuit breaker before retry (re-read state in case it changed)
            // Use getCircuitBreakerState() which properly updates and returns current state
            if (this.getCircuitBreakerState() === 'open') {
                throw new Error('Circuit breaker opened during retry sequence');
            }

            try {
                const result = await retryFn();
                this.updateCircuitBreaker(true);
                return result;
            } catch (error) {
                this.updateCircuitBreaker(false);
                
                // Check if it's another rate limit error
                if (error instanceof Error && 
                    (error.message.includes('429') || error.message.includes('Rate Limit'))) {
                    continue; // Try again
                }
                
                // Different error, rethrow
                throw error;
            }
        }

        throw new Error(`Rate limit retry failed after ${maxRetries} attempts`);
    }

    /**
     * Execute a function with automatic rate limiting and retry
     * 
     * Convenience method that combines checkLimit, recordUsage, and retry logic
     * 
     * @param userId - Unique identifier for the user/account
     * @param operation - The Gmail API operation
     * @param fn - The function to execute
     * @returns Promise resolving to the function result
     * @throws Error if rate limited and retries fail
     * 
     * @example
     * ```typescript
     * const messages = await limiter.execute(
     *     'user@example.com',
     *     'list',
     *     async () => gmail.users.messages.list({ userId: 'me', maxResults: 10 })
     * );
     * ```
     */
    async execute<T>(
        userId: string,
        operation: string,
        fn: () => Promise<T>
    ): Promise<T> {
        // Check if request is allowed
        const limitResult = await this.checkLimit(userId, operation);
        
        if (!limitResult.allowed) {
            if (limitResult.retryAfterMs !== null) {
                console.info(`[RateLimiter] Rate limited. Waiting ${limitResult.retryAfterMs}ms`);
                await sleep(limitResult.retryAfterMs);
            } else {
                throw new Error(`Rate limit exceeded: ${limitResult.warning}`);
            }
        }

        try {
            const result = await fn();
            this.recordUsage(userId, operation);
            return result;
        } catch (error) {
            this.recordFailure(userId);
            throw error;
        }
    }

    /**
     * Reset rate limit state for a specific user
     * 
     * @param userId - Unique identifier for the user/account
     */
    resetUser(userId: string): void {
        this.userBuckets.delete(userId);
        this.perUserQuotaUsage.delete(userId);
    }

    /**
     * Reset all rate limit state
     * 
     * Useful for testing or administrative purposes
     */
    resetAll(): void {
        this.userBuckets.clear();
        this.perUserQuotaUsage.clear();
        this.quotaUsedToday = 0;
        this.quotaDayStart = getUtcDayStart();
        this.emittedWarnings.clear();
        
        this.circuitBreaker.state = 'closed';
        this.circuitBreaker.failureCount = 0;
        this.circuitBreaker.successCount = 0;
        this.circuitBreaker.lastFailureTime = 0;
        this.circuitBreaker.lastStateChange = Date.now();
    }

    /**
     * Get current circuit breaker state
     * 
     * @returns Current circuit breaker state
     */
    getCircuitBreakerState(): CircuitState {
        // Update state first (check for recovery timeout)
        this.updateCircuitBreaker(true);
        return this.circuitBreaker.state;
    }

    /**
     * Get current configuration
     * 
     * @returns Current rate limiter configuration
     */
    getConfig(): Readonly<RateLimiterConfig> {
        return this.config;
    }
}

// ============================================================================
// Singleton Export for Easy Integration
// ============================================================================

/**
 * Default rate limiter instance for convenience
 * 
 * @example
 * ```typescript
 * import { defaultRateLimiter } from './rate-limiter.js';
 * 
 * const result = await defaultRateLimiter.checkLimit('user', 'list');
 * ```
 */
export const defaultRateLimiter = new RateLimiter();
