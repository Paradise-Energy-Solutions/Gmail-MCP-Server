/**
 * Unified Security Facade Module
 * 
 * Provides a single entry point for all security functionality in the Gmail MCP Server.
 * Integrates:
 * - Input validation (validators.ts)
 * - Credential security (credential-security.ts)
 * - Rate limiting (rate-limiter.ts)
 * - Audit logging (audit-logger.ts)
 * 
 * @module security
 */

// ============================================================================
// Re-exports from Security Modules
// ============================================================================

// Validators - Input validation
export {
    validateEmail,
    isPathContained,
    validateFilename,
    sanitizeFilename,
    validateSearchQuery,
    validateLabelName,
    validateAttachmentSize,
    VALIDATION_LIMITS,
} from './validators.js';

export type { ValidationResult } from './validators.js';

// Credential Security - Credential handling
export {
    loadCredentialsSecurely,
    enforceCredentialPermissions,
    OAUTH_SCOPES,
    shouldRefreshToken,
    sanitizeErrorMessage,
    handleAuthError,
    performSecurityAudit,
    ENV_VAR_NAMES,
} from './credential-security.js';

export type {
    Credentials,
    CredentialLoadResult,
    SecurityCheckResult,
} from './credential-security.js';

// Rate Limiter - Rate limiting and quota management
export {
    RateLimiter,
    defaultRateLimiter,
    calculateBackoffDelay,
    parseRetryAfterHeader,
} from './rate-limiter.js';

export type {
    RateLimiterConfig,
    QuotaStatus,
    RateLimitResult,
    CircuitState,
} from './rate-limiter.js';

// Audit Logger - Audit logging
export {
    AuditLogger,
    initializeAuditLogger,
    getAuditLogger,
    createOperationLogger,
    logSecurityEvent,
    redactEmail,
    AuditEventType,
    LogLevel,
} from './audit-logger.js';

export type {
    AuditConfig,
    AuditEntry,
    AuditContext,
    OperationLogger,
    SecurityEvent,
    LogFormat,
    PIIHandlingMode,
} from './audit-logger.js';

// ============================================================================
// Type Definitions
// ============================================================================

import {
    validateEmail,
    validateFilename,
    validateSearchQuery,
    validateLabelName,
} from './validators.js';

import type { ValidationResult } from './validators.js';

import {
    loadCredentialsSecurely,
    performSecurityAudit,
    shouldRefreshToken,
    sanitizeErrorMessage,
} from './credential-security.js';

import type {
    Credentials,
    CredentialLoadResult,
} from './credential-security.js';

import {
    RateLimiter,
    calculateBackoffDelay,
    parseRetryAfterHeader,
} from './rate-limiter.js';

import type {
    RateLimiterConfig,
    QuotaStatus,
    RateLimitResult,
    CircuitState,
} from './rate-limiter.js';

import {
    AuditLogger,
    initializeAuditLogger,
    getAuditLogger,
    logSecurityEvent,
    redactEmail,
    AuditEventType,
    LogLevel,
} from './audit-logger.js';

import type {
    AuditConfig,
    LogFormat,
} from './audit-logger.js';

/**
 * Type of validation to perform
 */
export type ValidationType = 'email' | 'filename' | 'searchQuery' | 'labelName';

/**
 * Configuration for the SecurityManager
 */
export interface SecurityConfig {
    /** Minimum log level (default: INFO) */
    logLevel?: LogLevel;
    
    /** Log output format (default: 'json') */
    logFormat?: LogFormat;
    
    /** Path to audit log file (default: undefined - no file output) */
    logFilePath?: string;
    
    /** Requests per minute limit (default: 250) */
    rateLimitPerMinute?: number;
    
    /** Daily quota limit (default: 1,000,000,000) */
    dailyQuotaLimit?: number;
    
    /** Path to OAuth keys file */
    oauthKeysPath?: string;
    
    /** Path to credentials/token file */
    credentialsPath?: string;
    
    /** Prefer environment variables for credentials (default: true) */
    preferEnvVars?: boolean;
    
    /** Enable console output for audit logs (default: true) */
    consoleOutput?: boolean;
    
    /** PII handling mode for email addresses (default: 'redact') */
    piiHandling?: 'redact' | 'hash' | 'domain_only' | 'omit';
}

/**
 * Current security system status
 */
export interface SecurityStatus {
    /** Whether the security system is initialized */
    initialized: boolean;
    
    /** Audit logger status */
    auditLogger: {
        enabled: boolean;
        logLevel: LogLevel;
        format: LogFormat;
        fileOutput: boolean;
    };
    
    /** Rate limiter status */
    rateLimiter: {
        enabled: boolean;
        quotaStatus: QuotaStatus;
        circuitState: CircuitState;
    };
    
    /** Credential security status */
    credentials: {
        loaded: boolean;
        source: 'environment' | 'file' | 'none';
        warnings: string[];
    };
    
    /** Overall security health */
    health: 'healthy' | 'degraded' | 'unhealthy';
    
    /** Any active warnings */
    warnings: string[];
}

/**
 * Result of a secure execution
 */
export interface SecureExecutionResult<T> {
    /** Whether the execution was successful */
    success: boolean;
    
    /** The result data (if successful) */
    data?: T;
    
    /** Error message (if failed) */
    error?: string;
    
    /** Execution duration in milliseconds */
    durationMs: number;
    
    /** Rate limit status after execution */
    rateLimitStatus: RateLimitResult;
}

// ============================================================================
// SecurityManager Class
// ============================================================================

/**
 * Unified security manager that coordinates all security components.
 * 
 * Features:
 * - Centralized validation with audit logging
 * - Rate limit checking with automatic logging
 * - Secure API execution wrapper
 * - Security status monitoring
 * 
 * @example
 * ```typescript
 * const security = new SecurityManager({
 *     logLevel: LogLevel.INFO,
 *     rateLimitPerMinute: 100,
 * });
 * 
 * await security.initialize();
 * 
 * // Validate and log
 * const result = security.validateAndLog('email', 'user@example.com');
 * 
 * // Execute securely
 * const data = await security.executeSecure(
 *     'user123',
 *     'messages.list',
 *     AuditEventType.EMAIL_READ,
 *     async () => gmail.users.messages.list({ userId: 'me' })
 * );
 * ```
 */
export class SecurityManager {
    private config: SecurityConfig;
    private rateLimiter: RateLimiter;
    private auditLogger: AuditLogger | null = null;
    private credentials: CredentialLoadResult | null = null;
    private initialized: boolean = false;

    /**
     * Create a new SecurityManager instance
     * @param config Security configuration
     */
    constructor(config: SecurityConfig = {}) {
        this.config = {
            logLevel: LogLevel.INFO,
            logFormat: 'json',
            rateLimitPerMinute: 250,
            dailyQuotaLimit: 1_000_000_000,
            preferEnvVars: true,
            consoleOutput: true,
            piiHandling: 'redact',
            ...config,
        };

        // Initialize rate limiter
        this.rateLimiter = new RateLimiter({
            tokenBucket: {
                maxTokens: this.config.rateLimitPerMinute!,
                refillRate: this.config.rateLimitPerMinute!,
                refillIntervalMs: 60000,
            },
            dailyQuotaLimit: this.config.dailyQuotaLimit,
        });
    }

    /**
     * Initialize the security manager
     * Sets up audit logging and loads credentials if configured
     */
    async initialize(): Promise<void> {
        // Initialize audit logger
        const auditConfig: AuditConfig = {
            minLevel: this.config.logLevel ?? LogLevel.INFO,
            format: this.config.logFormat ?? 'json',
            consoleOutput: this.config.consoleOutput ?? true,
            fileOutput: !!this.config.logFilePath,
            filePath: this.config.logFilePath,
            piiHandling: this.config.piiHandling ?? 'redact',
        };

        this.auditLogger = initializeAuditLogger(auditConfig);

        // Load credentials if paths are provided
        if (this.config.oauthKeysPath && this.config.credentialsPath) {
            this.credentials = loadCredentialsSecurely(
                this.config.oauthKeysPath,
                this.config.credentialsPath
            );

            // Log credential loading result
            if (this.credentials.credentials) {
                this.auditLogger.info(
                    AuditEventType.AUTH_SUCCESS,
                    'credentials_loaded',
                    'success',
                    { details: { source: this.credentials.source } }
                );
            } else {
                this.auditLogger.warn(
                    AuditEventType.AUTH_FAILURE,
                    'credentials_load_failed',
                    { details: { warnings: this.credentials.warnings } }
                );
            }
        }

        this.initialized = true;

        // Log initialization
        this.auditLogger.info(
            AuditEventType.CONFIG_CHANGE,
            'security_manager_initialized',
            'success',
            { details: { config: this.getSanitizedConfig() } }
        );
    }

    /**
     * Get sanitized config for logging (no sensitive paths)
     */
    private getSanitizedConfig(): Record<string, unknown> {
        return {
            logLevel: this.config.logLevel,
            logFormat: this.config.logFormat,
            rateLimitPerMinute: this.config.rateLimitPerMinute,
            dailyQuotaLimit: this.config.dailyQuotaLimit,
            consoleOutput: this.config.consoleOutput,
            piiHandling: this.config.piiHandling,
            hasOauthKeysPath: !!this.config.oauthKeysPath,
            hasCredentialsPath: !!this.config.credentialsPath,
        };
    }

    /**
     * Validate input and log the validation attempt
     * 
     * @param type Type of validation to perform
     * @param value Value to validate
     * @returns Validation result
     * 
     * @example
     * ```typescript
     * const result = security.validateAndLog('email', 'user@example.com');
     * if (!result.valid) {
     *     console.error('Invalid email:', result.error);
     * }
     * ```
     */
    validateAndLog(type: ValidationType, value: string): ValidationResult {
        let result: ValidationResult;

        switch (type) {
            case 'email':
                result = validateEmail(value);
                break;
            case 'filename':
                result = validateFilename(value);
                break;
            case 'searchQuery':
                result = validateSearchQuery(value);
                break;
            case 'labelName':
                result = validateLabelName(value);
                break;
            default:
                result = { valid: false, error: `Unknown validation type: ${type}` };
        }

        // Log validation result
        const logger = this.auditLogger ?? getAuditLogger();
        
        if (result.valid) {
            logger.debug(
                AuditEventType.CONFIG_CHANGE, // Using CONFIG_CHANGE for validation events
                `validate_${type}`,
                { validationType: type, valid: true }
            );
        } else {
            logSecurityEvent({
                eventType: AuditEventType.SECURITY_VIOLATION,
                severity: 'low',
                description: `Validation failed for ${type}: ${result.error}`,
                source: 'validation',
                context: { validationType: type, error: result.error },
            });
        }

        return result;
    }

    /**
     * Check rate limit and log the check
     * 
     * @param userId User identifier for rate limiting
     * @param operation The operation being performed
     * @returns Promise resolving to whether the request should proceed
     * 
     * @example
     * ```typescript
     * const allowed = await security.checkRateLimitAndLog('user123', 'messages.send');
     * if (!allowed) {
     *     throw new Error('Rate limit exceeded');
     * }
     * ```
     */
    async checkRateLimitAndLog(userId: string, operation: string): Promise<boolean> {
        const result = await this.rateLimiter.checkLimit(userId, operation);
        const logger = this.auditLogger ?? getAuditLogger();

        if (!result.allowed) {
            logger.logRateLimitEvent(AuditEventType.RATE_LIMIT_HIT, {
                userId,
                operation,
                remainingTokens: result.remainingTokens,
                retryAfterMs: result.retryAfterMs,
                quotaUsagePercent: result.quotaUsagePercent,
                circuitState: result.circuitState,
            });
        } else if (result.warning) {
            logger.logRateLimitEvent(AuditEventType.QUOTA_WARNING, {
                userId,
                operation,
                warning: result.warning,
                quotaUsagePercent: result.quotaUsagePercent,
            });
        }

        return result.allowed;
    }

    /**
     * Execute an operation with full security integration
     * 
     * Wraps an API call with:
     * - Rate limiting check
     * - Audit logging (start, success/failure)
     * - Error handling with sanitization
     * - Duration tracking
     * 
     * @param userId User identifier
     * @param operation Operation name for logging
     * @param eventType Audit event type
     * @param fn The async function to execute
     * @returns The function result
     * @throws Error if rate limited or function fails
     * 
     * @example
     * ```typescript
     * const messages = await security.executeSecure(
     *     'user@example.com',
     *     'messages.list',
     *     AuditEventType.EMAIL_READ,
     *     async () => gmail.users.messages.list({ userId: 'me' })
     * );
     * ```
     */
    async executeSecure<T>(
        userId: string,
        operation: string,
        eventType: AuditEventType,
        fn: () => Promise<T>
    ): Promise<T> {
        const logger = this.auditLogger ?? getAuditLogger();
        const opLogger = logger.createOperationLogger(operation, eventType, { userId });
        
        // Check rate limit
        const rateLimitResult = await this.rateLimiter.checkLimit(userId, operation);
        
        if (!rateLimitResult.allowed) {
            opLogger.failure('RATE_LIMIT_EXCEEDED', {
                retryAfterMs: rateLimitResult.retryAfterMs,
                quotaUsagePercent: rateLimitResult.quotaUsagePercent,
            });
            
            throw new Error(
                `Rate limit exceeded. Retry after ${rateLimitResult.retryAfterMs}ms. ` +
                `Quota usage: ${rateLimitResult.quotaUsagePercent.toFixed(1)}%`
            );
        }

        // Log quota warning if present
        if (rateLimitResult.warning) {
            opLogger.warn(rateLimitResult.warning);
        }

        try {
            // Execute the function
            const result = await fn();
            
            // Record successful usage
            this.rateLimiter.recordUsage(userId, operation);
            
            // Log success
            opLogger.success(undefined, {
                quotaUsagePercent: rateLimitResult.quotaUsagePercent,
            });
            
            return result;
        } catch (error) {
            // Record failure
            this.rateLimiter.recordFailure(userId);
            
            // Log failure with sanitized error
            const errorMessage = error instanceof Error ? error.message : String(error);
            opLogger.failure('EXECUTION_ERROR', {
                error: errorMessage.substring(0, 200), // Truncate for safety
            });
            
            throw error;
        }
    }

    /**
     * Get current security status report
     * 
     * @returns Comprehensive security status
     * 
     * @example
     * ```typescript
     * const status = security.getSecurityStatus();
     * console.log('Health:', status.health);
     * console.log('Quota used:', status.rateLimiter.quotaStatus.usagePercent + '%');
     * ```
     */
    getSecurityStatus(): SecurityStatus {
        const quotaStatus = this.rateLimiter.getQuotaStatus();
        const circuitState = this.rateLimiter.getCircuitBreakerState();
        const warnings: string[] = [];

        // Collect warnings
        warnings.push(...quotaStatus.warnings);
        
        if (this.credentials?.warnings) {
            warnings.push(...this.credentials.warnings);
        }

        if (circuitState === 'open') {
            warnings.push('Circuit breaker is open - API requests may be blocked');
        }

        // Determine health
        let health: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
        
        if (circuitState === 'open' || !this.initialized) {
            health = 'unhealthy';
        } else if (circuitState === 'half-open' || warnings.length > 0) {
            health = 'degraded';
        }

        return {
            initialized: this.initialized,
            auditLogger: {
                enabled: !!this.auditLogger,
                logLevel: this.config.logLevel ?? LogLevel.INFO,
                format: this.config.logFormat ?? 'json',
                fileOutput: !!this.config.logFilePath,
            },
            rateLimiter: {
                enabled: true,
                quotaStatus,
                circuitState,
            },
            credentials: {
                loaded: !!this.credentials?.credentials,
                source: this.credentials?.source ?? 'none',
                warnings: this.credentials?.warnings ?? [],
            },
            health,
            warnings,
        };
    }

    /**
     * Get the underlying rate limiter instance
     * For advanced rate limiting operations
     */
    getRateLimiter(): RateLimiter {
        return this.rateLimiter;
    }

    /**
     * Get the underlying audit logger instance
     * For advanced logging operations
     */
    getAuditLogger(): AuditLogger {
        return this.auditLogger ?? getAuditLogger();
    }

    /**
     * Get loaded credentials
     * @returns Credentials if loaded, null otherwise
     */
    getCredentials(): Credentials | null {
        return this.credentials?.credentials ?? null;
    }

    /**
     * Shutdown the security manager
     * Flushes audit logs and cleans up resources
     */
    async shutdown(): Promise<void> {
        if (this.auditLogger) {
            await this.auditLogger.shutdown();
        }
        this.initialized = false;
    }
}

// ============================================================================
// Middleware-Style Hooks
// ============================================================================

/**
 * Pre-request hook for security checks
 * Runs validation, rate limit check, and logs intent
 * 
 * @param userId User identifier
 * @param operation Operation name
 * @throws Error if rate limit exceeded
 * 
 * @example
 * ```typescript
 * await beforeRequest('user123', 'messages.send');
 * // Proceed with API call
 * ```
 */
export async function beforeRequest(userId: string, operation: string): Promise<void> {
    const security = getSecurity();
    const logger = security.getAuditLogger();
    
    // Log intent
    logger.info(
        AuditEventType.EMAIL_READ, // Generic event type for request start
        `${operation}_started`,
        'success',
        { userId, details: { operation } }
    );
    
    // Check rate limit
    const allowed = await security.checkRateLimitAndLog(userId, operation);
    if (!allowed) {
        throw new Error(`Rate limit exceeded for operation: ${operation}`);
    }
}

/**
 * Post-request hook for logging results
 * Logs operation result and updates metrics
 * 
 * @param userId User identifier
 * @param operation Operation name
 * @param success Whether the operation succeeded
 * @param error Optional error if operation failed
 * 
 * @example
 * ```typescript
 * try {
 *     await apiCall();
 *     afterRequest('user123', 'messages.send', true);
 * } catch (error) {
 *     afterRequest('user123', 'messages.send', false, error);
 * }
 * ```
 */
export function afterRequest(
    userId: string,
    operation: string,
    success: boolean,
    error?: Error
): void {
    const security = getSecurity();
    const logger = security.getAuditLogger();
    const rateLimiter = security.getRateLimiter();

    if (success) {
        rateLimiter.recordUsage(userId, operation);
        logger.info(
            AuditEventType.EMAIL_READ,
            `${operation}_completed`,
            'success',
            { userId }
        );
    } else {
        rateLimiter.recordFailure(userId);
        logger.error(
            AuditEventType.EMAIL_READ,
            `${operation}_failed`,
            'OPERATION_ERROR',
            {
                userId,
                details: { error: error?.message?.substring(0, 200) },
            }
        );
    }
}

/**
 * Wrap an MCP handler with security integration
 * 
 * Creates a decorated handler that automatically:
 * - Checks rate limits
 * - Logs operations
 * - Handles errors safely
 * 
 * @param handler The original handler function
 * @returns Wrapped handler with security integration
 * 
 * @example
 * ```typescript
 * const originalHandler = async (args: { userId: string }) => {
 *     return gmail.users.messages.list({ userId: args.userId });
 * };
 * 
 * const secureHandler = wrapHandler(originalHandler);
 * // Use secureHandler in your MCP server
 * ```
 */
export function wrapHandler<T>(
    handler: (args: Record<string, unknown>) => Promise<T>
): (args: Record<string, unknown>) => Promise<T> {
    return async (args: Record<string, unknown>): Promise<T> => {
        const security = getSecurity();
        const userId = (args.userId as string) ?? 'anonymous';
        const operation = (args.operation as string) ?? 'unknown';
        
        return security.executeSecure(
            userId,
            operation,
            AuditEventType.EMAIL_READ, // Default event type
            async () => handler(args)
        );
    };
}

/**
 * Create a typed handler wrapper for specific operations
 * 
 * @param eventType The audit event type for this handler
 * @param operationName The operation name for logging
 * @returns A function that wraps handlers with security
 * 
 * @example
 * ```typescript
 * const wrapEmailRead = createTypedHandler(AuditEventType.EMAIL_READ, 'messages.get');
 * 
 * const secureGetMessage = wrapEmailRead(async (args) => {
 *     return gmail.users.messages.get({ userId: 'me', id: args.messageId });
 * });
 * ```
 */
export function createTypedHandler<TArgs extends Record<string, unknown>, TResult>(
    eventType: AuditEventType,
    operationName: string
): (handler: (args: TArgs) => Promise<TResult>) => (args: TArgs) => Promise<TResult> {
    return (handler: (args: TArgs) => Promise<TResult>) => {
        return async (args: TArgs): Promise<TResult> => {
            const security = getSecurity();
            const userId = (args.userId as string) ?? 'anonymous';
            
            return security.executeSecure(
                userId,
                operationName,
                eventType,
                async () => handler(args)
            );
        };
    };
}

// ============================================================================
// Security Singleton
// ============================================================================

/** Singleton SecurityManager instance */
let securityManager: SecurityManager | null = null;

/**
 * Get the global SecurityManager instance
 * 
 * @returns The SecurityManager singleton
 * @throws Error if not initialized (call initializeSecurity first)
 * 
 * @example
 * ```typescript
 * const security = getSecurity();
 * const status = security.getSecurityStatus();
 * ```
 */
export function getSecurity(): SecurityManager {
    if (!securityManager) {
        // Auto-initialize with defaults if not explicitly initialized
        securityManager = new SecurityManager();
        // Note: initialize() should be called for full functionality
        console.warn('[SECURITY] SecurityManager auto-initialized with defaults. Call initializeSecurity() for full configuration.');
    }
    return securityManager;
}

/**
 * Initialize the global security system
 * 
 * Should be called once at application startup with your configuration.
 * 
 * @param config Security configuration
 * @returns Promise resolving to the initialized SecurityManager
 * 
 * @example
 * ```typescript
 * await initializeSecurity({
 *     logLevel: LogLevel.INFO,
 *     logFormat: 'json',
 *     logFilePath: './audit.log',
 *     rateLimitPerMinute: 100,
 *     oauthKeysPath: './oauth_keys.json',
 *     credentialsPath: './credentials.json',
 * });
 * 
 * // Now you can use getSecurity() anywhere
 * const security = getSecurity();
 * ```
 */
export async function initializeSecurity(config: SecurityConfig = {}): Promise<SecurityManager> {
    securityManager = new SecurityManager(config);
    await securityManager.initialize();
    return securityManager;
}

/**
 * Shutdown the global security system
 * 
 * Call this during application shutdown to flush logs and clean up resources.
 * 
 * @example
 * ```typescript
 * process.on('SIGTERM', async () => {
 *     await shutdownSecurity();
 *     process.exit(0);
 * });
 * ```
 */
export async function shutdownSecurity(): Promise<void> {
    if (securityManager) {
        await securityManager.shutdown();
        securityManager = null;
    }
}

// ============================================================================
// Default Export
// ============================================================================

export default {
    // Classes
    SecurityManager,
    RateLimiter,
    AuditLogger,
    
    // Singleton functions
    initializeSecurity,
    getSecurity,
    shutdownSecurity,
    
    // Middleware hooks
    beforeRequest,
    afterRequest,
    wrapHandler,
    createTypedHandler,
    
    // Enums
    AuditEventType,
    LogLevel,
    
    // Validation
    validateEmail,
    validateFilename,
    validateSearchQuery,
    validateLabelName,
    
    // Credential security
    loadCredentialsSecurely,
    performSecurityAudit,
    shouldRefreshToken,
    sanitizeErrorMessage,
    
    // Rate limiting
    calculateBackoffDelay,
    parseRetryAfterHeader,
    
    // Audit logging
    initializeAuditLogger,
    getAuditLogger,
    logSecurityEvent,
    redactEmail,
};
