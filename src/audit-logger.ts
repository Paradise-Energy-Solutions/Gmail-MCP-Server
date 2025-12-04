/**
 * Audit Logging Module
 * 
 * Provides comprehensive audit logging for the Gmail MCP Server.
 * Features:
 * - Structured JSON logging for machine parsing
 * - Human-readable format for development
 * - Multiple log levels including SECURITY
 * - Sensitive data redaction
 * - File output with rotation support
 * - External log aggregation hooks
 */

import fs from 'fs';
import path from 'path';

// ============================================================================
// Enums
// ============================================================================

/**
 * Log levels for audit entries.
 * SECURITY level is always logged regardless of minimum level setting.
 */
export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    SECURITY = 4,
}

/**
 * Audit event types for categorizing logged actions.
 */
export enum AuditEventType {
    // Authentication events
    AUTH_SUCCESS = 'AUTH_SUCCESS',
    AUTH_FAILURE = 'AUTH_FAILURE',
    AUTH_REFRESH = 'AUTH_REFRESH',
    
    // Email operations
    EMAIL_READ = 'EMAIL_READ',
    EMAIL_SEND = 'EMAIL_SEND',
    EMAIL_DELETE = 'EMAIL_DELETE',
    EMAIL_MODIFY = 'EMAIL_MODIFY',
    
    // Label operations
    LABEL_CREATE = 'LABEL_CREATE',
    LABEL_DELETE = 'LABEL_DELETE',
    LABEL_MODIFY = 'LABEL_MODIFY',
    
    // Filter operations
    FILTER_CREATE = 'FILTER_CREATE',
    FILTER_DELETE = 'FILTER_DELETE',
    
    // Attachment operations
    ATTACHMENT_DOWNLOAD = 'ATTACHMENT_DOWNLOAD',
    ATTACHMENT_UPLOAD = 'ATTACHMENT_UPLOAD',
    
    // System events
    RATE_LIMIT_HIT = 'RATE_LIMIT_HIT',
    QUOTA_WARNING = 'QUOTA_WARNING',
    CONFIG_CHANGE = 'CONFIG_CHANGE',
    SECURITY_VIOLATION = 'SECURITY_VIOLATION',
}

// ============================================================================
// Interfaces
// ============================================================================

/**
 * PII handling mode configuration.
 */
export type PIIHandlingMode = 'redact' | 'hash' | 'domain_only' | 'omit';

/**
 * Log output format.
 */
export type LogFormat = 'json' | 'human';

/**
 * File rotation strategy.
 */
export type RotationStrategy = 'daily' | 'size';

/**
 * Configuration for the audit logger.
 */
export interface AuditConfig {
    /** Minimum log level to output (SECURITY always logged) */
    minLevel: LogLevel;
    
    /** Output format */
    format: LogFormat;
    
    /** Enable console output */
    consoleOutput: boolean;
    
    /** Enable file output */
    fileOutput: boolean;
    
    /** File output path (used if fileOutput is true) */
    filePath?: string;
    
    /** File rotation strategy */
    rotationStrategy?: RotationStrategy;
    
    /** Max file size in bytes for size-based rotation (default: 10MB) */
    maxFileSize?: number;
    
    /** Max number of rotated files to keep (default: 5) */
    maxFiles?: number;
    
    /** PII handling mode for email addresses */
    piiHandling: PIIHandlingMode;
    
    /** Enable batch/buffer mode for high throughput */
    batchMode?: boolean;
    
    /** Batch flush interval in milliseconds (default: 5000) */
    batchFlushInterval?: number;
    
    /** Maximum batch size before forced flush (default: 100) */
    maxBatchSize?: number;
    
    /** External log callback for aggregation systems */
    externalCallback?: (entry: AuditEntry) => void | Promise<void>;
    
    /** Application/service identifier */
    serviceId?: string;
    
    /** Include hostname in logs */
    includeHostname?: boolean;
}

/**
 * Structure of an audit log entry.
 */
export interface AuditEntry {
    /** ISO 8601 formatted timestamp */
    timestamp: string;
    
    /** Log level */
    level: LogLevel;
    
    /** Human-readable level name */
    levelName: string;
    
    /** Type of audit event */
    eventType: AuditEventType;
    
    /** User identifier (redacted if email) */
    userId?: string;
    
    /** Session identifier for request correlation */
    sessionId?: string;
    
    /** Operation being performed */
    operation: string;
    
    /** Resource identifier (e.g., message ID, label ID) */
    resourceId?: string;
    
    /** Resource type (e.g., 'email', 'label', 'filter') */
    resourceType?: string;
    
    /** Outcome of the operation */
    outcome: 'success' | 'failure' | 'blocked';
    
    /** Additional details (sanitized) */
    details?: Record<string, unknown>;
    
    /** Error code if applicable */
    errorCode?: string;
    
    /** Operation duration in milliseconds */
    duration?: number;
    
    /** Client IP address (if available) */
    ipAddress?: string;
    
    /** Service/application identifier */
    serviceId?: string;
    
    /** Hostname where the log was generated */
    hostname?: string;
}

/**
 * Context for wrapping operations with audit logging.
 */
export interface AuditContext {
    /** User identifier */
    userId?: string;
    
    /** Session identifier */
    sessionId?: string;
    
    /** Client IP address */
    ipAddress?: string;
    
    /** Parent operation for nested contexts */
    parentOperation?: string;
}

/**
 * Security event structure for dedicated security logging.
 */
export interface SecurityEvent {
    /** Type of security event */
    eventType: AuditEventType;
    
    /** Severity level */
    severity: 'low' | 'medium' | 'high' | 'critical';
    
    /** Description of the security event */
    description: string;
    
    /** Source of the event (e.g., 'auth', 'api', 'rate-limiter') */
    source: string;
    
    /** User involved (if known) */
    userId?: string;
    
    /** IP address involved */
    ipAddress?: string;
    
    /** Additional context */
    context?: Record<string, unknown>;
    
    /** Recommended action */
    recommendedAction?: string;
}

/**
 * Scoped operation logger interface.
 */
export interface OperationLogger {
    /** Log debug message */
    debug(message: string, details?: Record<string, unknown>): void;
    
    /** Log info message */
    info(message: string, details?: Record<string, unknown>): void;
    
    /** Log warning message */
    warn(message: string, details?: Record<string, unknown>): void;
    
    /** Log error message */
    error(message: string, errorCode?: string, details?: Record<string, unknown>): void;
    
    /** Log operation success */
    success(resourceId?: string, details?: Record<string, unknown>): void;
    
    /** Log operation failure */
    failure(errorCode: string, details?: Record<string, unknown>): void;
    
    /** Get elapsed time since logger creation */
    getElapsed(): number;
}

// ============================================================================
// Constants
// ============================================================================

/** Log level names for display */
const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
    [LogLevel.DEBUG]: 'DEBUG',
    [LogLevel.INFO]: 'INFO',
    [LogLevel.WARN]: 'WARN',
    [LogLevel.ERROR]: 'ERROR',
    [LogLevel.SECURITY]: 'SECURITY',
};

/** Default configuration values */
const DEFAULT_CONFIG: Partial<AuditConfig> = {
    minLevel: LogLevel.INFO,
    format: 'json',
    consoleOutput: true,
    fileOutput: false,
    piiHandling: 'redact',
    batchMode: false,
    batchFlushInterval: 5000,
    maxBatchSize: 100,
    maxFileSize: 10 * 1024 * 1024, // 10MB
    maxFiles: 5,
    includeHostname: false,
};

/** Fields that should never be logged */
const FORBIDDEN_FIELDS = new Set([
    'password',
    'secret',
    'token',
    'accessToken',
    'refreshToken',
    'access_token',
    'refresh_token',
    'client_secret',
    'clientSecret',
    'apiKey',
    'api_key',
    'authorization',
    'cookie',
    'sessionToken',
    'session_token',
    'privateKey',
    'private_key',
    'body',           // Email body content
    'content',        // Email content
    'subject',        // Email subject (PII)
    'htmlBody',       // HTML email content
    'textBody',       // Text email content
    'snippet',        // Email snippet
    'recipients',     // Recipient list
    'to',             // Email recipients
    'cc',             // Email CC
    'bcc',            // Email BCC
]);

/** Fields containing email addresses that need redaction */
const EMAIL_FIELDS = new Set([
    'email',
    'from',
    'sender',
    'replyTo',
    'reply_to',
    'userEmail',
    'user_email',
    'recipient',
]);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate a SHA-256 hash of a string (first 8 characters).
 * @param input String to hash
 * @returns Short hash string
 */
function shortHash(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).substring(0, 8);
}

/**
 * Redact an email address based on the configured handling mode.
 * @param email Email address to redact
 * @param mode PII handling mode
 * @returns Redacted email representation
 */
export function redactEmail(email: string, mode: PIIHandlingMode = 'redact'): string {
    if (!email || typeof email !== 'string') {
        return '[invalid-email]';
    }
    
    // Basic email validation
    const atIndex = email.indexOf('@');
    if (atIndex === -1) {
        return '[invalid-email]';
    }
    
    const localPart = email.substring(0, atIndex);
    const domain = email.substring(atIndex + 1);
    
    switch (mode) {
        case 'omit':
            return '[email-omitted]';
        
        case 'hash':
            return `[user:${shortHash(email)}@${domain}]`;
        
        case 'domain_only':
            return `[user@${domain}]`;
        
        case 'redact':
        default:
            // Show first character and domain
            const firstChar = localPart.charAt(0);
            return `${firstChar}***@${domain}`;
    }
}

/**
 * Redact sensitive fields from an object.
 * @param obj Object to sanitize
 * @param additionalFields Additional field names to redact
 * @returns New object with sensitive fields redacted
 */
export function redactSensitiveFields(
    obj: Record<string, unknown>,
    additionalFields: string[] = []
): Record<string, unknown> {
    if (!obj || typeof obj !== 'object') {
        return {};
    }
    
    const fieldsToRedact = new Set([...FORBIDDEN_FIELDS, ...additionalFields]);
    const result: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(obj)) {
        // Skip forbidden fields entirely
        if (fieldsToRedact.has(key)) {
            result[key] = '[REDACTED]';
            continue;
        }
        
        // Handle email fields
        if (EMAIL_FIELDS.has(key) && typeof value === 'string') {
            result[key] = redactEmail(value);
            continue;
        }
        
        // Recursively handle nested objects
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            result[key] = redactSensitiveFields(value as Record<string, unknown>, additionalFields);
            continue;
        }
        
        // Handle arrays
        if (Array.isArray(value)) {
            result[key] = value.map(item => {
                if (typeof item === 'string' && EMAIL_FIELDS.has(key)) {
                    return redactEmail(item);
                }
                if (item && typeof item === 'object') {
                    return redactSensitiveFields(item as Record<string, unknown>, additionalFields);
                }
                return item;
            });
            continue;
        }
        
        result[key] = value;
    }
    
    return result;
}

/**
 * Sanitize a file path for logging.
 * @param filePath File path to sanitize
 * @returns Sanitized path
 */
export function sanitizePathForLogging(filePath: string): string {
    if (!filePath) {
        return '[no-path]';
    }
    
    // Extract just the filename
    const filename = path.basename(filePath);
    
    // Check if it's a sensitive file type
    if (/\.(json|key|pem|crt|credentials|env)$/i.test(filename)) {
        return `[credential-file:${filename}]`;
    }
    
    return `[file:${filename}]`;
}

/**
 * Get current hostname safely.
 * @returns Hostname or 'unknown'
 */
function getHostname(): string {
    try {
        return require('os').hostname();
    } catch {
        return 'unknown';
    }
}

/**
 * Format a log entry for human-readable output.
 * @param entry Audit entry to format
 * @returns Formatted string
 */
function formatHumanReadable(entry: AuditEntry): string {
    const parts = [
        `[${entry.timestamp}]`,
        `[${entry.levelName}]`,
        `[${entry.eventType}]`,
        entry.operation,
    ];
    
    if (entry.userId) {
        parts.push(`user=${entry.userId}`);
    }
    
    if (entry.resourceType && entry.resourceId) {
        parts.push(`${entry.resourceType}=${entry.resourceId}`);
    }
    
    parts.push(`outcome=${entry.outcome}`);
    
    if (entry.duration !== undefined) {
        parts.push(`duration=${entry.duration}ms`);
    }
    
    if (entry.errorCode) {
        parts.push(`error=${entry.errorCode}`);
    }
    
    if (entry.details && Object.keys(entry.details).length > 0) {
        parts.push(`details=${JSON.stringify(entry.details)}`);
    }
    
    return parts.join(' ');
}

// ============================================================================
// Audit Logger Class
// ============================================================================

/**
 * Singleton audit logger instance.
 */
let loggerInstance: AuditLogger | null = null;

/**
 * Comprehensive audit logger for the Gmail MCP Server.
 * Implements singleton pattern for consistent logging across the application.
 */
export class AuditLogger {
    private config: Required<AuditConfig>;
    private batch: AuditEntry[] = [];
    private batchTimer: NodeJS.Timeout | null = null;
    private currentLogFile: string | null = null;
    private currentLogFileSize: number = 0;
    private currentLogDate: string | null = null;
    private fileStream: fs.WriteStream | null = null;
    private contextStack: AuditContext[] = [];
    
    /**
     * Create a new AuditLogger instance.
     * @param config Logger configuration
     */
    constructor(config: AuditConfig) {
        this.config = {
            ...DEFAULT_CONFIG,
            ...config,
            minLevel: config.minLevel ?? LogLevel.INFO,
            format: config.format ?? 'json',
            consoleOutput: config.consoleOutput ?? true,
            fileOutput: config.fileOutput ?? false,
            piiHandling: config.piiHandling ?? 'redact',
            batchMode: config.batchMode ?? false,
            batchFlushInterval: config.batchFlushInterval ?? 5000,
            maxBatchSize: config.maxBatchSize ?? 100,
            maxFileSize: config.maxFileSize ?? 10 * 1024 * 1024,
            maxFiles: config.maxFiles ?? 5,
            includeHostname: config.includeHostname ?? false,
            rotationStrategy: config.rotationStrategy ?? 'daily',
            filePath: config.filePath ?? './audit.log',
            serviceId: config.serviceId ?? 'gmail-mcp-server',
            externalCallback: config.externalCallback,
        } as Required<AuditConfig>;
        
        if (this.config.batchMode) {
            this.startBatchTimer();
        }
        
        if (this.config.fileOutput && this.config.filePath) {
            this.initializeFileOutput();
        }
    }
    
    /**
     * Initialize file output and rotation.
     */
    private initializeFileOutput(): void {
        const logDir = path.dirname(this.config.filePath);
        
        try {
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }
            
            this.rotateLogFileIfNeeded();
        } catch (error) {
            console.error('[AUDIT] Failed to initialize file output:', error);
            this.config.fileOutput = false;
        }
    }
    
    /**
     * Check and perform log file rotation if needed.
     */
    private rotateLogFileIfNeeded(): void {
        const today = new Date().toISOString().split('T')[0];
        const basePath = this.config.filePath;
        
        // Check if rotation is needed
        let needsRotation = false;
        
        if (this.config.rotationStrategy === 'daily') {
            if (this.currentLogDate !== today) {
                needsRotation = true;
            }
        } else if (this.config.rotationStrategy === 'size') {
            if (this.currentLogFileSize >= this.config.maxFileSize) {
                needsRotation = true;
            }
        }
        
        if (needsRotation || !this.currentLogFile) {
            // Close existing stream
            if (this.fileStream) {
                this.fileStream.end();
                this.fileStream = null;
            }
            
            // Generate new filename
            const ext = path.extname(basePath);
            const base = path.basename(basePath, ext);
            const dir = path.dirname(basePath);
            
            if (this.config.rotationStrategy === 'daily') {
                this.currentLogFile = path.join(dir, `${base}-${today}${ext}`);
            } else {
                const timestamp = Date.now();
                this.currentLogFile = path.join(dir, `${base}-${timestamp}${ext}`);
            }
            
            this.currentLogDate = today;
            this.currentLogFileSize = 0;
            
            // Clean up old files
            this.cleanupOldLogFiles(dir, base, ext);
            
            // Create new write stream
            this.fileStream = fs.createWriteStream(this.currentLogFile, { flags: 'a' });
        }
    }
    
    /**
     * Remove old log files beyond the retention limit.
     */
    private cleanupOldLogFiles(dir: string, base: string, ext: string): void {
        try {
            const files = fs.readdirSync(dir)
                .filter(f => f.startsWith(base) && f.endsWith(ext))
                .map(f => ({
                    name: f,
                    path: path.join(dir, f),
                    stat: fs.statSync(path.join(dir, f)),
                }))
                .sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
            
            // Remove files beyond maxFiles limit
            for (let i = this.config.maxFiles; i < files.length; i++) {
                try {
                    fs.unlinkSync(files[i].path);
                } catch {
                    // Ignore deletion errors
                }
            }
        } catch {
            // Ignore cleanup errors
        }
    }
    
    /**
     * Start the batch flush timer.
     */
    private startBatchTimer(): void {
        if (this.batchTimer) {
            clearInterval(this.batchTimer);
        }
        
        this.batchTimer = setInterval(() => {
            this.flushBatch();
        }, this.config.batchFlushInterval);
        
        // Ensure timer doesn't prevent process exit
        if (this.batchTimer.unref) {
            this.batchTimer.unref();
        }
    }
    
    /**
     * Flush the batch of log entries.
     */
    public async flushBatch(): Promise<void> {
        if (this.batch.length === 0) {
            return;
        }
        
        const entries = [...this.batch];
        this.batch = [];
        
        for (const entry of entries) {
            await this.writeEntry(entry);
        }
    }
    
    /**
     * Write a single log entry to all configured outputs.
     */
    private async writeEntry(entry: AuditEntry): Promise<void> {
        const formatted = this.config.format === 'json'
            ? JSON.stringify(entry)
            : formatHumanReadable(entry);
        
        // Console output
        if (this.config.consoleOutput) {
            if (entry.level >= LogLevel.ERROR) {
                console.error(formatted);
            } else {
                console.log(formatted);
            }
        }
        
        // File output
        if (this.config.fileOutput && this.fileStream) {
            this.rotateLogFileIfNeeded();
            const line = formatted + '\n';
            this.fileStream.write(line);
            this.currentLogFileSize += Buffer.byteLength(line);
        }
        
        // External callback
        if (this.config.externalCallback) {
            try {
                await this.config.externalCallback(entry);
            } catch (error) {
                // Log callback errors to stderr but don't fail
                console.error('[AUDIT] External callback error:', error);
            }
        }
    }
    
    /**
     * Get the current audit context.
     */
    private getCurrentContext(): AuditContext {
        return this.contextStack.length > 0
            ? this.contextStack[this.contextStack.length - 1]
            : {};
    }
    
    /**
     * Push a new context onto the stack.
     */
    public pushContext(context: AuditContext): void {
        this.contextStack.push({
            ...this.getCurrentContext(),
            ...context,
        });
    }
    
    /**
     * Pop the current context from the stack.
     */
    public popContext(): AuditContext | undefined {
        return this.contextStack.pop();
    }
    
    /**
     * Create an audit entry with common fields populated.
     */
    private createEntry(
        level: LogLevel,
        eventType: AuditEventType,
        operation: string,
        outcome: 'success' | 'failure' | 'blocked',
        options: Partial<AuditEntry> = {}
    ): AuditEntry {
        const context = this.getCurrentContext();
        
        const entry: AuditEntry = {
            timestamp: new Date().toISOString(),
            level,
            levelName: LOG_LEVEL_NAMES[level],
            eventType,
            operation,
            outcome,
            serviceId: this.config.serviceId,
            ...options,
        };
        
        // Add context fields
        if (context.userId || options.userId) {
            entry.userId = options.userId ?? context.userId;
            // Redact if it looks like an email
            if (entry.userId && entry.userId.includes('@')) {
                entry.userId = redactEmail(entry.userId, this.config.piiHandling);
            }
        }
        
        if (context.sessionId || options.sessionId) {
            entry.sessionId = options.sessionId ?? context.sessionId;
        }
        
        if (context.ipAddress || options.ipAddress) {
            entry.ipAddress = options.ipAddress ?? context.ipAddress;
        }
        
        if (this.config.includeHostname) {
            entry.hostname = getHostname();
        }
        
        // Sanitize details
        if (options.details) {
            entry.details = redactSensitiveFields(options.details);
        }
        
        return entry;
    }
    
    /**
     * Log an entry (handles batching if enabled).
     */
    private async logEntry(entry: AuditEntry): Promise<void> {
        // SECURITY level is always logged immediately
        if (entry.level === LogLevel.SECURITY) {
            await this.writeEntry(entry);
            return;
        }
        
        // Check minimum level
        if (entry.level < this.config.minLevel) {
            return;
        }
        
        if (this.config.batchMode) {
            this.batch.push(entry);
            
            // Force flush if batch is full
            if (this.batch.length >= this.config.maxBatchSize) {
                await this.flushBatch();
            }
        } else {
            await this.writeEntry(entry);
        }
    }
    
    // ========================================================================
    // Public Logging Methods
    // ========================================================================
    
    /**
     * Log a debug message.
     * @param eventType Event type
     * @param operation Operation name
     * @param details Additional details
     */
    public debug(
        eventType: AuditEventType,
        operation: string,
        details?: Record<string, unknown>
    ): void {
        const entry = this.createEntry(LogLevel.DEBUG, eventType, operation, 'success', { details });
        this.logEntry(entry);
    }
    
    /**
     * Log an info message.
     * @param eventType Event type
     * @param operation Operation name
     * @param outcome Operation outcome
     * @param options Additional entry options
     */
    public info(
        eventType: AuditEventType,
        operation: string,
        outcome: 'success' | 'failure' | 'blocked' = 'success',
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.INFO, eventType, operation, outcome, options);
        this.logEntry(entry);
    }
    
    /**
     * Log a warning message.
     * @param eventType Event type
     * @param operation Operation name
     * @param options Additional entry options
     */
    public warn(
        eventType: AuditEventType,
        operation: string,
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.WARN, eventType, operation, 'failure', options);
        this.logEntry(entry);
    }
    
    /**
     * Log an error message.
     * @param eventType Event type
     * @param operation Operation name
     * @param errorCode Error code
     * @param options Additional entry options
     */
    public error(
        eventType: AuditEventType,
        operation: string,
        errorCode: string,
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.ERROR, eventType, operation, 'failure', {
            ...options,
            errorCode,
        });
        this.logEntry(entry);
    }
    
    /**
     * Log a security event (always logged regardless of level).
     * @param event Security event details
     */
    public logSecurityEvent(event: SecurityEvent): void {
        const entry = this.createEntry(
            LogLevel.SECURITY,
            event.eventType,
            `[${event.severity.toUpperCase()}] ${event.description}`,
            'blocked',
            {
                userId: event.userId,
                ipAddress: event.ipAddress,
                details: {
                    source: event.source,
                    severity: event.severity,
                    recommendedAction: event.recommendedAction,
                    ...event.context,
                },
            }
        );
        this.logEntry(entry);
    }
    
    /**
     * Log an authentication event.
     * @param eventType Auth event type
     * @param success Whether authentication succeeded
     * @param options Additional options
     */
    public logAuth(
        eventType: AuditEventType.AUTH_SUCCESS | AuditEventType.AUTH_FAILURE | AuditEventType.AUTH_REFRESH,
        success: boolean,
        options?: Partial<AuditEntry>
    ): void {
        const level = success ? LogLevel.INFO : LogLevel.WARN;
        const outcome = success ? 'success' : 'failure';
        const entry = this.createEntry(level, eventType, 'authentication', outcome, options);
        this.logEntry(entry);
    }
    
    /**
     * Log an email operation.
     * @param eventType Email event type
     * @param messageId Message ID
     * @param outcome Operation outcome
     * @param options Additional options
     */
    public logEmailOperation(
        eventType: AuditEventType.EMAIL_READ | AuditEventType.EMAIL_SEND | AuditEventType.EMAIL_DELETE | AuditEventType.EMAIL_MODIFY,
        messageId: string,
        outcome: 'success' | 'failure' | 'blocked',
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.INFO, eventType, eventType.toLowerCase(), outcome, {
            ...options,
            resourceId: messageId,
            resourceType: 'email',
        });
        this.logEntry(entry);
    }
    
    /**
     * Log a label operation.
     * @param eventType Label event type
     * @param labelId Label ID
     * @param outcome Operation outcome
     * @param options Additional options
     */
    public logLabelOperation(
        eventType: AuditEventType.LABEL_CREATE | AuditEventType.LABEL_DELETE | AuditEventType.LABEL_MODIFY,
        labelId: string,
        outcome: 'success' | 'failure' | 'blocked',
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.INFO, eventType, eventType.toLowerCase(), outcome, {
            ...options,
            resourceId: labelId,
            resourceType: 'label',
        });
        this.logEntry(entry);
    }
    
    /**
     * Log a filter operation.
     * @param eventType Filter event type
     * @param filterId Filter ID
     * @param outcome Operation outcome
     * @param options Additional options
     */
    public logFilterOperation(
        eventType: AuditEventType.FILTER_CREATE | AuditEventType.FILTER_DELETE,
        filterId: string,
        outcome: 'success' | 'failure' | 'blocked',
        options?: Partial<AuditEntry>
    ): void {
        const entry = this.createEntry(LogLevel.INFO, eventType, eventType.toLowerCase(), outcome, {
            ...options,
            resourceId: filterId,
            resourceType: 'filter',
        });
        this.logEntry(entry);
    }
    
    /**
     * Log a rate limit or quota event.
     * @param eventType Rate limit or quota event type
     * @param details Event details
     */
    public logRateLimitEvent(
        eventType: AuditEventType.RATE_LIMIT_HIT | AuditEventType.QUOTA_WARNING,
        details: Record<string, unknown>
    ): void {
        const level = eventType === AuditEventType.RATE_LIMIT_HIT ? LogLevel.WARN : LogLevel.INFO;
        const entry = this.createEntry(level, eventType, 'rate_limit_check', 'blocked', { details });
        this.logEntry(entry);
    }
    
    /**
     * Create a scoped operation logger.
     * @param operation Operation name
     * @param eventType Default event type for this operation
     * @param context Additional context
     * @returns Scoped operation logger
     */
    public createOperationLogger(
        operation: string,
        eventType: AuditEventType,
        context?: Partial<AuditContext>
    ): OperationLogger {
        const startTime = Date.now();
        const logger = this;
        
        if (context) {
            this.pushContext(context);
        }
        
        return {
            debug(message: string, details?: Record<string, unknown>): void {
                logger.debug(eventType, `${operation}: ${message}`, details);
            },
            
            info(message: string, details?: Record<string, unknown>): void {
                logger.info(eventType, `${operation}: ${message}`, 'success', { details });
            },
            
            warn(message: string, details?: Record<string, unknown>): void {
                logger.warn(eventType, `${operation}: ${message}`, { details });
            },
            
            error(message: string, errorCode?: string, details?: Record<string, unknown>): void {
                logger.error(eventType, `${operation}: ${message}`, errorCode ?? 'UNKNOWN_ERROR', { details });
            },
            
            success(resourceId?: string, details?: Record<string, unknown>): void {
                logger.info(eventType, operation, 'success', {
                    resourceId,
                    duration: Date.now() - startTime,
                    details,
                });
                if (context) {
                    logger.popContext();
                }
            },
            
            failure(errorCode: string, details?: Record<string, unknown>): void {
                logger.error(eventType, operation, errorCode, {
                    duration: Date.now() - startTime,
                    details,
                });
                if (context) {
                    logger.popContext();
                }
            },
            
            getElapsed(): number {
                return Date.now() - startTime;
            },
        };
    }
    
    /**
     * Execute a function within an audit context.
     * @param context Audit context for the operation
     * @param fn Function to execute
     * @returns Result of the function
     */
    public async withAuditContext<T>(
        context: AuditContext,
        fn: () => T | Promise<T>
    ): Promise<T> {
        this.pushContext(context);
        try {
            return await fn();
        } finally {
            this.popContext();
        }
    }
    
    /**
     * Shutdown the logger, flushing any pending entries.
     */
    public async shutdown(): Promise<void> {
        // Stop batch timer
        if (this.batchTimer) {
            clearInterval(this.batchTimer);
            this.batchTimer = null;
        }
        
        // Flush remaining batch entries
        await this.flushBatch();
        
        // Close file stream
        if (this.fileStream) {
            await new Promise<void>((resolve) => {
                this.fileStream!.end(resolve);
            });
            this.fileStream = null;
        }
    }
    
    /**
     * Update logger configuration.
     * @param updates Configuration updates
     */
    public updateConfig(updates: Partial<AuditConfig>): void {
        const oldBatchMode = this.config.batchMode;
        const oldFileOutput = this.config.fileOutput;
        
        Object.assign(this.config, updates);
        
        // Handle batch mode changes
        if (updates.batchMode !== undefined && updates.batchMode !== oldBatchMode) {
            if (updates.batchMode) {
                this.startBatchTimer();
            } else {
                if (this.batchTimer) {
                    clearInterval(this.batchTimer);
                    this.batchTimer = null;
                }
                this.flushBatch();
            }
        }
        
        // Handle file output changes
        if (updates.fileOutput !== undefined && updates.fileOutput !== oldFileOutput) {
            if (updates.fileOutput && this.config.filePath) {
                this.initializeFileOutput();
            } else if (this.fileStream) {
                this.fileStream.end();
                this.fileStream = null;
            }
        }
        
        // Log config change
        this.info(
            AuditEventType.CONFIG_CHANGE,
            'audit_logger_config_update',
            'success',
            { details: { updatedFields: Object.keys(updates) } }
        );
    }
}

// ============================================================================
// Module-Level Functions
// ============================================================================

/**
 * Initialize the global audit logger instance.
 * @param config Logger configuration
 * @returns The initialized AuditLogger instance
 */
export function initializeAuditLogger(config: AuditConfig): AuditLogger {
    if (loggerInstance) {
        // Update existing instance
        loggerInstance.updateConfig(config);
    } else {
        loggerInstance = new AuditLogger(config);
    }
    return loggerInstance;
}

/**
 * Get the global audit logger instance.
 * @returns The AuditLogger instance
 * @throws Error if logger has not been initialized
 */
export function getAuditLogger(): AuditLogger {
    if (!loggerInstance) {
        // Auto-initialize with defaults if not initialized
        loggerInstance = new AuditLogger({
            minLevel: LogLevel.INFO,
            format: 'json',
            consoleOutput: true,
            fileOutput: false,
            piiHandling: 'redact',
        });
    }
    return loggerInstance;
}

/**
 * Create an operation logger for a specific operation.
 * Convenience wrapper around getAuditLogger().createOperationLogger().
 * @param operation Operation name
 * @param eventType Event type
 * @param context Optional context
 * @returns Operation logger
 */
export function createOperationLogger(
    operation: string,
    eventType: AuditEventType,
    context?: Partial<AuditContext>
): OperationLogger {
    return getAuditLogger().createOperationLogger(operation, eventType, context);
}

/**
 * Execute a function within an audit context.
 * Convenience wrapper around getAuditLogger().withAuditContext().
 * @param context Audit context
 * @param fn Function to execute
 * @returns Function result
 */
export async function withAuditContext<T>(
    context: AuditContext,
    fn: () => T | Promise<T>
): Promise<T> {
    return getAuditLogger().withAuditContext(context, fn);
}

/**
 * Log a security event.
 * Convenience wrapper around getAuditLogger().logSecurityEvent().
 * @param event Security event to log
 */
export function logSecurityEvent(event: SecurityEvent): void {
    getAuditLogger().logSecurityEvent(event);
}

// ============================================================================
// Default Export
// ============================================================================

export default {
    LogLevel,
    AuditEventType,
    AuditLogger,
    initializeAuditLogger,
    getAuditLogger,
    createOperationLogger,
    withAuditContext,
    logSecurityEvent,
    redactEmail,
    redactSensitiveFields,
    sanitizePathForLogging,
};
