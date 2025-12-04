/**
 * Credential Security Module
 * 
 * Provides secure credential handling, OAuth scope management,
 * token refresh logic, and error message sanitization.
 */

import fs from 'fs';
import path from 'path';

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface Credentials {
    clientId: string;
    clientSecret: string;
    refreshToken?: string;
    accessToken?: string;
    expiryDate?: number;
}

export interface OAuthKeys {
    client_id: string;
    client_secret: string;
    redirect_uris?: string[];
}

export interface TokenInfo {
    access_token?: string;
    refresh_token?: string;
    expiry_date?: number;
    token_type?: string;
    scope?: string;
}

export interface CredentialValidationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
}

export interface CredentialLoadResult {
    source: 'environment' | 'file' | 'none';
    credentials: Credentials | null;
    warnings: string[];
}

export type ScopePreset = 'MINIMAL' | 'STANDARD' | 'FULL';

// ============================================================================
// OAuth Scope Presets
// ============================================================================

/**
 * OAuth scope presets for different access levels.
 * Use the minimal scope necessary for your operations.
 */
export const OAUTH_SCOPES = {
    /** Read-only access to Gmail */
    MINIMAL: ['https://www.googleapis.com/auth/gmail.readonly'],
    
    /** Read and send access (no modify/delete) */
    STANDARD: [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.send',
    ],
    
    /** Full access including modify and label operations */
    FULL: [
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/gmail.send',
    ],
} as const;

/**
 * Individual scope definitions for granular control
 */
export const GMAIL_SCOPES = {
    READONLY: 'https://www.googleapis.com/auth/gmail.readonly',
    SEND: 'https://www.googleapis.com/auth/gmail.send',
    MODIFY: 'https://www.googleapis.com/auth/gmail.modify',
    SETTINGS_BASIC: 'https://www.googleapis.com/auth/gmail.settings.basic',
    COMPOSE: 'https://www.googleapis.com/auth/gmail.compose',
    INSERT: 'https://www.googleapis.com/auth/gmail.insert',
    LABELS: 'https://www.googleapis.com/auth/gmail.labels',
} as const;

/**
 * Get OAuth scopes for a given preset
 */
export function getScopesForPreset(preset: ScopePreset): string[] {
    return [...OAUTH_SCOPES[preset]];
}

/**
 * Validate that requested scopes are known and safe
 */
export function validateScopes(scopes: string[]): { valid: boolean; unknownScopes: string[] } {
    const knownScopes = new Set<string>(Object.values(GMAIL_SCOPES));
    const unknownScopes = scopes.filter(scope => !knownScopes.has(scope));
    return {
        valid: unknownScopes.length === 0,
        unknownScopes,
    };
}

// ============================================================================
// File Permission Management
// ============================================================================

const SECURE_FILE_MODE = 0o600; // Owner read/write only

/**
 * Enforce secure permissions (0600) on credential files.
 * @param filePath Path to the credential file
 * @returns true if permissions were set successfully
 */
export function enforceCredentialPermissions(filePath: string): boolean {
    try {
        if (!fs.existsSync(filePath)) {
            return false;
        }
        fs.chmodSync(filePath, SECURE_FILE_MODE);
        return true;
    } catch (error) {
        // Log warning without exposing the full path
        const sanitizedPath = sanitizePathForLogging(filePath);
        console.warn(`[SECURITY WARNING] Could not set permissions on credential file: ${sanitizedPath}`);
        return false;
    }
}

/**
 * Check if a credential file has secure permissions (0600).
 * @param filePath Path to the credential file
 * @returns true if permissions are secure
 */
export function checkCredentialPermissions(filePath: string): boolean {
    try {
        if (!fs.existsSync(filePath)) {
            return true; // Non-existent file doesn't have insecure permissions
        }
        const stats = fs.statSync(filePath);
        const mode = stats.mode & 0o777;
        return mode === SECURE_FILE_MODE;
    } catch (error) {
        return false;
    }
}

/**
 * Check and warn about insecure file permissions.
 * @param filePath Path to the credential file
 * @returns Array of security warnings
 */
export function auditCredentialFilePermissions(filePath: string): string[] {
    const warnings: string[] = [];
    
    try {
        if (!fs.existsSync(filePath)) {
            return warnings;
        }
        
        const stats = fs.statSync(filePath);
        const mode = stats.mode & 0o777;
        
        // Check for group read/write
        if (mode & 0o070) {
            warnings.push(`[SECURITY WARNING] Credential file has group permissions. Run: chmod 600 <credential-file>`);
        }
        
        // Check for world read/write
        if (mode & 0o007) {
            warnings.push(`[SECURITY CRITICAL] Credential file is world-readable/writable! Immediate action required.`);
        }
        
        // Check for write permissions beyond owner
        if (mode & 0o022) {
            warnings.push(`[SECURITY WARNING] Credential file has write permissions for group/others.`);
        }
        
    } catch (error) {
        warnings.push(`[SECURITY WARNING] Could not audit credential file permissions.`);
    }
    
    return warnings;
}

// ============================================================================
// Credential Validation
// ============================================================================

/**
 * Validate OAuth keys file structure before loading.
 * @param content Parsed JSON content of the OAuth keys file
 * @returns Validation result with errors and warnings
 */
export function validateOAuthKeysStructure(content: unknown): CredentialValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    if (!content || typeof content !== 'object') {
        errors.push('OAuth keys file is empty or not a valid JSON object');
        return { valid: false, errors, warnings };
    }
    
    const obj = content as Record<string, unknown>;
    
    // Check for 'installed' or 'web' credentials
    const keys = obj.installed || obj.web;
    
    if (!keys || typeof keys !== 'object') {
        errors.push('OAuth keys file must contain either "installed" or "web" credentials object');
        return { valid: false, errors, warnings };
    }
    
    const keysObj = keys as Record<string, unknown>;
    
    // Validate required fields
    if (!keysObj.client_id || typeof keysObj.client_id !== 'string') {
        errors.push('Missing or invalid "client_id" in OAuth keys');
    }
    
    if (!keysObj.client_secret || typeof keysObj.client_secret !== 'string') {
        errors.push('Missing or invalid "client_secret" in OAuth keys');
    }
    
    // Validate client_id format (basic check)
    if (typeof keysObj.client_id === 'string') {
        if (!keysObj.client_id.includes('.apps.googleusercontent.com')) {
            warnings.push('client_id does not appear to be a valid Google OAuth client ID');
        }
    }
    
    // Check for redirect_uris
    if (!keysObj.redirect_uris || !Array.isArray(keysObj.redirect_uris)) {
        warnings.push('No redirect_uris specified in OAuth keys');
    }
    
    return { valid: errors.length === 0, errors, warnings };
}

/**
 * Validate stored credentials/token file structure.
 * @param content Parsed JSON content of the credentials file
 * @returns Validation result with errors and warnings
 */
export function validateCredentialsStructure(content: unknown): CredentialValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    if (!content || typeof content !== 'object') {
        errors.push('Credentials file is empty or not a valid JSON object');
        return { valid: false, errors, warnings };
    }
    
    const creds = content as Record<string, unknown>;
    
    // Check for refresh token (required for offline access)
    if (!creds.refresh_token || typeof creds.refresh_token !== 'string') {
        warnings.push('No refresh_token found - may need to re-authenticate');
    }
    
    // Check for access token
    if (!creds.access_token || typeof creds.access_token !== 'string') {
        warnings.push('No access_token found - will need to refresh on first use');
    }
    
    // Check expiry date
    if (creds.expiry_date) {
        if (typeof creds.expiry_date !== 'number') {
            warnings.push('expiry_date is not a valid timestamp');
        } else if (creds.expiry_date < Date.now()) {
            warnings.push('access_token has expired - will attempt refresh');
        }
    }
    
    return { valid: errors.length === 0, errors, warnings };
}

// ============================================================================
// Environment Variable Credential Loading
// ============================================================================

/**
 * Environment variable names for credentials
 */
export const ENV_VAR_NAMES = {
    CLIENT_ID: 'GMAIL_MCP_CLIENT_ID',
    CLIENT_SECRET: 'GMAIL_MCP_CLIENT_SECRET',
    REFRESH_TOKEN: 'GMAIL_MCP_REFRESH_TOKEN',
    ACCESS_TOKEN: 'GMAIL_MCP_ACCESS_TOKEN',
    EXPIRY_DATE: 'GMAIL_MCP_EXPIRY_DATE',
} as const;

/**
 * Load credentials from environment variables.
 * This is the preferred method for production deployments.
 * @returns Credentials object if all required env vars are set, null otherwise
 */
export function loadCredentialsFromEnv(): Credentials | null {
    const clientId = process.env[ENV_VAR_NAMES.CLIENT_ID];
    const clientSecret = process.env[ENV_VAR_NAMES.CLIENT_SECRET];
    const refreshToken = process.env[ENV_VAR_NAMES.REFRESH_TOKEN];
    const accessToken = process.env[ENV_VAR_NAMES.ACCESS_TOKEN];
    const expiryDateStr = process.env[ENV_VAR_NAMES.EXPIRY_DATE];
    
    // Require at minimum client ID, secret, and refresh token
    if (!clientId || !clientSecret || !refreshToken) {
        return null;
    }
    
    const credentials: Credentials = {
        clientId,
        clientSecret,
        refreshToken,
    };
    
    if (accessToken) {
        credentials.accessToken = accessToken;
    }
    
    if (expiryDateStr) {
        const expiryDate = parseInt(expiryDateStr, 10);
        if (!isNaN(expiryDate)) {
            credentials.expiryDate = expiryDate;
        }
    }
    
    return credentials;
}

/**
 * Check which credential environment variables are set.
 * Useful for debugging without exposing actual values.
 */
export function checkEnvVarsPresent(): Record<string, boolean> {
    return {
        [ENV_VAR_NAMES.CLIENT_ID]: !!process.env[ENV_VAR_NAMES.CLIENT_ID],
        [ENV_VAR_NAMES.CLIENT_SECRET]: !!process.env[ENV_VAR_NAMES.CLIENT_SECRET],
        [ENV_VAR_NAMES.REFRESH_TOKEN]: !!process.env[ENV_VAR_NAMES.REFRESH_TOKEN],
        [ENV_VAR_NAMES.ACCESS_TOKEN]: !!process.env[ENV_VAR_NAMES.ACCESS_TOKEN],
        [ENV_VAR_NAMES.EXPIRY_DATE]: !!process.env[ENV_VAR_NAMES.EXPIRY_DATE],
    };
}

// ============================================================================
// Secure Credential Loading (Prefers Env Vars)
// ============================================================================

/**
 * Load credentials securely, preferring environment variables over file storage.
 * @param oauthKeysPath Path to OAuth keys file (fallback)
 * @param credentialsPath Path to credentials/token file (fallback)
 * @returns Credential load result with source and any warnings
 */
export function loadCredentialsSecurely(
    oauthKeysPath: string,
    credentialsPath: string
): CredentialLoadResult {
    const warnings: string[] = [];
    
    // Try environment variables first (preferred for production)
    const envCredentials = loadCredentialsFromEnv();
    if (envCredentials) {
        console.log('[SECURITY] Credentials loaded from environment variables (recommended)');
        return {
            source: 'environment',
            credentials: envCredentials,
            warnings: [],
        };
    }
    
    // Fall back to file-based credentials
    warnings.push('[SECURITY NOTICE] Using file-based credentials. Consider using environment variables for production.');
    
    // Check and warn about file permissions
    const oauthPermWarnings = auditCredentialFilePermissions(oauthKeysPath);
    const credPermWarnings = auditCredentialFilePermissions(credentialsPath);
    warnings.push(...oauthPermWarnings, ...credPermWarnings);
    
    // Attempt to enforce secure permissions
    if (fs.existsSync(oauthKeysPath)) {
        enforceCredentialPermissions(oauthKeysPath);
    }
    if (fs.existsSync(credentialsPath)) {
        enforceCredentialPermissions(credentialsPath);
    }
    
    // Load and validate OAuth keys
    if (!fs.existsSync(oauthKeysPath)) {
        return {
            source: 'none',
            credentials: null,
            warnings: [...warnings, 'OAuth keys file not found'],
        };
    }
    
    try {
        const oauthContent = JSON.parse(fs.readFileSync(oauthKeysPath, 'utf8'));
        const oauthValidation = validateOAuthKeysStructure(oauthContent);
        
        if (!oauthValidation.valid) {
            return {
                source: 'none',
                credentials: null,
                warnings: [...warnings, ...oauthValidation.errors],
            };
        }
        warnings.push(...oauthValidation.warnings);
        
        const keys = oauthContent.installed || oauthContent.web;
        
        const credentials: Credentials = {
            clientId: keys.client_id,
            clientSecret: keys.client_secret,
        };
        
        // Load stored tokens if available
        if (fs.existsSync(credentialsPath)) {
            const tokenContent = JSON.parse(fs.readFileSync(credentialsPath, 'utf8'));
            const tokenValidation = validateCredentialsStructure(tokenContent);
            warnings.push(...tokenValidation.warnings);
            
            if (tokenContent.refresh_token) {
                credentials.refreshToken = tokenContent.refresh_token;
            }
            if (tokenContent.access_token) {
                credentials.accessToken = tokenContent.access_token;
            }
            if (tokenContent.expiry_date) {
                credentials.expiryDate = tokenContent.expiry_date;
            }
        }
        
        return {
            source: 'file',
            credentials,
            warnings,
        };
        
    } catch (error) {
        return {
            source: 'none',
            credentials: null,
            warnings: [...warnings, 'Failed to parse credential files'],
        };
    }
}

// ============================================================================
// Token Expiration Management
// ============================================================================

/** Default threshold for token refresh (5 minutes before expiry) */
export const DEFAULT_REFRESH_THRESHOLD_MS = 5 * 60 * 1000;

/**
 * Check if an access token is expired or near expiration.
 * @param expiryDate Token expiry timestamp in milliseconds
 * @param thresholdMs Threshold before expiry to consider "near expiration" (default: 5 min)
 * @returns Object indicating expiration status
 */
export function checkTokenExpiration(
    expiryDate: number | undefined,
    thresholdMs: number = DEFAULT_REFRESH_THRESHOLD_MS
): { isExpired: boolean; isNearExpiry: boolean; msUntilExpiry: number | null } {
    if (!expiryDate) {
        return { isExpired: true, isNearExpiry: true, msUntilExpiry: null };
    }
    
    const now = Date.now();
    const msUntilExpiry = expiryDate - now;
    
    return {
        isExpired: msUntilExpiry <= 0,
        isNearExpiry: msUntilExpiry <= thresholdMs,
        msUntilExpiry: msUntilExpiry > 0 ? msUntilExpiry : 0,
    };
}

/**
 * Determine if a token refresh is needed before making an API call.
 * @param expiryDate Token expiry timestamp in milliseconds
 * @param thresholdMs Threshold for proactive refresh (default: 5 min)
 * @returns true if refresh is recommended
 */
export function shouldRefreshToken(
    expiryDate: number | undefined,
    thresholdMs: number = DEFAULT_REFRESH_THRESHOLD_MS
): boolean {
    const status = checkTokenExpiration(expiryDate, thresholdMs);
    return status.isExpired || status.isNearExpiry;
}

/**
 * Log a token refresh event without exposing sensitive data.
 * @param success Whether the refresh was successful
 * @param errorMessage Optional sanitized error message if failed
 */
export function logTokenRefreshEvent(success: boolean, errorMessage?: string): void {
    const timestamp = new Date().toISOString();
    if (success) {
        console.log(`[${timestamp}] [AUTH] Token refreshed successfully`);
    } else {
        console.error(`[${timestamp}] [AUTH] Token refresh failed: ${errorMessage || 'Unknown error'}`);
    }
}

// ============================================================================
// Error Message Sanitization
// ============================================================================

/**
 * Patterns to detect and sanitize in error messages
 */
const SENSITIVE_PATTERNS = [
    // File paths - common credential locations
    /\/[\w\-\.\/]+\.(json|key|pem|crt|credentials)/gi,
    // Home directory paths
    /\/home\/[\w\-]+\//gi,
    /\/Users\/[\w\-]+\//gi,
    // Windows paths
    /[A-Z]:\\[\w\-\\.\\]+/gi,
    // Access tokens (Bearer tokens)
    /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/gi,
    // OAuth tokens (ya29.* format for Google)
    /ya29\.[A-Za-z0-9\-_]+/gi,
    // Refresh tokens
    /1\/\/[A-Za-z0-9\-_]+/gi,
    // Generic JWT-like tokens
    /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/gi,
    // Client secrets
    /GOCSPX-[A-Za-z0-9\-_]+/gi,
    // API keys
    /AIza[A-Za-z0-9\-_]{35}/gi,
    // Email addresses in error context (might be partial credentials)
    /client.*id.*[\w\-]+\.apps\.googleusercontent\.com/gi,
];

/**
 * Replacement placeholders for sanitized content
 */
const SANITIZED_PLACEHOLDERS: Record<string, string> = {
    path: '[REDACTED_PATH]',
    token: '[REDACTED_TOKEN]',
    secret: '[REDACTED_SECRET]',
    credential: '[REDACTED]',
};

/**
 * Sanitize a file path for safe logging.
 * Replaces the full path with just the filename or a placeholder.
 * @param filePath The file path to sanitize
 * @returns Sanitized path suitable for logging
 */
export function sanitizePathForLogging(filePath: string): string {
    // Extract just the filename without the directory path
    const filename = path.basename(filePath);
    // Check if it's a sensitive filename
    if (/\.(json|key|pem|crt|credentials)$/i.test(filename)) {
        return `[credential-file:${filename}]`;
    }
    return `[file:${filename}]`;
}

/**
 * Sanitize an error message for external display.
 * Removes credential paths, tokens, and other sensitive data.
 * @param message The error message to sanitize
 * @returns Sanitized message safe for external display
 */
export function sanitizeErrorMessage(message: string): string {
    let sanitized = message;
    
    for (const pattern of SENSITIVE_PATTERNS) {
        sanitized = sanitized.replace(pattern, SANITIZED_PLACEHOLDERS.credential);
    }
    
    return sanitized;
}

/**
 * Create a safe error for external consumers while preserving details internally.
 * @param error The original error
 * @param context Additional context about where the error occurred
 * @returns Object with both sanitized external message and full internal details
 */
export function createSafeAuthError(
    error: Error | unknown,
    context: string
): { external: string; internal: string } {
    const originalMessage = error instanceof Error ? error.message : String(error);
    const originalStack = error instanceof Error ? error.stack : undefined;
    
    const sanitizedMessage = sanitizeErrorMessage(originalMessage);
    
    return {
        external: `Authentication error in ${context}: ${sanitizedMessage}`,
        internal: `[AUTH ERROR] Context: ${context}\nOriginal: ${originalMessage}\n${originalStack || ''}`,
    };
}

/**
 * Wrap an authentication-related error for safe external display.
 * Logs full details internally but returns sanitized message.
 * @param error The original error
 * @param context Context description for the error
 * @returns Sanitized error message for external use
 */
export function handleAuthError(error: Error | unknown, context: string): string {
    const safeError = createSafeAuthError(error, context);
    
    // Log full details internally (to stderr to separate from normal output)
    console.error(safeError.internal);
    
    // Return sanitized message for external use
    return safeError.external;
}

// ============================================================================
// Security Configuration Warnings
// ============================================================================

/**
 * Configuration security check results
 */
export interface SecurityCheckResult {
    secure: boolean;
    warnings: string[];
    recommendations: string[];
}

/**
 * Perform a comprehensive security check on the credential configuration.
 * @param oauthKeysPath Path to OAuth keys file
 * @param credentialsPath Path to credentials/token file
 * @returns Security check results with warnings and recommendations
 */
export function performSecurityAudit(
    oauthKeysPath: string,
    credentialsPath: string
): SecurityCheckResult {
    const warnings: string[] = [];
    const recommendations: string[] = [];
    let secure = true;
    
    // Check for environment variable usage
    const envVars = checkEnvVarsPresent();
    const usingEnvVars = envVars[ENV_VAR_NAMES.CLIENT_ID] && 
                         envVars[ENV_VAR_NAMES.CLIENT_SECRET] && 
                         envVars[ENV_VAR_NAMES.REFRESH_TOKEN];
    
    if (!usingEnvVars) {
        recommendations.push('Consider using environment variables for credentials in production');
    }
    
    // Check OAuth keys file permissions
    if (fs.existsSync(oauthKeysPath)) {
        if (!checkCredentialPermissions(oauthKeysPath)) {
            secure = false;
            warnings.push('OAuth keys file has insecure permissions (should be 0600)');
            recommendations.push(`Run: chmod 600 "${oauthKeysPath}"`);
        }
    }
    
    // Check credentials file permissions
    if (fs.existsSync(credentialsPath)) {
        if (!checkCredentialPermissions(credentialsPath)) {
            secure = false;
            warnings.push('Credentials file has insecure permissions (should be 0600)');
            recommendations.push(`Run: chmod 600 "${credentialsPath}"`);
        }
    }
    
    // Check for credentials in common insecure locations
    const insecureLocations = [
        '/tmp/',
        '/var/tmp/',
        process.cwd() + '/credentials',
    ];
    
    for (const location of insecureLocations) {
        if (oauthKeysPath.startsWith(location) || credentialsPath.startsWith(location)) {
            secure = false;
            warnings.push(`Credentials stored in potentially insecure location: ${sanitizePathForLogging(location)}`);
        }
    }
    
    return { secure, warnings, recommendations };
}

/**
 * Print security warnings to console with appropriate formatting.
 * @param result Security check result
 */
export function printSecurityWarnings(result: SecurityCheckResult): void {
    if (result.warnings.length > 0) {
        console.warn('\n⚠️  SECURITY WARNINGS:');
        for (const warning of result.warnings) {
            console.warn(`   • ${warning}`);
        }
    }
    
    if (result.recommendations.length > 0) {
        console.log('\n📋 Security Recommendations:');
        for (const rec of result.recommendations) {
            console.log(`   • ${rec}`);
        }
    }
    
    if (result.secure) {
        console.log('\n✅ Credential security check passed');
    } else {
        console.warn('\n❌ Credential security issues detected - please address warnings above');
    }
}
