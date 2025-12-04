/**
 * Input Validation and Injection Prevention Module
 * Provides comprehensive validation for security-critical inputs
 */

import path from 'path';

// ==================== Configuration Constants ====================

export const VALIDATION_LIMITS = {
    MAX_EMAIL_LENGTH: 254,
    MAX_LABEL_NAME_LENGTH: 100,
    MAX_LABEL_ID_LENGTH: 255,
    MAX_FILTER_ID_LENGTH: 255,
    MAX_FILENAME_LENGTH: 255,
    MAX_PATH_LENGTH: 4096,
    MAX_SEARCH_QUERY_LENGTH: 1000,
    MAX_SUBJECT_LENGTH: 998, // RFC 5322 recommendation
    MAX_ATTACHMENT_SIZE: 25 * 1024 * 1024, // 25MB default
    MAX_EMAIL_BODY_LENGTH: 10 * 1024 * 1024, // 10MB
};

// ==================== Validation Result Types ====================

export interface ValidationResult {
    valid: boolean;
    error?: string;
    sanitized?: string;
}

// ==================== Email Validation ====================

/**
 * Validates email address following RFC 5322 with SMTP injection prevention
 * Rejects newlines, carriage returns, and other injection patterns
 */
export function validateEmail(email: string): ValidationResult {
    // Null/undefined check
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email address is required' };
    }

    // Length check (RFC 5321 max is 254 characters)
    if (email.length > VALIDATION_LIMITS.MAX_EMAIL_LENGTH) {
        return { valid: false, error: `Email address exceeds maximum length of ${VALIDATION_LIMITS.MAX_EMAIL_LENGTH} characters` };
    }

    // SMTP injection prevention - reject newlines, carriage returns
    if (/[\r\n]/.test(email)) {
        return { valid: false, error: 'Email address contains invalid characters (newlines not allowed)' };
    }

    // Reject null bytes
    if (email.includes('\0')) {
        return { valid: false, error: 'Email address contains null bytes' };
    }

    // Reject semicolons (used in some SMTP injection attacks)
    if (email.includes(';')) {
        return { valid: false, error: 'Email address contains invalid character (semicolon)' };
    }

    // Reject multiple @ symbols
    const atCount = (email.match(/@/g) || []).length;
    if (atCount !== 1) {
        return { valid: false, error: 'Email address must contain exactly one @ symbol' };
    }

    // RFC 5322 compliant regex (simplified but effective)
    const emailRegex = /^[^\s@<>()[\]\\,;:]+@[^\s@<>()[\]\\,;:]+\.[^\s@<>()[\]\\,;:]+$/;
    if (!emailRegex.test(email)) {
        return { valid: false, error: 'Email address format is invalid' };
    }

    // Check for valid domain structure
    const [localPart, domain] = email.split('@');
    
    if (!localPart || localPart.length === 0) {
        return { valid: false, error: 'Email local part is empty' };
    }
    
    if (!domain || domain.length === 0) {
        return { valid: false, error: 'Email domain is empty' };
    }

    // Domain should not start or end with hyphen or dot
    if (/^[-.]|[-.]$/.test(domain)) {
        return { valid: false, error: 'Email domain format is invalid' };
    }

    return { valid: true };
}

/**
 * Validates an array of email addresses
 */
export function validateEmailList(emails: string[]): ValidationResult {
    if (!Array.isArray(emails)) {
        return { valid: false, error: 'Email list must be an array' };
    }

    for (let i = 0; i < emails.length; i++) {
        const result = validateEmail(emails[i]);
        if (!result.valid) {
            return { valid: false, error: `Invalid email at index ${i}: ${result.error}` };
        }
    }

    return { valid: true };
}

/**
 * Legacy compatible email validator (returns boolean)
 * Use validateEmail() for detailed error messages
 */
export function isValidEmail(email: string): boolean {
    return validateEmail(email).valid;
}

// ==================== Path Validation ====================

/**
 * Validates that a target path is contained within a base directory
 * Prevents path traversal attacks (../, symlink attacks)
 */
export function isPathContained(basePath: string, targetPath: string): boolean {
    try {
        const resolvedBase = path.resolve(basePath);
        const resolvedTarget = path.resolve(basePath, targetPath);
        
        // Ensure the resolved target starts with the base path
        // Add path.sep to prevent partial directory name matches
        return resolvedTarget.startsWith(resolvedBase + path.sep) || resolvedTarget === resolvedBase;
    } catch {
        return false;
    }
}

/**
 * Comprehensive path validation with detailed error messages
 */
export function validatePath(targetPath: string, basePath?: string): ValidationResult {
    if (!targetPath || typeof targetPath !== 'string') {
        return { valid: false, error: 'Path is required' };
    }

    // Length check
    if (targetPath.length > VALIDATION_LIMITS.MAX_PATH_LENGTH) {
        return { valid: false, error: `Path exceeds maximum length of ${VALIDATION_LIMITS.MAX_PATH_LENGTH} characters` };
    }

    // Null byte check (critical for security)
    if (targetPath.includes('\0')) {
        return { valid: false, error: 'Path contains null bytes' };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(targetPath)) {
        return { valid: false, error: 'Path contains control characters' };
    }

    // Check for obvious path traversal attempts
    const normalizedPath = path.normalize(targetPath);
    if (normalizedPath.includes('..')) {
        return { valid: false, error: 'Path traversal detected (../ not allowed)' };
    }

    // If basePath is provided, check containment
    if (basePath) {
        if (!isPathContained(basePath, targetPath)) {
            return { valid: false, error: 'Path escapes the allowed directory' };
        }
    }

    return { valid: true, sanitized: normalizedPath };
}

/**
 * Validates a file path for safe writing operations
 */
export function validateSavePath(savePath: string, baseDir: string): ValidationResult {
    const pathResult = validatePath(savePath, baseDir);
    if (!pathResult.valid) {
        return pathResult;
    }

    // Additional checks for save paths
    const resolvedPath = path.resolve(baseDir, savePath);
    
    // Check the resolved path is still contained
    if (!isPathContained(baseDir, resolvedPath)) {
        return { valid: false, error: 'Resolved save path escapes allowed directory' };
    }

    return { valid: true, sanitized: resolvedPath };
}

// ==================== Filename Validation ====================

/**
 * Validates and sanitizes attachment filenames
 * Rejects null bytes, path separators, control characters
 */
export function validateFilename(filename: string): ValidationResult {
    if (!filename || typeof filename !== 'string') {
        return { valid: false, error: 'Filename is required' };
    }

    // Length check
    if (filename.length > VALIDATION_LIMITS.MAX_FILENAME_LENGTH) {
        return { valid: false, error: `Filename exceeds maximum length of ${VALIDATION_LIMITS.MAX_FILENAME_LENGTH} characters` };
    }

    // Null byte check
    if (filename.includes('\0')) {
        return { valid: false, error: 'Filename contains null bytes' };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(filename)) {
        return { valid: false, error: 'Filename contains control characters' };
    }

    // Path separator check (prevent directory traversal)
    if (filename.includes('/') || filename.includes('\\')) {
        return { valid: false, error: 'Filename contains path separators' };
    }

    // Path traversal patterns
    if (filename === '.' || filename === '..' || filename.startsWith('.')) {
        // Allow hidden files but not traversal
        if (filename === '.' || filename === '..') {
            return { valid: false, error: 'Filename cannot be . or ..' };
        }
    }

    // Reject common dangerous patterns
    const dangerousPatterns = [
        /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i, // Windows reserved names
    ];
    
    const baseName = path.parse(filename).name;
    for (const pattern of dangerousPatterns) {
        if (pattern.test(baseName)) {
            return { valid: false, error: 'Filename uses reserved system name' };
        }
    }

    return { valid: true, sanitized: filename };
}

/**
 * Sanitizes a filename by removing or replacing dangerous characters
 */
export function sanitizeFilename(filename: string): string {
    if (!filename || typeof filename !== 'string') {
        return 'unnamed-file';
    }

    let sanitized = filename;

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Remove control characters
    // eslint-disable-next-line no-control-regex
    sanitized = sanitized.replace(/[\x00-\x1f\x7f]/g, '');

    // Replace path separators with underscores
    sanitized = sanitized.replace(/[/\\]/g, '_');

    // Limit length
    if (sanitized.length > VALIDATION_LIMITS.MAX_FILENAME_LENGTH) {
        const ext = path.extname(sanitized);
        const baseName = path.basename(sanitized, ext);
        const maxBaseLength = VALIDATION_LIMITS.MAX_FILENAME_LENGTH - ext.length;
        sanitized = baseName.substring(0, maxBaseLength) + ext;
    }

    // If empty after sanitization, provide default
    if (!sanitized || sanitized.length === 0) {
        return 'unnamed-file';
    }

    return sanitized;
}

// ==================== Gmail Search Query Validation ====================

/**
 * Dangerous patterns in Gmail search queries
 */
const DANGEROUS_QUERY_PATTERNS = [
    /[{}\[\]]/g,              // Curly braces and brackets (potential injection)
    /\x00/g,                  // Null bytes
    // eslint-disable-next-line no-control-regex
    /[\x00-\x1f\x7f]/g,       // Control characters
];

/**
 * Validates Gmail search query
 */
export function validateSearchQuery(query: string): ValidationResult {
    if (!query || typeof query !== 'string') {
        return { valid: false, error: 'Search query is required' };
    }

    // Length check
    if (query.length > VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH) {
        return { valid: false, error: `Search query exceeds maximum length of ${VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH} characters` };
    }

    // Null byte check
    if (query.includes('\0')) {
        return { valid: false, error: 'Search query contains null bytes' };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(query)) {
        return { valid: false, error: 'Search query contains control characters' };
    }

    return { valid: true };
}

/**
 * Sanitizes a Gmail search query by escaping/removing dangerous patterns
 */
export function sanitizeSearchQuery(query: string): string {
    if (!query || typeof query !== 'string') {
        return '';
    }

    let sanitized = query;

    // Remove dangerous patterns
    for (const pattern of DANGEROUS_QUERY_PATTERNS) {
        sanitized = sanitized.replace(pattern, '');
    }

    // Trim excessive whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim();

    // Limit length
    if (sanitized.length > VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH) {
        sanitized = sanitized.substring(0, VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH);
    }

    return sanitized;
}

// ==================== Label Validation ====================

/**
 * Validates Gmail label name
 */
export function validateLabelName(labelName: string): ValidationResult {
    if (!labelName || typeof labelName !== 'string') {
        return { valid: false, error: 'Label name is required' };
    }

    // Trim and check
    const trimmed = labelName.trim();
    if (trimmed.length === 0) {
        return { valid: false, error: 'Label name cannot be empty' };
    }

    // Length check
    if (trimmed.length > VALIDATION_LIMITS.MAX_LABEL_NAME_LENGTH) {
        return { valid: false, error: `Label name exceeds maximum length of ${VALIDATION_LIMITS.MAX_LABEL_NAME_LENGTH} characters` };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(trimmed)) {
        return { valid: false, error: 'Label name contains control characters' };
    }

    // Null byte check
    if (trimmed.includes('\0')) {
        return { valid: false, error: 'Label name contains null bytes' };
    }

    return { valid: true, sanitized: trimmed };
}

/**
 * Validates Gmail label ID
 */
export function validateLabelId(labelId: string): ValidationResult {
    if (!labelId || typeof labelId !== 'string') {
        return { valid: false, error: 'Label ID is required' };
    }

    // Trim and check
    const trimmed = labelId.trim();
    if (trimmed.length === 0) {
        return { valid: false, error: 'Label ID cannot be empty' };
    }

    // Length check
    if (trimmed.length > VALIDATION_LIMITS.MAX_LABEL_ID_LENGTH) {
        return { valid: false, error: `Label ID exceeds maximum length of ${VALIDATION_LIMITS.MAX_LABEL_ID_LENGTH} characters` };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(trimmed)) {
        return { valid: false, error: 'Label ID contains control characters' };
    }

    // Label IDs should be alphanumeric with some allowed special characters
    // Gmail uses IDs like "Label_1" or "INBOX", "CATEGORY_PERSONAL", etc.
    if (!/^[a-zA-Z0-9_/-]+$/.test(trimmed)) {
        return { valid: false, error: 'Label ID contains invalid characters' };
    }

    return { valid: true, sanitized: trimmed };
}

/**
 * Sanitizes a label ID for safe API calls
 */
export function sanitizeLabelId(labelId: string): string {
    if (!labelId || typeof labelId !== 'string') {
        return '';
    }

    // Remove any characters that aren't alphanumeric, underscore, hyphen, or forward slash
    return labelId.replace(/[^a-zA-Z0-9_/-]/g, '').substring(0, VALIDATION_LIMITS.MAX_LABEL_ID_LENGTH);
}

// ==================== Filter Validation ====================

/**
 * Validates filter ID
 */
export function validateFilterId(filterId: string): ValidationResult {
    if (!filterId || typeof filterId !== 'string') {
        return { valid: false, error: 'Filter ID is required' };
    }

    const trimmed = filterId.trim();
    if (trimmed.length === 0) {
        return { valid: false, error: 'Filter ID cannot be empty' };
    }

    if (trimmed.length > VALIDATION_LIMITS.MAX_FILTER_ID_LENGTH) {
        return { valid: false, error: `Filter ID exceeds maximum length of ${VALIDATION_LIMITS.MAX_FILTER_ID_LENGTH} characters` };
    }

    // Control character check
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(trimmed)) {
        return { valid: false, error: 'Filter ID contains control characters' };
    }

    return { valid: true, sanitized: trimmed };
}

/**
 * Validates filter criteria inputs
 */
export function validateFilterCriteria(criteria: Record<string, unknown>): ValidationResult {
    if (!criteria || typeof criteria !== 'object') {
        return { valid: false, error: 'Filter criteria must be an object' };
    }

    // Validate email fields in criteria
    const emailFields = ['from', 'to'];
    for (const field of emailFields) {
        if (criteria[field]) {
            const value = criteria[field];
            if (typeof value !== 'string') {
                return { valid: false, error: `Filter criteria '${field}' must be a string` };
            }
            const emailResult = validateEmail(value);
            if (!emailResult.valid) {
                return { valid: false, error: `Invalid ${field} in criteria: ${emailResult.error}` };
            }
        }
    }

    // Validate query fields
    const queryFields = ['query', 'negatedQuery', 'subject'];
    for (const field of queryFields) {
        if (criteria[field]) {
            const value = criteria[field];
            if (typeof value !== 'string') {
                return { valid: false, error: `Filter criteria '${field}' must be a string` };
            }
            const queryResult = validateSearchQuery(value);
            if (!queryResult.valid) {
                return { valid: false, error: `Invalid ${field} in criteria: ${queryResult.error}` };
            }
        }
    }

    return { valid: true };
}

/**
 * Validates filter action inputs
 */
export function validateFilterAction(action: Record<string, unknown>): ValidationResult {
    if (!action || typeof action !== 'object') {
        return { valid: false, error: 'Filter action must be an object' };
    }

    // Validate forward email
    if (action.forward) {
        if (typeof action.forward !== 'string') {
            return { valid: false, error: 'Forward address must be a string' };
        }
        const emailResult = validateEmail(action.forward);
        if (!emailResult.valid) {
            return { valid: false, error: `Invalid forward address: ${emailResult.error}` };
        }
    }

    // Validate label IDs
    const labelArrayFields = ['addLabelIds', 'removeLabelIds'];
    for (const field of labelArrayFields) {
        if (action[field]) {
            if (!Array.isArray(action[field])) {
                return { valid: false, error: `${field} must be an array` };
            }
            for (const labelId of action[field] as string[]) {
                const labelResult = validateLabelId(labelId);
                if (!labelResult.valid) {
                    return { valid: false, error: `Invalid label ID in ${field}: ${labelResult.error}` };
                }
            }
        }
    }

    return { valid: true };
}

// ==================== Attachment Size Validation ====================

/**
 * Validates attachment size
 */
export function validateAttachmentSize(sizeInBytes: number, maxSize: number = VALIDATION_LIMITS.MAX_ATTACHMENT_SIZE): ValidationResult {
    if (typeof sizeInBytes !== 'number' || isNaN(sizeInBytes)) {
        return { valid: false, error: 'Attachment size must be a number' };
    }

    if (sizeInBytes < 0) {
        return { valid: false, error: 'Attachment size cannot be negative' };
    }

    if (sizeInBytes > maxSize) {
        const maxSizeMB = Math.round(maxSize / (1024 * 1024));
        const actualSizeMB = Math.round(sizeInBytes / (1024 * 1024));
        return { 
            valid: false, 
            error: `Attachment size (${actualSizeMB}MB) exceeds maximum allowed size (${maxSizeMB}MB)` 
        };
    }

    return { valid: true };
}

// ==================== Generic String Validation ====================

/**
 * Validates string length with configurable limits
 */
export function validateStringLength(
    value: string, 
    fieldName: string, 
    options: { minLength?: number; maxLength: number }
): ValidationResult {
    if (value === null || value === undefined) {
        return { valid: false, error: `${fieldName} is required` };
    }

    if (typeof value !== 'string') {
        return { valid: false, error: `${fieldName} must be a string` };
    }

    if (options.minLength !== undefined && value.length < options.minLength) {
        return { valid: false, error: `${fieldName} must be at least ${options.minLength} characters` };
    }

    if (value.length > options.maxLength) {
        return { valid: false, error: `${fieldName} exceeds maximum length of ${options.maxLength} characters` };
    }

    return { valid: true };
}

/**
 * Validates that a string does not contain control characters
 */
export function validateNoControlCharacters(value: string, fieldName: string): ValidationResult {
    if (!value || typeof value !== 'string') {
        return { valid: true }; // Empty strings pass
    }

    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
        return { valid: false, error: `${fieldName} contains invalid control characters` };
    }

    return { valid: true };
}

// ==================== Message ID Validation ====================

/**
 * Validates Gmail message ID format
 */
export function validateMessageId(messageId: string): ValidationResult {
    if (!messageId || typeof messageId !== 'string') {
        return { valid: false, error: 'Message ID is required' };
    }

    const trimmed = messageId.trim();
    if (trimmed.length === 0) {
        return { valid: false, error: 'Message ID cannot be empty' };
    }

    // Gmail message IDs are typically alphanumeric
    if (!/^[a-zA-Z0-9]+$/.test(trimmed)) {
        return { valid: false, error: 'Message ID contains invalid characters' };
    }

    // Reasonable length limit
    if (trimmed.length > 255) {
        return { valid: false, error: 'Message ID exceeds maximum length' };
    }

    return { valid: true, sanitized: trimmed };
}

// ==================== Export all validators ====================

export const validators = {
    // Email
    validateEmail,
    validateEmailList,
    isValidEmail,
    
    // Path
    isPathContained,
    validatePath,
    validateSavePath,
    
    // Filename
    validateFilename,
    sanitizeFilename,
    
    // Search
    validateSearchQuery,
    sanitizeSearchQuery,
    
    // Labels
    validateLabelName,
    validateLabelId,
    sanitizeLabelId,
    
    // Filters
    validateFilterId,
    validateFilterCriteria,
    validateFilterAction,
    
    // Attachments
    validateAttachmentSize,
    
    // Generic
    validateStringLength,
    validateNoControlCharacters,
    validateMessageId,
    
    // Constants
    VALIDATION_LIMITS,
};

export default validators;
