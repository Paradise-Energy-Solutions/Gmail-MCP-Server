/**
 * Validators Module Test Suite
 * Tests for input validation functions in validators.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
    validateEmail,
    validateEmailList,
    isValidEmail,
    isPathContained,
    validatePath,
    validateSavePath,
    validateFilename,
    sanitizeFilename,
    validateSearchQuery,
    sanitizeSearchQuery,
    validateLabelName,
    validateLabelId,
    sanitizeLabelId,
    validateFilterId,
    validateFilterCriteria,
    validateFilterAction,
    validateAttachmentSize,
    validateStringLength,
    validateNoControlCharacters,
    validateMessageId,
    VALIDATION_LIMITS,
} from '../validators.js';

// ============================================================================
// Email Validation Tests
// ============================================================================

describe('Email Validation', () => {
    describe('validateEmail', () => {
        describe('valid emails', () => {
            it('should accept standard email format', () => {
                const result = validateEmail('user@example.com');
                assert.strictEqual(result.valid, true);
                assert.strictEqual(result.error, undefined);
            });

            it('should accept email with subdomain', () => {
                const result = validateEmail('user@mail.example.com');
                assert.strictEqual(result.valid, true);
            });

            it('should accept email with plus sign', () => {
                const result = validateEmail('user+tag@example.com');
                assert.strictEqual(result.valid, true);
            });

            it('should accept email with dots in local part', () => {
                const result = validateEmail('first.last@example.com');
                assert.strictEqual(result.valid, true);
            });

            it('should accept email with numbers', () => {
                const result = validateEmail('user123@example456.com');
                assert.strictEqual(result.valid, true);
            });

            it('should accept email with hyphen in domain', () => {
                const result = validateEmail('user@my-domain.com');
                assert.strictEqual(result.valid, true);
            });
        });

        describe('invalid formats', () => {
            it('should reject empty string', () => {
                const result = validateEmail('');
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('required'));
            });

            it('should reject null/undefined', () => {
                const result = validateEmail(null as unknown as string);
                assert.strictEqual(result.valid, false);
            });

            it('should reject email without @ symbol', () => {
                const result = validateEmail('userexample.com');
                assert.strictEqual(result.valid, false);
            });

            it('should reject email with multiple @ symbols', () => {
                const result = validateEmail('user@@example.com');
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('exactly one @'));
            });

            it('should reject email without domain extension', () => {
                const result = validateEmail('user@example');
                assert.strictEqual(result.valid, false);
            });

            it('should reject email with spaces', () => {
                const result = validateEmail('user @example.com');
                assert.strictEqual(result.valid, false);
            });
        });

        describe('injection prevention', () => {
            it('should reject email with newline (SMTP injection)', () => {
                const result = validateEmail('user@example.com\nRCPT TO:attacker@evil.com');
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('newline'));
            });

            it('should reject email with carriage return', () => {
                const result = validateEmail('user@example.com\rBCC:attacker@evil.com');
                assert.strictEqual(result.valid, false);
            });

            it('should reject email with null byte', () => {
                const result = validateEmail('user\0@example.com');
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('null'));
            });

            it('should reject email with semicolon', () => {
                const result = validateEmail('user;DROP TABLE users@example.com');
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('semicolon'));
            });
        });

        describe('edge cases', () => {
            it('should reject email exceeding max length', () => {
                const longLocal = 'a'.repeat(250);
                const result = validateEmail(`${longLocal}@example.com`);
                assert.strictEqual(result.valid, false);
                assert.ok(result.error?.includes('maximum length'));
            });

            it('should reject email with empty local part', () => {
                const result = validateEmail('@example.com');
                assert.strictEqual(result.valid, false);
            });

            it('should reject email with empty domain', () => {
                const result = validateEmail('user@');
                assert.strictEqual(result.valid, false);
            });

            it('should reject domain starting with hyphen', () => {
                const result = validateEmail('user@-example.com');
                assert.strictEqual(result.valid, false);
            });

        it('should reject domain starting with hyphen', () => {
            // Note: The validator checks if the WHOLE domain starts/ends with hyphen
            // It does NOT check individual domain labels
            const result = validateEmail('user@-example.com');
            assert.strictEqual(result.valid, false);
        });            it('should reject domain starting with dot', () => {
                const result = validateEmail('user@.example.com');
                assert.strictEqual(result.valid, false);
            });
        });
    });

    describe('validateEmailList', () => {
        it('should accept valid email array', () => {
            const result = validateEmailList(['a@b.com', 'c@d.com']);
            assert.strictEqual(result.valid, true);
        });

        it('should reject non-array input', () => {
            const result = validateEmailList('not-an-array' as unknown as string[]);
            assert.strictEqual(result.valid, false);
        });

        it('should identify invalid email with index', () => {
            const result = validateEmailList(['valid@email.com', 'invalid', 'another@email.com']);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('index 1'));
        });

        it('should accept empty array', () => {
            const result = validateEmailList([]);
            assert.strictEqual(result.valid, true);
        });
    });

    describe('isValidEmail (legacy)', () => {
        it('should return true for valid email', () => {
            assert.strictEqual(isValidEmail('user@example.com'), true);
        });

        it('should return false for invalid email', () => {
            assert.strictEqual(isValidEmail('invalid'), false);
        });
    });
});

// ============================================================================
// Path Validation Tests
// ============================================================================

describe('Path Validation', () => {
    describe('isPathContained', () => {
        it('should return true for contained path', () => {
            assert.strictEqual(isPathContained('/home/user', 'documents/file.txt'), true);
        });

        it('should return true for path equal to base', () => {
            assert.strictEqual(isPathContained('/home/user', ''), true);
        });

        it('should return false for path traversal with ../', () => {
            assert.strictEqual(isPathContained('/home/user', '../etc/passwd'), false);
        });

        it('should return false for absolute path outside base', () => {
            assert.strictEqual(isPathContained('/home/user', '/etc/passwd'), false);
        });

        it('should handle complex traversal attempts', () => {
            assert.strictEqual(isPathContained('/home/user', 'docs/../../../etc/passwd'), false);
        });

        it('should handle partial directory name attacks', () => {
            // /home/user should not contain /home/username
            assert.strictEqual(isPathContained('/home/user', '/home/username'), false);
        });
    });

    describe('validatePath', () => {
        it('should accept valid relative path', () => {
            const result = validatePath('documents/file.txt');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty path', () => {
            const result = validatePath('');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('required'));
        });

        it('should reject path with null bytes', () => {
            const result = validatePath('file\0.txt');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('null'));
        });

        it('should reject path with control characters', () => {
            const result = validatePath('file\x07.txt');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('control'));
        });

        it('should reject path exceeding max length', () => {
            const longPath = 'a'.repeat(VALIDATION_LIMITS.MAX_PATH_LENGTH + 1);
            const result = validatePath(longPath);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('maximum length'));
        });

        it('should reject obvious traversal patterns', () => {
            const result = validatePath('../../../etc/passwd');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('traversal'));
        });

        it('should reject path escaping base directory', () => {
            const result = validatePath('../secret.txt', '/home/user/documents');
            assert.strictEqual(result.valid, false);
            // Error message says "Path traversal detected" not "escapes"
            assert.ok(result.error?.includes('traversal'), `Expected error to mention 'traversal', got: ${result.error}`);
        });

        it('should return sanitized normalized path', () => {
            const result = validatePath('./documents//file.txt');
            assert.strictEqual(result.valid, true);
            assert.ok(result.sanitized);
        });
    });

    describe('validateSavePath', () => {
        it('should accept valid save path', () => {
            const result = validateSavePath('output.txt', '/home/user');
            assert.strictEqual(result.valid, true);
        });

        it('should reject save path escaping base directory', () => {
            const result = validateSavePath('../outside.txt', '/home/user/safe');
            assert.strictEqual(result.valid, false);
        });

        it('should return resolved path', () => {
            const result = validateSavePath('subdir/file.txt', '/home/user');
            assert.strictEqual(result.valid, true);
            assert.ok(result.sanitized?.startsWith('/home/user'));
        });
    });
});

// ============================================================================
// Filename Validation Tests
// ============================================================================

describe('Filename Validation', () => {
    describe('validateFilename', () => {
        it('should accept valid filename', () => {
            const result = validateFilename('document.pdf');
            assert.strictEqual(result.valid, true);
        });

        it('should accept filename with spaces', () => {
            const result = validateFilename('my document.pdf');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty filename', () => {
            const result = validateFilename('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject filename with null bytes', () => {
            const result = validateFilename('file\0.txt');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('null'));
        });

        it('should reject filename with control characters', () => {
            const result = validateFilename('file\x1f.txt');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('control'));
        });

        it('should reject filename with forward slash', () => {
            const result = validateFilename('dir/file.txt');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('path separator'));
        });

        it('should reject filename with backslash', () => {
            const result = validateFilename('dir\\file.txt');
            assert.strictEqual(result.valid, false);
        });

        it('should reject . as filename', () => {
            const result = validateFilename('.');
            assert.strictEqual(result.valid, false);
        });

        it('should reject .. as filename', () => {
            const result = validateFilename('..');
            assert.strictEqual(result.valid, false);
        });

        it('should accept hidden files starting with .', () => {
            const result = validateFilename('.gitignore');
            assert.strictEqual(result.valid, true);
        });

        describe('Windows reserved names', () => {
            const reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM9', 'LPT1', 'LPT9'];
            
            for (const name of reservedNames) {
                it(`should reject reserved name: ${name}`, () => {
                    const result = validateFilename(`${name}.txt`);
                    assert.strictEqual(result.valid, false);
                    assert.ok(result.error?.includes('reserved'));
                });

                it(`should reject reserved name case-insensitive: ${name.toLowerCase()}`, () => {
                    const result = validateFilename(`${name.toLowerCase()}.txt`);
                    assert.strictEqual(result.valid, false);
                });
            }
        });

        it('should reject filename exceeding max length', () => {
            const longName = 'a'.repeat(VALIDATION_LIMITS.MAX_FILENAME_LENGTH + 1);
            const result = validateFilename(longName);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('maximum length'));
        });
    });

    describe('sanitizeFilename', () => {
        it('should return unchanged valid filename', () => {
            assert.strictEqual(sanitizeFilename('document.pdf'), 'document.pdf');
        });

        it('should remove null bytes', () => {
            assert.strictEqual(sanitizeFilename('file\0.txt'), 'file.txt');
        });

        it('should remove control characters', () => {
            assert.strictEqual(sanitizeFilename('file\x1f.txt'), 'file.txt');
        });

        it('should replace path separators with underscores', () => {
            assert.strictEqual(sanitizeFilename('dir/file.txt'), 'dir_file.txt');
            assert.strictEqual(sanitizeFilename('dir\\file.txt'), 'dir_file.txt');
        });

        it('should truncate long filenames preserving extension', () => {
            const longName = 'a'.repeat(300) + '.pdf';
            const sanitized = sanitizeFilename(longName);
            assert.ok(sanitized.endsWith('.pdf'));
            assert.ok(sanitized.length <= VALIDATION_LIMITS.MAX_FILENAME_LENGTH);
        });

        it('should return default for empty input', () => {
            assert.strictEqual(sanitizeFilename(''), 'unnamed-file');
        });

        it('should return default for null input', () => {
            assert.strictEqual(sanitizeFilename(null as unknown as string), 'unnamed-file');
        });
    });
});

// ============================================================================
// Search Query Validation Tests
// ============================================================================

describe('Search Query Validation', () => {
    describe('validateSearchQuery', () => {
        it('should accept valid search query', () => {
            const result = validateSearchQuery('from:user@example.com subject:important');
            assert.strictEqual(result.valid, true);
        });

        it('should accept Gmail operators', () => {
            const result = validateSearchQuery('is:unread has:attachment after:2023/01/01');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty query', () => {
            const result = validateSearchQuery('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject query with null bytes', () => {
            const result = validateSearchQuery('search\0term');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('null'));
        });

        it('should reject query with control characters', () => {
            const result = validateSearchQuery('search\x07term');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('control'));
        });

        it('should reject query exceeding max length', () => {
            const longQuery = 'a'.repeat(VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH + 1);
            const result = validateSearchQuery(longQuery);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('maximum length'));
        });
    });

    describe('sanitizeSearchQuery', () => {
        it('should remove null bytes', () => {
            const result = sanitizeSearchQuery('search\0term');
            assert.ok(!result.includes('\0'));
        });

        it('should remove curly braces (potential injection)', () => {
            const result = sanitizeSearchQuery('search{injection}term');
            assert.ok(!result.includes('{'));
            assert.ok(!result.includes('}'));
        });

        it('should trim excessive whitespace', () => {
            const result = sanitizeSearchQuery('search    term');
            assert.strictEqual(result, 'search term');
        });

        it('should return empty string for null input', () => {
            assert.strictEqual(sanitizeSearchQuery(null as unknown as string), '');
        });

        it('should truncate to max length', () => {
            const longQuery = 'a'.repeat(VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH + 100);
            const result = sanitizeSearchQuery(longQuery);
            assert.strictEqual(result.length, VALIDATION_LIMITS.MAX_SEARCH_QUERY_LENGTH);
        });
    });
});

// ============================================================================
// Label Validation Tests
// ============================================================================

describe('Label Validation', () => {
    describe('validateLabelName', () => {
        it('should accept valid label name', () => {
            const result = validateLabelName('Important');
            assert.strictEqual(result.valid, true);
        });

        it('should accept label with spaces', () => {
            const result = validateLabelName('Work Projects');
            assert.strictEqual(result.valid, true);
        });

        it('should accept nested label name', () => {
            const result = validateLabelName('Work/Projects/Active');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty label name', () => {
            const result = validateLabelName('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject whitespace-only label', () => {
            const result = validateLabelName('   ');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('empty'));
        });

        it('should reject label with null bytes', () => {
            const result = validateLabelName('label\0name');
            assert.strictEqual(result.valid, false);
        });

        it('should reject label with control characters', () => {
            const result = validateLabelName('label\x1fname');
            assert.strictEqual(result.valid, false);
        });

        it('should reject label exceeding max length', () => {
            const longLabel = 'a'.repeat(VALIDATION_LIMITS.MAX_LABEL_NAME_LENGTH + 1);
            const result = validateLabelName(longLabel);
            assert.strictEqual(result.valid, false);
        });

        it('should return trimmed sanitized name', () => {
            const result = validateLabelName('  Label Name  ');
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.sanitized, 'Label Name');
        });
    });

    describe('validateLabelId', () => {
        it('should accept valid label ID', () => {
            const result = validateLabelId('Label_1');
            assert.strictEqual(result.valid, true);
        });

        it('should accept system label IDs', () => {
            const result = validateLabelId('INBOX');
            assert.strictEqual(result.valid, true);
        });

        it('should accept category labels', () => {
            const result = validateLabelId('CATEGORY_PERSONAL');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty label ID', () => {
            const result = validateLabelId('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject label ID with special characters', () => {
            const result = validateLabelId('Label@1');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('invalid characters'));
        });

        it('should reject label ID exceeding max length', () => {
            const longId = 'a'.repeat(VALIDATION_LIMITS.MAX_LABEL_ID_LENGTH + 1);
            const result = validateLabelId(longId);
            assert.strictEqual(result.valid, false);
        });
    });

    describe('sanitizeLabelId', () => {
        it('should remove invalid characters', () => {
            const result = sanitizeLabelId('Label@!#$%1');
            assert.strictEqual(result, 'Label1');
        });

        it('should preserve valid characters', () => {
            const result = sanitizeLabelId('Label_1-2/3');
            assert.strictEqual(result, 'Label_1-2/3');
        });

        it('should return empty string for null', () => {
            assert.strictEqual(sanitizeLabelId(null as unknown as string), '');
        });
    });
});

// ============================================================================
// Filter Validation Tests
// ============================================================================

describe('Filter Validation', () => {
    describe('validateFilterId', () => {
        it('should accept valid filter ID', () => {
            const result = validateFilterId('ANGjdJ8xyz123');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty filter ID', () => {
            const result = validateFilterId('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject filter ID with control characters', () => {
            const result = validateFilterId('filter\x00id');
            assert.strictEqual(result.valid, false);
        });
    });

    describe('validateFilterCriteria', () => {
        it('should accept valid filter criteria', () => {
            const result = validateFilterCriteria({
                from: 'sender@example.com',
                subject: 'Test Subject',
            });
            assert.strictEqual(result.valid, true);
        });

        it('should reject non-object criteria', () => {
            const result = validateFilterCriteria('not-an-object' as unknown as Record<string, unknown>);
            assert.strictEqual(result.valid, false);
        });

        it('should reject invalid email in from field', () => {
            const result = validateFilterCriteria({
                from: 'invalid-email',
            });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('from'));
        });

        it('should reject invalid email in to field', () => {
            const result = validateFilterCriteria({
                to: 'invalid-email',
            });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('to'));
        });
    });

    describe('validateFilterAction', () => {
        it('should accept valid filter action', () => {
            const result = validateFilterAction({
                addLabelIds: ['IMPORTANT'],
                removeLabelIds: ['UNREAD'],
            });
            assert.strictEqual(result.valid, true);
        });

        it('should reject non-object action', () => {
            const result = validateFilterAction('not-an-object' as unknown as Record<string, unknown>);
            assert.strictEqual(result.valid, false);
        });

        it('should reject invalid forward address', () => {
            const result = validateFilterAction({
                forward: 'invalid-email',
            });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('forward'));
        });

        it('should reject non-array addLabelIds', () => {
            const result = validateFilterAction({
                addLabelIds: 'not-an-array',
            });
            assert.strictEqual(result.valid, false);
        });
    });
});

// ============================================================================
// Attachment Size Validation Tests
// ============================================================================

describe('Attachment Size Validation', () => {
    describe('validateAttachmentSize', () => {
        it('should accept size within limit', () => {
            const result = validateAttachmentSize(1024 * 1024); // 1MB
            assert.strictEqual(result.valid, true);
        });

        it('should accept zero size', () => {
            const result = validateAttachmentSize(0);
            assert.strictEqual(result.valid, true);
        });

        it('should reject negative size', () => {
            const result = validateAttachmentSize(-100);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('negative'));
        });

        it('should reject size exceeding default limit', () => {
            const result = validateAttachmentSize(30 * 1024 * 1024); // 30MB
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('exceeds'));
        });

        it('should respect custom max size', () => {
            const customMax = 5 * 1024 * 1024; // 5MB
            const result = validateAttachmentSize(6 * 1024 * 1024, customMax);
            assert.strictEqual(result.valid, false);
        });

        it('should reject non-number input', () => {
            const result = validateAttachmentSize('1024' as unknown as number);
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('number'));
        });

        it('should reject NaN', () => {
            const result = validateAttachmentSize(NaN);
            assert.strictEqual(result.valid, false);
        });
    });
});

// ============================================================================
// Generic Validation Tests
// ============================================================================

describe('Generic Validation', () => {
    describe('validateStringLength', () => {
        it('should accept string within limits', () => {
            const result = validateStringLength('hello', 'field', { maxLength: 10 });
            assert.strictEqual(result.valid, true);
        });

        it('should reject string below minimum', () => {
            const result = validateStringLength('hi', 'field', { minLength: 5, maxLength: 10 });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('at least'));
        });

        it('should reject string above maximum', () => {
            const result = validateStringLength('hello world', 'field', { maxLength: 5 });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('exceeds'));
        });

        it('should reject null value', () => {
            const result = validateStringLength(null as unknown as string, 'field', { maxLength: 10 });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('required'));
        });

        it('should reject non-string value', () => {
            const result = validateStringLength(123 as unknown as string, 'field', { maxLength: 10 });
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('string'));
        });
    });

    describe('validateNoControlCharacters', () => {
        it('should accept normal string', () => {
            const result = validateNoControlCharacters('Hello World!', 'field');
            assert.strictEqual(result.valid, true);
        });

        it('should accept empty string', () => {
            const result = validateNoControlCharacters('', 'field');
            assert.strictEqual(result.valid, true);
        });

        it('should reject string with null byte', () => {
            const result = validateNoControlCharacters('Hello\x00World', 'field');
            assert.strictEqual(result.valid, false);
        });

        it('should reject string with bell character', () => {
            const result = validateNoControlCharacters('Hello\x07World', 'field');
            assert.strictEqual(result.valid, false);
        });

        it('should accept newlines and tabs (common whitespace)', () => {
            // Note: \n (0x0a), \r (0x0d), \t (0x09) are typically allowed
            const result = validateNoControlCharacters('Hello\nWorld\tTest', 'field');
            // Based on the regex in validators.ts, \n, \r, \t are in the range but might be excluded
            // Check actual behavior - the regex excludes 0x09, 0x0a, 0x0d
            assert.strictEqual(result.valid, true);
        });

        it('should reject DEL character', () => {
            const result = validateNoControlCharacters('Hello\x7fWorld', 'field');
            assert.strictEqual(result.valid, false);
        });
    });

    describe('validateMessageId', () => {
        it('should accept valid message ID', () => {
            const result = validateMessageId('18abc123def');
            assert.strictEqual(result.valid, true);
        });

        it('should reject empty message ID', () => {
            const result = validateMessageId('');
            assert.strictEqual(result.valid, false);
        });

        it('should reject message ID with special characters', () => {
            const result = validateMessageId('msg-id-123');
            assert.strictEqual(result.valid, false);
            assert.ok(result.error?.includes('invalid characters'));
        });

        it('should reject very long message ID', () => {
            const longId = 'a'.repeat(300);
            const result = validateMessageId(longId);
            assert.strictEqual(result.valid, false);
        });

        it('should trim whitespace', () => {
            const result = validateMessageId('  abc123  ');
            assert.strictEqual(result.valid, true);
            assert.strictEqual(result.sanitized, 'abc123');
        });
    });
});
