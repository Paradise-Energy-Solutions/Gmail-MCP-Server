/**
 * Inline-Image and htmlBodyFile Feature Test Suite
 *
 * Tests Zod schema validation for the new SendEmailSchema fields:
 *   - htmlBodyFile: mutually exclusive with htmlBody
 *   - inline_images: InlineImageSchema field-level constraints
 *
 * Does NOT test live Gmail API calls. Import the schemas directly by
 * re-exporting them from a test-helper; here we replicate the Zod shapes
 * to keep tests fast and self-contained.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Replicate the exact Zod schemas from index.ts so tests remain in-process
// and do not require the full server bootstrap (OAuth, file system, etc.).
// If the schemas in index.ts change, update these accordingly.
// ---------------------------------------------------------------------------

const InlineImageSchema = z.object({
    content_id: z
        .string()
        .regex(
            /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/,
            'content_id must start with a letter or digit and contain only letters, digits, underscores, hyphens, or dots'
        )
        .max(255),
    mime_type: z
        .string()
        .regex(
            /^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^.]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^.+]*$/,
            'mime_type must be a valid media type such as image/png or image/jpeg'
        )
        .max(100),
    source: z
        .string()
        .startsWith('file://', 'source must be a file:// URI'),
});

const SendEmailSchema = z
    .object({
        to: z.array(z.string()),
        subject: z.string(),
        body: z.string(),
        htmlBody: z.string().optional(),
        htmlBodyFile: z.string().optional(),
        mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().default('text/plain'),
        cc: z.array(z.string()).optional(),
        bcc: z.array(z.string()).optional(),
        threadId: z.string().optional(),
        inReplyTo: z.string().optional(),
        attachments: z.array(z.string()).optional(),
        inline_images: z.array(InlineImageSchema).optional(),
    })
    .refine(
        (data) => !(data.htmlBody && data.htmlBodyFile),
        {
            message: 'Provide either htmlBody or htmlBodyFile, not both. ' +
                     'Use htmlBodyFile when the HTML content is large to avoid agent context-window overflow.',
            path: ['htmlBody'],
        }
    );

// ---------------------------------------------------------------------------
// Minimal valid base payload — reused across tests
// ---------------------------------------------------------------------------
const BASE_PAYLOAD = {
    to: ['recipient@example.com'],
    subject: 'Test email',
    body: 'Plain text fallback',
};

// ============================================================================
// SendEmailSchema — mutual-exclusion refinement
// ============================================================================

describe('SendEmailSchema mutual exclusion: htmlBody vs htmlBodyFile', () => {
    it('should accept payload with only htmlBody', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBody: '<p>Hello</p>',
        });
        assert.strictEqual(result.success, true);
    });

    it('should accept payload with only htmlBodyFile', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBodyFile: '/home/user/template.html',
        });
        assert.strictEqual(result.success, true);
    });

    it('should accept payload with neither htmlBody nor htmlBodyFile', () => {
        const result = SendEmailSchema.safeParse(BASE_PAYLOAD);
        assert.strictEqual(result.success, true);
    });

    it('should REJECT payload with both htmlBody and htmlBodyFile', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBody: '<p>Hello</p>',
            htmlBodyFile: '/home/user/template.html',
        });
        assert.strictEqual(result.success, false);
        const issues = result.error?.issues ?? [];
        assert.ok(issues.length > 0, 'Expected at least one Zod issue');
        const message = issues[0].message;
        assert.ok(
            message.includes('htmlBody') || message.includes('htmlBodyFile'),
            `Expected error message to mention htmlBody or htmlBodyFile; got: "${message}"`
        );
    });

    it('error message from mutual-exclusion violation should be actionable', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBody: '<p>Hi</p>',
            htmlBodyFile: '/templates/welcome.html',
        });
        assert.strictEqual(result.success, false);
        const message = result.error?.issues[0]?.message ?? '';
        assert.ok(
            message.toLowerCase().includes('not both') ||
            message.toLowerCase().includes('one or the other'),
            `Error message should guide the caller; got: "${message}"`
        );
    });
});

// ============================================================================
// InlineImageSchema — field-level validation
// ============================================================================

describe('InlineImageSchema field validation', () => {
    describe('content_id', () => {
        it('should accept an alphanumeric content_id', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, true);
        });

        it('should accept content_id with allowed special characters', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'company-logo_v2.0',
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, true);
        });

        it('should REJECT content_id starting with a dot', () => {
            const result = InlineImageSchema.safeParse({
                content_id: '.hidden',
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT content_id containing a space', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'company logo',
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT content_id exceeding 255 characters', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'a'.repeat(256),
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT empty content_id', () => {
            const result = InlineImageSchema.safeParse({
                content_id: '',
                mime_type: 'image/png',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });
    });

    describe('mime_type', () => {
        it('should accept common image MIME types', () => {
            for (const mime of ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml']) {
                const result = InlineImageSchema.safeParse({
                    content_id: 'img',
                    mime_type: mime,
                    source: 'file:///home/user/img.png',
                });
                assert.strictEqual(result.success, true, `Expected mime_type '${mime}' to be accepted`);
            }
        });

        it('should REJECT a mime_type with no slash', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'imagepng',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT empty mime_type', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: '',
                source: 'file:///home/user/logo.png',
            });
            assert.strictEqual(result.success, false);
        });
    });

    describe('source', () => {
        it('should accept a valid file:// URI', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: 'file:///home/user/images/logo.png',
            });
            assert.strictEqual(result.success, true);
        });

        it('should REJECT a plain path without the file:// prefix', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: '/home/user/images/logo.png',
            });
            assert.strictEqual(result.success, false);
            const message = result.error?.issues[0]?.message ?? '';
            assert.ok(
                message.includes('file://'),
                `Error message should mention file:// URI; got: "${message}"`
            );
        });

        it('should REJECT a data: URI (base64 data must not bypass context limits)', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: 'data:image/png;base64,iVBORw0KGgo=',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT an http:// URI', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: 'http://example.com/logo.png',
            });
            assert.strictEqual(result.success, false);
        });

        it('should REJECT an empty source', () => {
            const result = InlineImageSchema.safeParse({
                content_id: 'logo',
                mime_type: 'image/png',
                source: '',
            });
            assert.strictEqual(result.success, false);
        });
    });
});

// ============================================================================
// SendEmailSchema — inline_images integration
// ============================================================================

describe('SendEmailSchema with inline_images', () => {
    it('should accept a payload with valid inline_images array', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBody: '<img src="cid:logo"> Hello',
            inline_images: [
                {
                    content_id: 'logo',
                    mime_type: 'image/png',
                    source: 'file:///home/user/logo.png',
                },
            ],
        });
        assert.strictEqual(result.success, true);
    });

    it('should accept a payload with inline_images and htmlBodyFile', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBodyFile: '/home/user/template.html',
            inline_images: [
                {
                    content_id: 'banner',
                    mime_type: 'image/jpeg',
                    source: 'file:///home/user/banner.jpg',
                },
            ],
        });
        assert.strictEqual(result.success, true);
    });

    it('should accept a payload with no inline_images (backward compat)', () => {
        const result = SendEmailSchema.safeParse(BASE_PAYLOAD);
        assert.strictEqual(result.success, true);
        assert.strictEqual(result.data?.inline_images, undefined);
    });

    it('default mimeType should be text/plain (no HTML, no inline_images)', () => {
        const result = SendEmailSchema.safeParse(BASE_PAYLOAD);
        assert.strictEqual(result.success, true);
        assert.strictEqual(result.data?.mimeType, 'text/plain');
    });

    it('should REJECT inline_images with an invalid entry', () => {
        const result = SendEmailSchema.safeParse({
            ...BASE_PAYLOAD,
            htmlBody: '<img src="cid:logo">',
            inline_images: [
                {
                    content_id: 'logo',
                    mime_type: 'image/png',
                    source: '/not/a/file/uri.png', // missing file://
                },
            ],
        });
        assert.strictEqual(result.success, false);
    });
});
