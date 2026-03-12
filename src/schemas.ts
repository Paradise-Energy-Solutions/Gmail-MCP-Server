/**
 * Email tool Zod schemas.
 *
 * Extracted into a dedicated module so they can be imported by both
 * the server entry point (index.ts) and the test suite without
 * bootstrapping the full MCP server (OAuth init, file system, process.exit, etc.).
 */

import { z } from 'zod';
import path from 'path';

// ── InlineImageSchema ────────────────────────────────────────────────────────

/**
 * Describes one inline (CID-referenced) image to embed in the HTML body.
 * The image is transported as a multipart/related MIME part rather than
 * as a base64 data URI, which prevents agent context-window overflow.
 *
 * Usage in htmlBody: <img src="cid:logo" />
 * Corresponding entry: { content_id: "logo", mime_type: "image/png", source: "/path/to/logo.png" }
 */
export const InlineImageSchema = z.object({
    content_id: z
        .string()
        .regex(
            /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/,
            'content_id must start with a letter or digit and contain only letters, digits, underscores, hyphens, or dots'
        )
        .max(255, 'content_id must not exceed 255 characters')
        .describe(
            'Unique identifier referenced in htmlBody as <img src="cid:<content_id>">. ' +
            'Example: "logo" for <img src="cid:logo">'
        ),
    mime_type: z
        .string()
        .regex(
            /^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^.]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^.+]*$/,
            'mime_type must be a valid media type such as image/png or image/jpeg'
        )
        .max(100, 'mime_type must not exceed 100 characters')
        .describe('MIME type of the image. Examples: "image/png", "image/jpeg", "image/gif"'),
    source: z
        .string()
        .refine(
            (value) => value.startsWith('file://') || path.isAbsolute(value),
            {
                message:
                    'source must be either a file:// URI (e.g., "file:///home/user/images/logo.png") ' +
                    'or an absolute filesystem path (e.g., "/home/user/images/logo.png" or "C:\\images\\logo.png")',
            }
        )
        .describe(
            'Location of the image on the server filesystem. ' +
            'Accepts either a file:// URI or an absolute filesystem path. ' +
            'The file must reside inside GMAIL_MCP_ALLOWED_READ_PATH. ' +
            'Examples: "file:///home/user/images/logo.png", "/home/user/images/logo.png", "C:\\images\\logo.png"'
        ),
});

// ── SendEmailSchema ──────────────────────────────────────────────────────────

export const SendEmailSchema = z
    .object({
        to: z.array(z.string()).describe('List of recipient email addresses'),
        subject: z.string().describe('Email subject'),
        body: z
            .string()
            .describe('Email body content (used for text/plain or when htmlBody not provided)'),
        htmlBody: z
            .string()
            .optional()
            .describe(
                'HTML version of the email body. ' +
                'Mutually exclusive with htmlBodyFile — provide one or the other, not both. ' +
                'Use inline_images to embed images by CID reference instead of base64 data URIs.'
            ),
        htmlBodyFile: z
            .string()
            .optional()
            .describe(
                'Absolute path to an HTML file whose contents become the HTML body. ' +
                'Use this instead of htmlBody when the HTML is large (e.g. contains embedded images) ' +
                'to avoid exceeding the agent context window. ' +
                'The file must reside inside GMAIL_MCP_ALLOWED_READ_PATH. ' +
                'The server automatically uses multipart/alternative so the HTML is rendered — ' +
                'no need to set mimeType separately when using htmlBodyFile. ' +
                'Mutually exclusive with htmlBody — provide one or the other, not both. ' +
                'Example: "/home/user/templates/announcement.html"'
            ),
        mimeType: z
            .enum(['text/plain', 'text/html', 'multipart/alternative'])
            .optional()
            .default('text/plain')
            .describe('Email content type'),
        cc: z.array(z.string()).optional().describe('List of CC recipients'),
        bcc: z.array(z.string()).optional().describe('List of BCC recipients'),
        threadId: z.string().optional().describe('Thread ID to reply to'),
        inReplyTo: z.string().optional().describe('Message ID being replied to'),
        attachments: z
            .array(z.string())
            .optional()
            .describe(
                'List of absolute file paths to attach to the email. ' +
                'Each file must reside inside GMAIL_MCP_ALLOWED_READ_PATH. ' +
                'Example: ["/home/user/docs/report.pdf"]'
            ),
        inline_images: z
            .array(InlineImageSchema)
            .optional()
            .describe(
                'Inline images to embed as CID (Content-ID) parts in a multipart/related message. ' +
                'Each image is referenced in htmlBody as <img src="cid:<content_id>">. ' +
                'This approach keeps image data out of the agent context window. ' +
                'Requires htmlBody or htmlBodyFile to contain matching cid: references.'
            ),
    })
    // htmlBody and htmlBodyFile are mutually exclusive
    .refine(
        (data) => !(data.htmlBody && data.htmlBodyFile),
        {
            message:
                'Provide either htmlBody or htmlBodyFile, not both. ' +
                'Use htmlBodyFile when the HTML content is large to avoid agent context-window overflow.',
            path: ['htmlBody'],
        }
    )
    // inline_images requires an HTML body source (htmlBody or htmlBodyFile) to
    // contain the matching cid: references; providing inline_images without any
    // HTML body would produce unreferenced MIME parts with no visible effect.
    .refine(
        (data) =>
            !data.inline_images ||
            data.inline_images.length === 0 ||
            data.htmlBody !== undefined ||
            data.htmlBodyFile !== undefined,
        {
            message:
                'inline_images requires htmlBody or htmlBodyFile to contain matching cid: references.',
            path: ['inline_images'],
        }
    );
