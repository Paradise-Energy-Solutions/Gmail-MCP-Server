# Gmail MCP Server — Paradise Energy Solutions

An internal Model Context Protocol (MCP) server for Gmail integration, enabling AI assistants to manage Gmail through natural language interactions. This is a **security-hardened fork** of the original `@gongrzhe/server-gmail-autoauth-mcp` package, maintained for use within Paradise Energy Solutions.

> **⚠️ INTERNAL USE ONLY**  
> This server provides full access to Gmail operations including reading, sending, and deleting emails. Handle with appropriate care and ensure credentials are properly secured.

---

## Security Enhancements (Paradise Energy Fork)

This fork incorporates significant security improvements over the upstream repository:

### 🔒 Path Traversal Protection
- All file operations (attachment downloads) are validated against path traversal attacks
- Filenames are sanitized to remove malicious characters
- Save paths are verified to remain within allowed directories

### 🔑 Configurable OAuth Scopes
- **MINIMAL**: Read-only access to Gmail
- **STANDARD**: Read and send access (no modify/delete)
- **FULL**: Complete access including modify, delete, and settings (default)

Configure via environment variable:

```bash
GMAIL_MCP_SCOPE_LEVEL=STANDARD  # Options: MINIMAL, STANDARD, FULL
```

### 🛡️ Secure Credential Storage
- OAuth tokens are written with restrictive file permissions (`0o600`)
- Credentials are accessible only by the owning user
- Automatic permission enforcement on credential files

### 📋 Comprehensive Input Validation
- Email address validation (RFC 5322 compliant)
- Message ID format validation
- Label/filter ID validation
- Search query injection protection

### 📝 Audit Logging Infrastructure
- Structured JSON logging for security events
- Configurable log levels
- Supports security monitoring and compliance requirements

### ⏱️ Rate Limiting
- Token bucket algorithm prevents API abuse
- Configurable limits per operation type

For complete security details, see [SECURITY-REVIEW-2025-12.md](./SECURITY-REVIEW-2025-12.md).

---

## ⚠️ Important Safety Warnings

Before using this MCP server, please understand the following:

1. **Full Gmail Access**: This server can read, send, modify, and permanently delete emails. Actions taken through AI assistants are real and often irreversible.

2. **Credential Security**: 
   - Never share your `gcp-oauth.keys.json` or `credentials.json` files
   - Never commit credentials to version control
   - Store credentials only in the designated `~/.gmail-mcp/` directory

3. **AI Assistant Behaviour**: When using this server with AI assistants:
   - Always verify email recipients before sending
   - Review email content before confirming send operations
   - Be cautious with bulk operations (batch delete, batch modify)
   - The AI may misinterpret ambiguous instructions

4. **Audit Your Activity**: Regularly review your Gmail "Sent" folder and activity to ensure no unintended actions have occurred.

5. **Revoke Access When Not Needed**: If you no longer require MCP access, revoke the OAuth token in your [Google Account Security Settings](https://myaccount.google.com/permissions).

---

## Features

- **Send emails** with subject, content, attachments, and recipients
- **Full attachment support** — send and receive file attachments
- **Download email attachments** to local filesystem
- **HTML and multipart messages** with both HTML and plain text versions
- **International character support** in subjects and content
- **Read email messages** with advanced MIME structure handling
- **Search emails** using Gmail's powerful search syntax
- **Comprehensive label management** — create, update, delete, and list labels
- **Gmail filter management** — create, list, and delete filters
- **Batch operations** for efficiently processing multiple emails
- **Mark emails** as read/unread
- **Move emails** to different labels/folders
- **Delete emails** (use with caution)

---

## Installation & Configuration

### Prerequisites

1. **Node.js** (v18 or later recommended)
2. **Google Cloud Project** with Gmail API enabled
3. **OAuth 2.0 Credentials** (Desktop or Web application type)

### Step 1: Obtain Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Gmail API** for your project
4. Navigate to "APIs & Services" > "Credentials"
5. Click "Create Credentials" > "OAuth client ID"
6. Choose "Desktop app" as the application type
7. Download the JSON file and rename it to `gcp-oauth.keys.json`

### Step 2: Set Up Credentials Directory

```bash
# Create the credentials directory
mkdir -p ~/.gmail-mcp

# Move your OAuth keys file
mv gcp-oauth.keys.json ~/.gmail-mcp/

# Secure the directory
chmod 700 ~/.gmail-mcp
chmod 600 ~/.gmail-mcp/gcp-oauth.keys.json
```

### Step 3: Build the Server

```bash
cd /home/aegbert/gmail-mcp/gmail-mcp-server
npm install
npm run build
```

### Step 4: Authenticate

```bash
node dist/index.js auth
```

This will open your browser for Google OAuth authentication. After successful authentication, credentials will be saved to `~/.gmail-mcp/credentials.json`.

---

## VS Code Configuration

### Standard Linux/macOS Configuration

Add the following to your VS Code `mcp.json` (typically at `~/.config/Code/User/mcp.json`):

```json
{
  "servers": {
    "gmail": {
      "type": "stdio",
      "command": "node",
      "args": ["/home/aegbert/gmail-mcp/gmail-mcp-server/dist/index.js"],
      "env": {
        "GMAIL_OAUTH_PATH": "/home/aegbert/.gmail-mcp/gcp-oauth.keys.json"
      }
    }
  }
}
```

### WSL (Windows Subsystem for Linux) Configuration

When running VS Code in WSL mode from Windows, path handling requires special attention. The VS Code process runs from the Windows side, so paths must be accessible to Windows.

**Use WSL UNC paths for both the server and credentials:**

```json
{
  "servers": {
    "gmail": {
      "type": "stdio",
      "command": "node",
      "args": ["//wsl.localhost/Ubuntu/home/aegbert/gmail-mcp/gmail-mcp-server/dist/index.js"],
      "env": {
        "GMAIL_OAUTH_PATH": "//wsl.localhost/Ubuntu/home/aegbert/.gmail-mcp/gcp-oauth.keys.json"
      }
    }
  }
}
```

**Common WSL Pitfall**: If you use a Linux path (e.g., `/home/user/.gmail-mcp/...`) for `GMAIL_OAUTH_PATH` whilst the server executable uses a Windows UNC path, the server will fail to locate the credentials file. Both paths must use the same format.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GMAIL_OAUTH_PATH` | Path to `gcp-oauth.keys.json` | `~/.gmail-mcp/gcp-oauth.keys.json` |
| `GMAIL_CREDENTIALS_PATH` | Path to stored credentials | `~/.gmail-mcp/credentials.json` |
| `GMAIL_CONFIG_DIR` | Configuration directory | `~/.gmail-mcp` |
| `GMAIL_MCP_SCOPE_LEVEL` | OAuth scope level | `FULL` |

---

## Available Tools

### Email Operations

| Tool | Description |
|------|-------------|
| `send_email` | Send a new email (supports attachments) |
| `draft_email` | Create a draft email |
| `read_email` | Read an email by ID |
| `search_emails` | Search emails using Gmail syntax |
| `modify_email` | Add/remove labels from an email |
| `delete_email` | Permanently delete an email |
| `download_attachment` | Download an email attachment |

### Batch Operations

| Tool | Description |
|------|-------------|
| `batch_modify_emails` | Modify labels for multiple emails |
| `batch_delete_emails` | Delete multiple emails |

### Label Management

| Tool | Description |
|------|-------------|
| `list_email_labels` | List all Gmail labels |
| `create_label` | Create a new label |
| `update_label` | Update an existing label |
| `delete_label` | Delete a label |
| `get_or_create_label` | Get or create a label by name |

### Filter Management

| Tool | Description |
|------|-------------|
| `create_filter` | Create a Gmail filter |
| `create_filter_from_template` | Create filter from template |
| `list_filters` | List all filters |
| `get_filter` | Get filter details |
| `delete_filter` | Delete a filter |

---

## Search Syntax

The `search_emails` tool supports Gmail's search operators:

| Operator | Example | Description |
|----------|---------|-------------|
| `from:` | `from:john@example.com` | Emails from a sender |
| `to:` | `to:mary@example.com` | Emails to a recipient |
| `subject:` | `subject:"meeting notes"` | Subject contains text |
| `has:attachment` | `has:attachment` | Has attachments |
| `after:` | `after:2024/01/01` | After a date |
| `before:` | `before:2024/02/01` | Before a date |
| `is:` | `is:unread` | Email state |
| `label:` | `label:work` | Has a label |
| `in:` | `in:inbox` | In a folder |

Combine operators: `from:boss@company.com after:2024/01/01 has:attachment`

---

## Troubleshooting

### OAuth Keys Not Found

**Error**: `OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or ~/.gmail-mcp`

**Solutions**:
1. Verify the file exists: `ls -la ~/.gmail-mcp/gcp-oauth.keys.json`
2. Check environment variable path is correct
3. **For WSL**: Ensure you're using `//wsl.localhost/Ubuntu/...` paths in your VS Code configuration

### WSL Path Issues

**Symptom**: Server starts but cannot find credentials, error shows Windows path (e.g., `C:\\Users\\...`)

**Cause**: Mismatch between Linux and Windows path formats

**Solution**: Use WSL UNC paths (`//wsl.localhost/Ubuntu/...`) for all paths in `mcp.json` when running VS Code from Windows in WSL mode.

### Invalid Credentials Format

**Error**: Credentials file doesn't contain expected format

**Solution**: Ensure your `gcp-oauth.keys.json` contains either `web` or `installed` credentials object from Google Cloud Console.

### Authentication Timeout

**Symptom**: Server waits indefinitely for `initialize` response

**Possible Causes**:
1. OAuth credentials not yet obtained (run `node dist/index.js auth` first)
2. Credentials file path incorrect
3. Network issues reaching Google OAuth servers

### Permission Errors

**Error**: Cannot read/write credential files

**Solution**:
```bash
chmod 700 ~/.gmail-mcp
chmod 600 ~/.gmail-mcp/*.json
```

### Attachment Issues

- **File Not Found**: Verify attachment paths are absolute and accessible
- **Permission Errors**: Ensure read access to attachment files
- **Size Limits**: Gmail has a 25MB attachment limit per email
- **Download Failures**: Verify write permissions to download directory

---

## Development

### Running Tests

```bash
npm test
```

### Running Evals

```bash
OPENAI_API_KEY=your-key npx mcp-eval src/evals/evals.ts src/index.ts
```

### Building

```bash
npm run build
```

---

## License

MIT

---

## Internal Support

For issues or questions, contact the development team or file an issue on the internal GitHub repository.

**Repository**: [Paradise-Energy-Solutions/Gmail-MCP-Server](https://github.com/Paradise-Energy-Solutions/Gmail-MCP-Server)
