import fs from 'fs';
import path from 'path';
import os from 'os';

/**
 * Root config directory for Gmail MCP credentials.
 * Override with the GMAIL_CONFIG_DIR environment variable.
 */
export const CONFIG_DIR: string = (() => {
    if (process.env.GMAIL_CONFIG_DIR) {
        return process.env.GMAIL_CONFIG_DIR;
    }
    return path.join(os.homedir(), '.gmail-mcp');
})();

/**
 * Path to the Google OAuth keys file (gcp-oauth.keys.json).
 * Resolution order:
 *   1. GMAIL_OAUTH_PATH env var
 *   2. gcp-oauth.keys.json in current working directory
 *   3. CONFIG_DIR/gcp-oauth.keys.json
 */
export const OAUTH_PATH: string = (() => {
    if (process.env.GMAIL_OAUTH_PATH) {
        return process.env.GMAIL_OAUTH_PATH;
    }
    const localPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
    if (fs.existsSync(localPath)) {
        return localPath;
    }
    return path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
})();

/**
 * Path to the stored OAuth token (credentials.json).
 * Override with the GMAIL_CREDENTIALS_PATH environment variable.
 */
export const CREDENTIALS_PATH: string =
    process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');
