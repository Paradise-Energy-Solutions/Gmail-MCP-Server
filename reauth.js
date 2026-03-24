#!/usr/bin/env node
/**
 * reauth.js — Streamlined Gmail MCP reauthentication helper.
 *
 * Usage:
 *   node reauth.js           (prompts for confirmation before revoking token)
 *   node reauth.js --force   (skips confirmation prompt)
 *   npm run reauth
 *
 * What it does:
 *   1. Verifies the built server and shared config module are present.
 *   2. Imports path resolution from dist/config.js (same logic as the server).
 *   3. Verifies that gcp-oauth.keys.json is present.
 *   4. Prompts for confirmation before revoking an existing token (bypass with --force).
 *   5. Removes credentials.json so the server performs a fresh OAuth consent flow.
 *   6. Spawns `node dist/index.js auth` with inherited stdio for the interactive flow.
 */

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import readline from 'readline';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Build check (must precede dynamic import from dist/) ─────────────────────

const serverScript = path.join(__dirname, 'dist', 'index.js');
const configScript = path.join(__dirname, 'dist', 'config.js');

if (!fs.existsSync(serverScript) || !fs.existsSync(configScript)) {
    console.error(
        `ERROR: Built files not found in dist/.\n` +
        `Run \`npm run build\` first.`
    );
    process.exit(1);
}

// ── Import shared path config (single source of truth: src/config.ts) ────────

const { CONFIG_DIR, OAUTH_PATH, CREDENTIALS_PATH } = await import('./dist/config.js');

// ── Pre-flight checks ─────────────────────────────────────────────────────────

console.log('=== Gmail MCP Reauthentication ===\n');

if (!fs.existsSync(OAUTH_PATH)) {
    console.error(
        `ERROR: OAuth keys file not found.\n` +
        `Expected at: ${OAUTH_PATH}\n\n` +
        `Place gcp-oauth.keys.json in the project root or in ${CONFIG_DIR}, ` +
        `or set the GMAIL_OAUTH_PATH environment variable.`
    );
    process.exit(1);
}

console.log(`OAuth keys : ${OAUTH_PATH}`);
console.log(`Credentials: ${CREDENTIALS_PATH}\n`);

// ── Confirmation prompt (skip with --force) ───────────────────────────────────

let credentialsExist = false;
try {
    fs.accessSync(CREDENTIALS_PATH);
    credentialsExist = true;
} catch (e) {
    if (e.code !== 'ENOENT') throw e;
}

if (credentialsExist && !process.argv.includes('--force')) {
    const confirmed = await new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question('An existing token will be revoked. Continue? [y/N] ', (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase() === 'y');
        });
    });

    if (!confirmed) {
        console.log('Reauthentication cancelled.');
        process.exit(0);
    }
    console.log();
}

// ── Remove stale token ────────────────────────────────────────────────────────

try {
    fs.rmSync(CREDENTIALS_PATH);
    console.log('Removed existing credentials.json — starting fresh OAuth flow.\n');
} catch (err) {
    if (err.code !== 'ENOENT') throw err;
    console.log('No existing credentials.json found — proceeding to authenticate.\n');
}

// ── Run the auth flow ─────────────────────────────────────────────────────────

console.log(`Launching: node ${serverScript} auth\n`);

const child = spawn(process.execPath, [serverScript, 'auth'], { stdio: 'inherit' });

child.on('error', (err) => {
    console.error('Failed to start auth process:', err.message);
    process.exit(1);
});

child.on('exit', (code) => {
    if (code === 0) {
        console.log('\nReauthentication complete. You can now restart the MCP server.');
    } else {
        console.error(`\nAuth process exited with code ${code}.`);
    }
    process.exit(code ?? 1);
});
