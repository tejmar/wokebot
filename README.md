# Woke Nudge Bot

A Telegram moderation assistant that flags potentially hateful or toxic messages in group chats and lets an admin approve, edit, or ignore suggested replies. It uses OpenRouter for moderation classification and reply drafting, with per-group rate limits, random throttling, and admin controls.

## Features
- Flags messages and sends approvals to a single admin (no auto-replies).
- Per-group settings: enable/disable, notify-only mode, random chance, thresholds, mute.
- Built-in cooldowns: alert (10 min) and post (1 hour).
- SQLite storage for groups, pending approvals, and stats.

## Requirements
- Rust toolchain (edition 2021)
- Telegram bot token
- OpenRouter API key

## Setup
1) Create a `.env` file with:
   ```bash
   TG_BOT_TOKEN=...
   OPENROUTER_API_KEY=...
   ```
2) Update `ADMIN_ID` in `src/main.rs` to your Telegram user ID.

## Run
```bash
cargo run
```

## Admin Panel
- Use `/panel` in the bot DM to open the admin panel.
- List groups to open settings directly.
- Pending approvals show a per-item detail view with Post/Edit/Ignore.

## Data & Files
- `bot.sqlite` is created in the repo root and holds state.
- `src/main.rs` contains all logic (handlers, DB, settings UI).

## Notes
- The bot only processes group/supergroup messages.
- Random chance controls the percentage of flagged items that trigger admin alerts.
- Threshold controls the minimum classifier severity (0..1) required to flag.
