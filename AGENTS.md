# Repository Guidelines

## Project Structure & Module Organization
- `src/main.rs` contains the entire bot implementation (entry point, handlers, and DB helpers).
- `Cargo.toml` defines Rust dependencies and build metadata.
- `bot.sqlite` is the local SQLite database used at runtime.
- `target/` is Cargo build output (generated).

## Build, Test, and Development Commands
- `cargo build` compiles the bot.
- `cargo run` builds and starts the bot locally.
- `cargo test` runs the test suite (none currently defined).

## Configuration & Environment
- Required env vars: `TG_BOT_TOKEN` (Telegram bot token), `OPENROUTER_API_KEY` (OpenRouter API key).
- Optional: create a `.env` file in the repo root; `dotenvy` loads it at startup.
- The bot writes to `bot.sqlite` in the repo root; keep this file out of PRs unless explicitly needed.

## Coding Style & Naming Conventions
- Language: Rust 2021 edition.
- Use `rustfmt` defaults (4-space indentation, 100-column style typical for Rust).
- Prefer `snake_case` for functions/variables, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for consts.
- Keep async handlers small; move DB work into `db_call` closures when possible.

## Testing Guidelines
- No framework-specific tests are present yet.
- If adding tests, use `#[cfg(test)]` and `#[test]` or `#[tokio::test]` in Rust modules.
- Name tests by behavior (e.g., `test_classify_rejects_safe_message`).

## Commit & Pull Request Guidelines
- No commit history is available yet; use concise, imperative commit messages (e.g., "Add admin stats report").
- PRs should include:
  - A short description of the change and rationale.
  - Any new env vars or migrations needed.
  - Screenshots or logs only when user-visible behavior changes.

## Agent-Specific Instructions
- Follow instructions in `AGENTS.md` when present; keep guidance under 400 words and repo-specific.
