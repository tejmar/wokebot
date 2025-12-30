use anyhow::{anyhow, Context, Result};
use dotenvy::dotenv;
use log::{debug, error, info};
use rand::Rng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::env;
use teloxide::prelude::*;
use teloxide::requests::Requester;
use teloxide::types::{
    CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, MaybeInaccessibleMessage, Message,
    MessageId, ReplyParameters,
};
use time::OffsetDateTime;
use tokio::task;
use uuid::Uuid;

const ADMIN_ID: i64 = 370884641;

// Fast/cheap for moderation classification
const OR_MODEL_CLASSIFY: &str = "meta-llama/llama-3.1-8b-instruct";
// Your requested model for educational/witty replies
const OR_MODEL_DRAFT: &str = "sao10k/l3.1-70b-hanami-x1";

// Core behavior tuning
const ALERT_COOLDOWN_SECS: i64 = 10 * 60; // only alert admin once per 10min per group
const POST_COOLDOWN_SECS: i64 = 60 * 60; // max 1 reply/hour per group
const DEFAULT_THRESHOLD: f32 = 0.72;
const DEFAULT_RANDOM_CHANCE: f32 = 0.05;

// Button presets
const THRESH_PRESETS: [f32; 3] = [0.60, 0.72, 0.85];
const RAND_PRESETS: [f32; 4] = [0.00, 0.05, 0.10, 1.00];
const MUTE_PRESETS_SECS: [i64; 3] = [1 * 3600, 6 * 3600, 24 * 3600];

#[derive(Clone)]
struct AppState {
    db_path: String,
    http: reqwest::Client,
    openrouter_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClassifyJson {
    flag: bool,
    category: String,     // hate|harassment|toxicity|none
    severity: f32,        // 0..1
    reason: String,       // short
    safe_summary: String, // short summary w/o slurs
}

#[derive(Debug, Deserialize)]
struct DraftJson {
    reply: String,
}

#[derive(Debug, Clone)]
struct GroupSettings {
    enabled: bool,
    muted_until: i64,
    threshold: f32,
    last_alert_at: i64,
    last_post_at: i64,
    random_chance: f32,
    notify_only: bool,
}

fn now_ts() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn format_duration_secs(secs: i64) -> String {
    if secs <= 0 {
        return "0s".to_string();
    }
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

// Run sqlite work off the async executor (rusqlite is not Send/Sync)
async fn db_call<T, F>(db_path: String, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Connection) -> Result<T> + Send + 'static,
{
    task::spawn_blocking(move || {
        let conn = Connection::open(db_path)?;
        f(conn)
    })
    .await
    .context("sqlite task join failed")?
}

fn add_column_if_missing(conn: &Connection, table: &str, coldef: &str) -> Result<()> {
    let sql = format!("ALTER TABLE {} ADD COLUMN {}", table, coldef);
    match conn.execute(&sql, []) {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate column name") {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}

fn init_db(db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS groups (
  chat_id INTEGER PRIMARY KEY,
  title TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  muted_until INTEGER NOT NULL DEFAULT 0,
  threshold REAL NOT NULL DEFAULT 0.72,
  last_alert_at INTEGER NOT NULL DEFAULT 0,
  last_post_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY,
  chat_id INTEGER NOT NULL,
  chat_title TEXT,
  message_id INTEGER NOT NULL,
  from_user_id INTEGER,
  from_name TEXT,
  message_text TEXT NOT NULL,
  classify_json TEXT NOT NULL,
  suggested_reply TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS edit_sessions (
  admin_id INTEGER PRIMARY KEY,
  pending_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stats (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
"#,
    )?;

    // Migrations
    add_column_if_missing(&conn, "groups", "random_chance REAL NOT NULL DEFAULT 0.05")?;
    add_column_if_missing(&conn, "groups", "notify_only INTEGER NOT NULL DEFAULT 0")?;

    add_column_if_missing(&conn, "groups", "flagged_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "notified_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "posted_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "ignored_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "cooldown_block_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "random_dropped_count INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(&conn, "groups", "last_flag_at INTEGER NOT NULL DEFAULT 0")?;

    for k in [
        "flagged_total",
        "notified_total",
        "posted_total",
        "ignored_total",
        "cooldown_block_total",
        "random_dropped_total",
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO stats(key,value) VALUES(?1,0)",
            params![k],
        )?;
    }

    Ok(())
}

fn inc_stat(conn: &Connection, key: &str, delta: i64) -> Result<()> {
    conn.execute(
        "UPDATE stats SET value = value + ?2 WHERE key=?1",
        params![key, delta],
    )?;
    Ok(())
}

fn bump_group_counter(conn: &Connection, chat_id: i64, col: &str, delta: i64) -> Result<()> {
    let sql = format!("UPDATE groups SET {} = {} + ?2 WHERE chat_id=?1", col, col);
    conn.execute(&sql, params![chat_id, delta])?;
    Ok(())
}

fn upsert_group(conn: &Connection, chat_id: i64, title: &str) -> Result<()> {
    conn.execute(
        r#"
INSERT INTO groups(chat_id, title, threshold, random_chance, notify_only)
VALUES(?1, ?2, ?3, ?4, ?5)
ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title
"#,
        params![chat_id, title, DEFAULT_THRESHOLD, DEFAULT_RANDOM_CHANCE, 0],
    )?;
    Ok(())
}

fn get_group_settings(conn: &Connection, chat_id: i64) -> Result<GroupSettings> {
    let mut stmt = conn.prepare(
        r#"
SELECT
  enabled, muted_until, threshold, last_alert_at, last_post_at,
  random_chance, notify_only
FROM groups WHERE chat_id=?1
"#,
    )?;
    let row = stmt.query_row(params![chat_id], |r| {
        let enabled: i64 = r.get(0)?;
        let muted_until: i64 = r.get(1)?;
        let threshold: f32 = r.get(2)?;
        let last_alert_at: i64 = r.get(3)?;
        let last_post_at: i64 = r.get(4)?;
        let random_chance: f32 = r.get(5)?;
        let notify_only: i64 = r.get(6)?;
        Ok(GroupSettings {
            enabled: enabled == 1,
            muted_until,
            threshold,
            last_alert_at,
            last_post_at,
            random_chance,
            notify_only: notify_only == 1,
        })
    })?;
    Ok(row)
}

fn set_group_enabled(conn: &Connection, chat_id: i64, enabled: bool) -> Result<()> {
    conn.execute(
        "UPDATE groups SET enabled=?2 WHERE chat_id=?1",
        params![chat_id, if enabled { 1 } else { 0 }],
    )?;
    Ok(())
}

fn set_group_muted_until(conn: &Connection, chat_id: i64, muted_until: i64) -> Result<()> {
    conn.execute(
        "UPDATE groups SET muted_until=?2 WHERE chat_id=?1",
        params![chat_id, muted_until],
    )?;
    Ok(())
}

fn set_group_notify_only(conn: &Connection, chat_id: i64, notify_only: bool) -> Result<()> {
    conn.execute(
        "UPDATE groups SET notify_only=?2 WHERE chat_id=?1",
        params![chat_id, if notify_only { 1 } else { 0 }],
    )?;
    Ok(())
}

fn set_group_threshold(conn: &Connection, chat_id: i64, threshold: f32) -> Result<()> {
    conn.execute(
        "UPDATE groups SET threshold=?2 WHERE chat_id=?1",
        params![chat_id, threshold],
    )?;
    Ok(())
}

fn set_group_random_chance(conn: &Connection, chat_id: i64, p: f32) -> Result<()> {
    conn.execute(
        "UPDATE groups SET random_chance=?2 WHERE chat_id=?1",
        params![chat_id, p],
    )?;
    Ok(())
}

fn update_last_alert_at(conn: &Connection, chat_id: i64, ts: i64) -> Result<()> {
    conn.execute(
        "UPDATE groups SET last_alert_at=?2 WHERE chat_id=?1",
        params![chat_id, ts],
    )?;
    Ok(())
}

fn update_last_post_at(conn: &Connection, chat_id: i64, ts: i64) -> Result<()> {
    conn.execute(
        "UPDATE groups SET last_post_at=?2 WHERE chat_id=?1",
        params![chat_id, ts],
    )?;
    Ok(())
}

fn set_last_flag_at(conn: &Connection, chat_id: i64, ts: i64) -> Result<()> {
    conn.execute(
        "UPDATE groups SET last_flag_at=?2 WHERE chat_id=?1",
        params![chat_id, ts],
    )?;
    Ok(())
}

fn extract_first_json_object(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'{' {
            if depth == 0 {
                start = Some(i);
            }
            depth += 1;
        } else if b == b'}' {
            if depth > 0 {
                depth -= 1;
                if depth == 0 {
                    let st = start?;
                    return Some(s[st..=i].to_string());
                }
            }
        }
    }
    None
}

async fn val_from_openrouter(resp: reqwest::Response) -> Result<serde_json::Value> {
    let status = resp.status();
    let txt = resp.text().await.context("Failed reading OpenRouter response text")?;
    if !status.is_success() {
        return Err(anyhow!("OpenRouter error {}: {}", status, txt));
    }
    let val: serde_json::Value =
        serde_json::from_str(&txt).context("OpenRouter JSON parse failed")?;
    Ok(val)
}

async fn openrouter_chat_json<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    model: &str,
    system: &str,
    user: &str,
) -> Result<T> {
    #[derive(Serialize)]
    struct Msg<'a> {
        role: &'a str,
        content: &'a str,
    }
    #[derive(Serialize)]
    struct Body<'a> {
        model: &'a str,
        messages: Vec<Msg<'a>>,
        temperature: f32,
        max_tokens: u32,
    }

    let (temperature, max_tokens) = if model == OR_MODEL_CLASSIFY {
        (0.0, 250)
    } else {
        (0.4, 220)
    };

    let body = Body {
        model,
        messages: vec![
            Msg {
                role: "system",
                content: system,
            },
            Msg {
                role: "user",
                content: user,
            },
        ],
        temperature,
        max_tokens,
    };

    let resp = state
        .http
        .post("https://openrouter.ai/api/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", state.openrouter_key))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://example.com/woke-nudge-bot")
        .header("X-Title", "Woke Nudge Bot")
        .json(&body)
        .send()
        .await
        .context("OpenRouter request failed")?;

    let val = val_from_openrouter(resp).await?;
    let content = val["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("OpenRouter response missing message content"))?
        .trim()
        .to_string();

    let json_str =
        extract_first_json_object(&content).ok_or_else(|| anyhow!("Model did not return JSON. Got: {}", content))?;

    let parsed: T = serde_json::from_str(&json_str)
        .with_context(|| format!("Failed to parse model JSON: {}", json_str))?;
    Ok(parsed)
}

async fn classify_message(state: &AppState, chat_title: &str, msg_text: &str) -> Result<ClassifyJson> {
    let system = r#"
You are a content moderation classifier.
Return ONLY a single JSON object. No markdown.
Do NOT include slurs or quoted hateful phrases in outputs.
Schema:
{
  "flag": boolean,
  "category": "hate"|"harassment"|"toxicity"|"none",
  "severity": number,
  "reason": string,
  "safe_summary": string
}
"#;

    let user = format!(
        "Chat title: {}\nMessage:\n{}\n\nClassify the message.",
        chat_title, msg_text
    );

    openrouter_chat_json::<ClassifyJson>(state, OR_MODEL_CLASSIFY, system, &user).await
}

async fn draft_reply(state: &AppState, msg_text: &str) -> Result<String> {
    let system = r#"
You write educational, witty, calm replies that reduce harm.
Rules:
- 1–2 sentences max.
- No insults or mockery of the person.
- No slurs, no quoting slurs back.
- Focus on correcting misinformation, empathy, and civility.
Return ONLY JSON: {"reply":"..."}
"#;

    let user = format!(
        "Write a reply to this message:\n{}\n\nMake it educational + lightly witty, but respectful.",
        msg_text
    );

    let draft = openrouter_chat_json::<DraftJson>(state, OR_MODEL_DRAFT, system, &user).await?;
    Ok(draft.reply.trim().to_string())
}

fn help_text() -> &'static str {
    "🧠 Woke-Nudge-Bot Admin Help\n\n\
This bot never auto-replies. It flags messages and asks you to approve.\n\n\
Key behaviors:\n\
• Classification: cheap model decides if a message looks hateful/bigoted.\n\
• Random throttle: even if flagged, only notifies ~p% of the time per-group.\n\
• Rate limits: max 1 reply/hour per group + max 1 notify/10min per group.\n\n\
Alert buttons:\n\
• ✅ Post: replies in the group (threaded) unless Notify-only is ON.\n\
• ✏️ Edit: you send the exact reply text in DM within 5 minutes.\n\
• 🗑 Ignore: discards that pending item.\n\
• ⚙️ Group settings: opens per-group controls.\n\n\
Group settings:\n\
• Random chance: 0% / 5% / 10%\n\
• Threshold: 0.60 / 0.72 / 0.85\n\
• Mute: 1h / 6h / 24h\n\
• Notify-only: ON means never post, only notify you.\n\
• Enable/Disable: stop/resume monitoring.\n"
}

fn panel_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![
        vec![
            InlineKeyboardButton::callback("📋 List groups", "groups".to_string()),
            InlineKeyboardButton::callback("🧾 Pending count", "pending_count".to_string()),
        ],
        vec![
            InlineKeyboardButton::callback("📊 Stats", "stats".to_string()),
            InlineKeyboardButton::callback("❓ Help", "help".to_string()),
        ],
        vec![
            InlineKeyboardButton::callback("🔔 Unmute expired", "unmute_expired".to_string()),
            InlineKeyboardButton::callback("🧹 Clear pending", "clear_pending".to_string()),
        ],
    ])
}

fn alert_keyboard(pending_id: &str, chat_id: i64, notify_only: bool) -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![
        vec![
            InlineKeyboardButton::callback("✅ Post", format!("post:{}", pending_id)),
            InlineKeyboardButton::callback("✏️ Edit", format!("edit:{}", pending_id)),
            InlineKeyboardButton::callback("🗑 Ignore", format!("ignore:{}", pending_id)),
        ],
        vec![
            InlineKeyboardButton::callback(
                if notify_only { "🕵️ Notify-only ON" } else { "💬 Replies ON" },
                format!("toggle_notify:{}", chat_id),
            ),
            InlineKeyboardButton::callback("⚙️ Group settings", format!("gset:{}", chat_id)),
        ],
        vec![
            InlineKeyboardButton::callback("🛠 Admin panel", "panel".to_string()),
            InlineKeyboardButton::callback("❓ Help", "help".to_string()),
            InlineKeyboardButton::callback("📊 Stats", "stats".to_string()),
        ],
    ])
}

fn pending_detail_keyboard(pending_id: &str, chat_id: i64, notify_only: bool) -> InlineKeyboardMarkup {
    let mut rows = alert_keyboard(pending_id, chat_id, notify_only).inline_keyboard;
    rows.push(vec![InlineKeyboardButton::callback(
        "⬅️ Back to pending",
        "pending_count".to_string(),
    )]);
    InlineKeyboardMarkup::new(rows)
}

fn group_settings_keyboard(chat_id: i64, s: &GroupSettings) -> InlineKeyboardMarkup {
    // Random presets row
    let rand_row = RAND_PRESETS
        .iter()
        .map(|p| {
            let label = format!(
                "{}{}%",
                if (s.random_chance - p).abs() < 0.0001 { "✅ " } else { "" },
                (p * 100.0).round() as i32
            );
            InlineKeyboardButton::callback(label, format!("setp:{}:{:.2}", chat_id, p))
        })
        .collect::<Vec<_>>();

    // Threshold presets row
    let thr_row = THRESH_PRESETS
        .iter()
        .map(|t| {
            let label = format!(
                "{}{:.2}",
                if (s.threshold - t).abs() < 0.0001 { "✅ " } else { "" },
                t
            );
            InlineKeyboardButton::callback(label, format!("sett:{}:{:.2}", chat_id, t))
        })
        .collect::<Vec<_>>();

    // Mute row
    let mute_row = vec![
        InlineKeyboardButton::callback("🔇 1h", format!("mute:{}:{}", chat_id, MUTE_PRESETS_SECS[0])),
        InlineKeyboardButton::callback("🔇 6h", format!("mute:{}:{}", chat_id, MUTE_PRESETS_SECS[1])),
        InlineKeyboardButton::callback("🔇 24h", format!("mute:{}:{}", chat_id, MUTE_PRESETS_SECS[2])),
    ];
    let unmute_row = vec![InlineKeyboardButton::callback(
        "🔔 Unmute",
        format!("unmute:{}", chat_id),
    )];

    // Core toggles
    let toggle_row = vec![
        InlineKeyboardButton::callback(
            if s.enabled { "✅ Enabled" } else { "⛔ Disabled" },
            format!("tgen:{}", chat_id),
        ),
        InlineKeyboardButton::callback(
            if s.notify_only { "🕵️ Notify-only" } else { "💬 Replies" },
            format!("toggle_notify:{}", chat_id),
        ),
    ];
    let cooldown_row = vec![
        InlineKeyboardButton::callback("⏱ Clear alert cooldown", format!("clr_alert:{}", chat_id)),
        InlineKeyboardButton::callback("⏱ Clear post cooldown", format!("clr_post:{}", chat_id)),
    ];

    InlineKeyboardMarkup::new(vec![
        vec![InlineKeyboardButton::callback("🎲 Random chance", "noop".to_string())],
        rand_row,
        vec![InlineKeyboardButton::callback("🎚 Threshold", "noop".to_string())],
        thr_row,
        vec![InlineKeyboardButton::callback("🔇 Mute", "noop".to_string())],
        mute_row,
        unmute_row,
        vec![InlineKeyboardButton::callback("⚙️ Mode", "noop".to_string())],
        toggle_row,
        vec![InlineKeyboardButton::callback("⏱ Cooldowns", "noop".to_string())],
        cooldown_row,
        vec![
            InlineKeyboardButton::callback("⬅️ Back", "panel".to_string()),
            InlineKeyboardButton::callback("❓ Help", "help".to_string()),
        ],
    ])
}

async fn send_panel(bot: &Bot) -> Result<()> {
    bot.send_message(ChatId(ADMIN_ID), "🛠 Admin panel")
        .reply_markup(panel_keyboard())
        .await?;
    Ok(())
}

async fn send_or_edit_admin_message(
    bot: &Bot,
    message: Option<MaybeInaccessibleMessage>,
    text: String,
    markup: Option<InlineKeyboardMarkup>,
) -> Result<()> {
    if let Some(msg) = message.as_ref().and_then(|m| m.regular_message()) {
        let mut req = bot.edit_message_text(ChatId(ADMIN_ID), msg.id, text);
        if let Some(kb) = markup {
            req = req.reply_markup(kb);
        }
        req.await?;
    } else {
        let mut req = bot.send_message(ChatId(ADMIN_ID), text);
        if let Some(kb) = markup {
            req = req.reply_markup(kb);
        }
        req.await?;
    }
    Ok(())
}

fn shorten_label(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let trimmed: String = s.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{}...", trimmed)
}

async fn send_panel_to(bot: &Bot, message: Option<MaybeInaccessibleMessage>) -> Result<()> {
    send_or_edit_admin_message(
        bot,
        message,
        "🛠 Admin panel".to_string(),
        Some(panel_keyboard()),
    )
    .await
}

async fn send_help(bot: &Bot) -> Result<()> {
    bot.send_message(ChatId(ADMIN_ID), help_text()).await?;
    Ok(())
}

async fn send_help_to(bot: &Bot, message: Option<MaybeInaccessibleMessage>) -> Result<()> {
    let back = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
        "⬅️ Back",
        "panel".to_string(),
    )]]);
    send_or_edit_admin_message(bot, message, help_text().to_string(), Some(back)).await
}

async fn build_stats_report(state: &AppState) -> Result<String> {
    db_call(state.db_path.clone(), move |conn| {
        let mut out = String::new();
        let get = |k: &str| -> i64 {
            conn.query_row("SELECT value FROM stats WHERE key=?1", params![k], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
        };

        out.push_str("📊 Stats (global)\n");
        out.push_str(&format!("- flagged_total: {}\n", get("flagged_total")));
        out.push_str(&format!("- notified_total: {}\n", get("notified_total")));
        out.push_str(&format!("- posted_total: {}\n", get("posted_total")));
        out.push_str(&format!("- ignored_total: {}\n", get("ignored_total")));
        out.push_str(&format!("- cooldown_block_total: {}\n", get("cooldown_block_total")));
        out.push_str(&format!("- random_dropped_total: {}\n", get("random_dropped_total")));

        out.push_str("\n📋 Per-group (top 15 by flagged_count)\n");

        let mut stmt = conn.prepare(
            r#"
SELECT title, chat_id, enabled, muted_until, notify_only, random_chance,
       threshold,
       flagged_count, notified_count, posted_count, ignored_count, cooldown_block_count, random_dropped_count
FROM groups
ORDER BY flagged_count DESC
LIMIT 15
"#,
        )?;
        let mut rows = stmt.query([])?;
        let now = now_ts();

        while let Some(r) = rows.next()? {
            let title: String = r.get(0)?;
            let chat_id: i64 = r.get(1)?;
            let enabled: i64 = r.get(2)?;
            let muted_until: i64 = r.get(3)?;
            let notify_only: i64 = r.get(4)?;
            let random_chance: f32 = r.get(5)?;
            let threshold: f32 = r.get(6)?;
            let flagged: i64 = r.get(7)?;
            let notified: i64 = r.get(8)?;
            let posted: i64 = r.get(9)?;
            let ignored: i64 = r.get(10)?;
            let cooldown: i64 = r.get(11)?;
            let dropped: i64 = r.get(12)?;

            let status = if enabled == 1 { "EN" } else { "DIS" };
            let muted = if muted_until > now { "MUTED" } else { "OK" };
            let mode = if notify_only == 1 { "notify-only" } else { "replies" };

            out.push_str(&format!(
                "\n• {} ({}) [{}|{}|{}|p={:.0}%|t={:.2}]\n  flagged:{} notified:{} posted:{} ignored:{} cooldown:{} dropped:{}\n",
                title,
                chat_id,
                status,
                muted,
                mode,
                random_chance * 100.0,
                threshold,
                flagged,
                notified,
                posted,
                ignored,
                cooldown,
                dropped
            ));
        }

        Ok(out)
    })
    .await
}

async fn send_stats(bot: &Bot, state: &AppState) -> Result<()> {
    let report = build_stats_report(state).await?;
    bot.send_message(ChatId(ADMIN_ID), report).await?;
    Ok(())
}

async fn send_stats_to(
    bot: &Bot,
    state: &AppState,
    message: Option<MaybeInaccessibleMessage>,
) -> Result<()> {
    let report = build_stats_report(state).await?;
    let back = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
        "⬅️ Back",
        "panel".to_string(),
    )]]);
    send_or_edit_admin_message(bot, message, report, Some(back)).await
}

async fn show_group_settings(
    bot: &Bot,
    state: &AppState,
    chat_id: i64,
    message: Option<MaybeInaccessibleMessage>,
) -> Result<()> {
    let (title, s) = db_call(state.db_path.clone(), move |conn| {
        let title: String = conn
            .query_row("SELECT COALESCE(title,'(unknown)') FROM groups WHERE chat_id=?1", params![chat_id], |r| r.get(0))
            .unwrap_or_else(|_| "(unknown)".to_string());
        let s = get_group_settings(&conn, chat_id)?;
        Ok((title, s))
    })
    .await?;

    let now = now_ts();
    let muted = if s.muted_until > now {
        format!("MUTED ({})", format_duration_secs(s.muted_until - now))
    } else {
        "not muted".to_string()
    };

    let alert_cd = (ALERT_COOLDOWN_SECS - (now - s.last_alert_at)).max(0);
    let post_cd = (POST_COOLDOWN_SECS - (now - s.last_post_at)).max(0);
    let alert_cd_text = if alert_cd > 0 {
        format!("{} remaining", format_duration_secs(alert_cd))
    } else {
        "ready".to_string()
    };
    let post_cd_text = if post_cd > 0 {
        format!("{} remaining", format_duration_secs(post_cd))
    } else {
        "ready".to_string()
    };

    let text = format!(
        "⚙️ Group settings\n\
{} ({})\n\
Status: {}\n\
Mode: {}\n\
Random chance: {:.0}%\n\
Threshold: {:.2}\n\
Mute: {}\n\
Alert cooldown: {}\n\
Post cooldown: {}\n",
        title,
        chat_id,
        if s.enabled { "ENABLED" } else { "DISABLED" },
        if s.notify_only { "notify-only" } else { "replies" },
        s.random_chance * 100.0,
        s.threshold,
        muted,
        alert_cd_text,
        post_cd_text
    );

    send_or_edit_admin_message(
        bot,
        message,
        text,
        Some(group_settings_keyboard(chat_id, &s)),
    )
    .await?;

    Ok(())
}

async fn show_pending_details(
    bot: &Bot,
    state: &AppState,
    pending_id: &str,
    message: Option<MaybeInaccessibleMessage>,
) -> Result<()> {
    let pid = pending_id.to_string();
    let result: Option<(
        i64,
        String,
        String,
        String,
        String,
        String,
        i64,
        bool,
    )> = db_call(state.db_path.clone(), move |conn| {
            let row = conn
                .query_row(
                    r#"
SELECT chat_id, chat_title, message_text, from_name, classify_json, suggested_reply, created_at
FROM pending WHERE id=?1
"#,
                    params![pid],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, String>(5)?,
                            r.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()?;

            let Some(row) = row else {
                return Ok(None);
            };

            let notify_only: i64 = conn
                .query_row("SELECT notify_only FROM groups WHERE chat_id=?1", params![row.0], |r| {
                    r.get(0)
                })
                .unwrap_or(0);

            Ok(Some((
                row.0,
                row.1,
                row.2,
                row.3.unwrap_or_else(|| "Unknown".to_string()),
                row.4,
                row.5,
                row.6,
                notify_only == 1,
            )))
        })
        .await?;

    let Some((
        chat_id,
        chat_title,
        message_text,
        from_name,
        classify_json,
        suggested_reply,
        created_at,
        notify_only,
    )) = result
    else {
        let back = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
            "⬅️ Back",
            "pending_count".to_string(),
        )]]);
        send_or_edit_admin_message(
            bot,
            message,
            "🧾 Pending item not found (maybe already handled).".to_string(),
            Some(back),
        )
        .await?;
        return Ok(());
    };

    let classify: ClassifyJson = serde_json::from_str(&classify_json)?;

    let text = format!(
        "🧾 Pending approval\n\
Group: {} ({})\n\
From: {}\n\
Created: {}\n\
Category: {} | Severity: {:.2}\n\
Reason: {}\n\
Summary: {}\n\n\
Message:\n{}\n\n\
Suggested reply:\n{}\n",
        chat_title,
        chat_id,
        from_name,
        created_at,
        classify.category,
        classify.severity,
        classify.reason,
        classify.safe_summary,
        message_text,
        suggested_reply
    );

    send_or_edit_admin_message(
        bot,
        message,
        text,
        Some(pending_detail_keyboard(pending_id, chat_id, notify_only)),
    )
    .await?;

    Ok(())
}

async fn handle_group_message(bot: Bot, state: AppState, msg: Message) -> Result<()> {
    let chat = msg.chat.clone();
    let chat_id = chat.id.0;
    let chat_title = chat.title().unwrap_or("unknown group").to_string();

    let Some(text) = msg.text().map(|t| t.to_string()) else {
        return Ok(());
    };

    let chat_title_db = chat_title.clone();

    // Ensure group exists + fetch settings
    let settings = db_call(state.db_path.clone(), move |conn| {
        upsert_group(&conn, chat_id, &chat_title_db)?;
        Ok(get_group_settings(&conn, chat_id)?)
    })
    .await?;

    let now = now_ts();

    debug!(
        "group={} enabled={} muted_until={} last_alert_at={} threshold={} p={} notify_only={}",
        chat_id,
        settings.enabled,
        settings.muted_until,
        settings.last_alert_at,
        settings.threshold,
        settings.random_chance,
        settings.notify_only
    );

    if !settings.enabled || settings.muted_until > now || (now - settings.last_alert_at) < ALERT_COOLDOWN_SECS {
        return Ok(());
    }

    // Classify (cheap model)
    let classify = classify_message(&state, &chat_title, &text).await?;

    debug!(
        "classify chat_id={} flag={} cat={} sev={:.2} threshold={:.2}",
        chat_id, classify.flag, classify.category, classify.severity, settings.threshold
    );

    if !classify.flag || classify.severity < settings.threshold {
        return Ok(());
    }

    // Random throttle
    let roll: f32 = rand::thread_rng().gen();
    if roll > settings.random_chance {
        db_call(state.db_path.clone(), move |conn| {
            bump_group_counter(&conn, chat_id, "random_dropped_count", 1)?;
            inc_stat(&conn, "random_dropped_total", 1)?;
            Ok(())
        })
        .await?;
        return Ok(());
    }

    // Draft suggested reply (Hanami)
    let suggested = draft_reply(&state, &text).await?;
    let pending_id = Uuid::new_v4().to_string();

    let from = msg.from.clone();
    let (from_id, from_name) = if let Some(u) = from {
        let full = match &u.last_name {
            Some(ln) if !ln.is_empty() => format!("{} {}", u.first_name, ln),
            _ => u.first_name.clone(),
        };
        (Some(u.id.0 as i64), Some(full))
    } else {
        (None, None)
    };

    let pending_id_db = pending_id.clone();
    let title_for_db = chat_title.clone();
    let text_for_db = text.clone();
    let classify_for_db = serde_json::to_string(&classify)?;
    let suggested_for_db = suggested.clone();
    let msg_id_for_db = msg.id.0 as i64;
    let cat_for_log = classify.category.clone();
    let sev_for_log = classify.severity;

    let (dm_text, notify_only_now) = db_call(state.db_path.clone(), move |conn| {
        conn.execute(
            r#"INSERT INTO pending
(id, chat_id, chat_title, message_id, from_user_id, from_name, message_text, classify_json, suggested_reply, created_at)
VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#,
            params![
                pending_id_db,
                chat_id,
                title_for_db,
                msg_id_for_db,
                from_id,
                from_name,
                text_for_db,
                classify_for_db,
                suggested_for_db,
                now
            ],
        )?;

        update_last_alert_at(&conn, chat_id, now)?;
        set_last_flag_at(&conn, chat_id, now)?;

        bump_group_counter(&conn, chat_id, "flagged_count", 1)?;
        bump_group_counter(&conn, chat_id, "notified_count", 1)?;
        inc_stat(&conn, "flagged_total", 1)?;
        inc_stat(&conn, "notified_total", 1)?;

        let group_title: String = conn
            .query_row("SELECT title FROM groups WHERE chat_id=?1", params![chat_id], |r| r.get(0))
            .unwrap_or_else(|_| "unknown group".to_string());

        let from_disp: String = conn
            .query_row(
                "SELECT COALESCE(from_name,'Unknown') FROM pending WHERE id=?1",
                params![pending_id_db],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "Unknown".to_string());

        let notify_only: i64 = conn
            .query_row("SELECT notify_only FROM groups WHERE chat_id=?1", params![chat_id], |r| r.get(0))
            .unwrap_or(0);

        let mut dm = format!(
            "🚩 Flagged message\n\
Group: {} ({})\n\
From: {}\n\
Category: {} | Severity: {:.2}\n\
Reason: {}\n\
Summary: {}\n\n\
Suggested reply (preview):\n{}\n\n",
            group_title,
            chat_id,
            from_disp,
            classify.category,
            classify.severity,
            classify.reason,
            classify.safe_summary,
            suggested
        );

        if notify_only == 1 {
            dm.push_str("🕵️ Notify-only is ON for this group (Post/Edit will be blocked).\n");
        }

        dm.push_str("Tap Post to reply, Edit to customize.");

        Ok((dm, notify_only == 1))
    })
    .await?;

    info!(
        "notify admin chat_id={} category={} sev={:.2} notify_only={}",
        chat_id, cat_for_log, sev_for_log, notify_only_now
    );

    bot.send_message(ChatId(ADMIN_ID), dm_text)
        .reply_markup(alert_keyboard(&pending_id, chat_id, notify_only_now))
        .await?;

    Ok(())
}

async fn post_pending(
    bot: &Bot,
    state: &AppState,
    pending_id: &str,
    custom_text: Option<String>,
) -> Result<String> {
    let pid = pending_id.to_string();

    let (chat_id, message_id, suggested_reply, allowed, notify_only) =
        db_call(state.db_path.clone(), move |conn| {
            let (chat_id, _chat_title, message_id, suggested_reply): (i64, String, i64, String) =
                conn.query_row(
                    "SELECT chat_id, chat_title, message_id, suggested_reply FROM pending WHERE id=?1",
                    params![pid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;

            let s = get_group_settings(&conn, chat_id)?;
            let now = now_ts();
            let allowed = now - s.last_post_at >= POST_COOLDOWN_SECS;

            Ok((chat_id, message_id, suggested_reply, allowed, s.notify_only))
        })
        .await?;

    if notify_only {
        return Ok("🕵️ Notify-only is ON for this group — posting is disabled.".to_string());
    }

    if !allowed {
        db_call(state.db_path.clone(), move |conn| {
            bump_group_counter(&conn, chat_id, "cooldown_block_count", 1)?;
            inc_stat(&conn, "cooldown_block_total", 1)?;
            Ok(())
        })
        .await?;
        return Ok("⏳ Post blocked: group is on cooldown (max 1/hour).".to_string());
    }

    let text_to_send = custom_text.unwrap_or(suggested_reply);

    let rp = ReplyParameters {
        message_id: MessageId(message_id as i32),
        chat_id: None,
        allow_sending_without_reply: Some(true),
        quote: None,
        quote_parse_mode: None,
        quote_entities: None,
        quote_position: None,
    };

    bot.send_message(ChatId(chat_id), text_to_send)
        .reply_parameters(rp)
        .await?;

    let pid2 = pending_id.to_string();
    db_call(state.db_path.clone(), move |conn| {
        let now = now_ts();
        update_last_post_at(&conn, chat_id, now)?;
        bump_group_counter(&conn, chat_id, "posted_count", 1)?;
        inc_stat(&conn, "posted_total", 1)?;
        conn.execute("DELETE FROM pending WHERE id=?1", params![pid2])?;
        Ok(())
    })
    .await?;

    Ok("✅ Posted.".to_string())
}

async fn handle_admin_dm_text(bot: Bot, state: AppState, msg: Message) -> Result<()> {
    let Some(text) = msg.text().map(|t| t.trim().to_string()) else {
        return Ok(());
    };

    if msg.chat.id.0 != ADMIN_ID {
        return Ok(());
    }

    let now = now_ts();

    // Check edit session
    let pending_id: Option<String> = db_call(state.db_path.clone(), move |conn| {
        let pid: Option<String> = conn
            .query_row(
                "SELECT pending_id FROM edit_sessions WHERE admin_id=?1 AND expires_at>?2",
                params![ADMIN_ID, now],
                |r| r.get(0),
            )
            .optional()?;
        Ok(pid)
    })
    .await?;

    if let Some(pid) = pending_id {
        let pid_end = pid.clone();
        db_call(state.db_path.clone(), move |conn| {
            conn.execute("DELETE FROM edit_sessions WHERE admin_id=?1", params![ADMIN_ID])?;
            Ok(())
        })
        .await?;

        let status = post_pending(&bot, &state, &pid_end, Some(text)).await?;
        bot.send_message(ChatId(ADMIN_ID), status).await?;
        return Ok(());
    }

    match text.as_str() {
        "/start" | "/panel" => send_panel(&bot).await?,
        "/help" => send_help(&bot).await?,
        "/stats" => send_stats(&bot, &state).await?,
        _ => {
            bot.send_message(ChatId(ADMIN_ID), "Use /panel (or /help).").await?;
        }
    }

    Ok(())
}

async fn handle_callback(bot: Bot, state: AppState, q: CallbackQuery) -> Result<()> {
    let from_id = q.from.id.0 as i64;
    if from_id != ADMIN_ID {
        return Ok(());
    }
    let data = match q.data.clone() {
        Some(d) => d,
        None => return Ok(()),
    };

    bot.answer_callback_query(q.id.clone()).await?;

    let now = now_ts();

    if data == "noop" {
        return Ok(());
    }

    if data == "panel" {
        send_panel_to(&bot, q.message.clone()).await?;
        return Ok(());
    }
    if data == "help" {
        send_help_to(&bot, q.message.clone()).await?;
        return Ok(());
    }
    if data == "stats" {
        send_stats_to(&bot, &state, q.message.clone()).await?;
        return Ok(());
    }

    if data == "groups" {
        let groups = db_call(state.db_path.clone(), move |conn| {
            let mut stmt = conn.prepare(
                "SELECT chat_id, title, enabled, muted_until, notify_only FROM groups ORDER BY title",
            )?;
            let mut rows = stmt.query([])?;
            let now = now_ts();

            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                let chat_id: i64 = r.get(0)?;
                let title: String = r.get(1)?;
                let enabled: i64 = r.get(2)?;
                let muted_until: i64 = r.get(3)?;
                let notify_only: i64 = r.get(4)?;

                let mut badges = Vec::new();
                if enabled != 1 {
                    badges.push("OFF");
                }
                if muted_until > now {
                    badges.push("MUTED");
                }
                if notify_only == 1 {
                    badges.push("NOPOST");
                }

                let label = if badges.is_empty() {
                    title
                } else {
                    format!("{} [{}]", title, badges.join(","))
                };

                out.push((chat_id, label));
            }
            Ok(out)
        })
        .await?;

        if groups.is_empty() {
            bot.send_message(ChatId(ADMIN_ID), "📋 Known groups: none yet.")
                .await?;
            return Ok(());
        }

        let mut rows = Vec::new();
        for (chat_id, title) in groups {
            rows.push(vec![InlineKeyboardButton::callback(
                title,
                format!("gset:{}", chat_id),
            )]);
        }
        rows.push(vec![InlineKeyboardButton::callback(
            "⬅️ Back",
            "panel".to_string(),
        )]);

        send_or_edit_admin_message(
            &bot,
            q.message.clone(),
            "📋 Known groups: tap one to open settings.".to_string(),
            Some(InlineKeyboardMarkup::new(rows)),
        )
        .await?;
        return Ok(());
    }

    if data == "pending_count" {
        let pending = db_call(state.db_path.clone(), move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, chat_title, from_name FROM pending ORDER BY created_at DESC",
            )?;
            let mut rows = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                let id: String = r.get(0)?;
                let title: String = r.get(1)?;
                let from: Option<String> = r.get(2)?;
                out.push((id, title, from.unwrap_or_else(|| "Unknown".to_string())));
            }
            Ok(out)
        })
        .await?;

        if pending.is_empty() {
            let back = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
                "⬅️ Back",
                "panel".to_string(),
            )]]);
            send_or_edit_admin_message(
                &bot,
                q.message.clone(),
                "🧾 Pending approvals: 0".to_string(),
                Some(back),
            )
            .await?;
            return Ok(());
        }

        let mut rows = Vec::new();
        for (id, title, from) in pending {
            let label = shorten_label(&format!("{} - {}", title, from), 50);
            rows.push(vec![InlineKeyboardButton::callback(
                label,
                format!("pending:{}", id),
            )]);
        }
        rows.push(vec![InlineKeyboardButton::callback(
            "⬅️ Back",
            "panel".to_string(),
        )]);

        send_or_edit_admin_message(
            &bot,
            q.message.clone(),
            "🧾 Pending approvals: tap one to view details.".to_string(),
            Some(InlineKeyboardMarkup::new(rows)),
        )
        .await?;
        return Ok(());
    }

    if data == "unmute_expired" {
        db_call(state.db_path.clone(), move |conn| {
            conn.execute("UPDATE groups SET muted_until=0 WHERE muted_until<=?1", params![now])?;
            Ok(())
        })
        .await?;

        bot.send_message(ChatId(ADMIN_ID), "🔔 Cleared expired mutes.")
            .await?;
        return Ok(());
    }

    if data == "clear_pending" {
        db_call(state.db_path.clone(), move |conn| {
            conn.execute("DELETE FROM pending", [])?;
            Ok(())
        })
        .await?;

        bot.send_message(ChatId(ADMIN_ID), "🧹 Cleared all pending approvals.")
            .await?;
        return Ok(());
    }

    // --- Alert actions ---
    if let Some(rest) = data.strip_prefix("pending:") {
        show_pending_details(&bot, &state, rest, q.message.clone()).await?;
        return Ok(());
    }

    if let Some(rest) = data.strip_prefix("post:") {
        let status = post_pending(&bot, &state, rest, None).await?;
        bot.send_message(ChatId(ADMIN_ID), status).await?;
        return Ok(());
    }

    if let Some(rest) = data.strip_prefix("edit:") {
        let pid = rest.to_string();
        let expires = now + 300;

        db_call(state.db_path.clone(), move |conn| {
            conn.execute(
                "INSERT INTO edit_sessions(admin_id, pending_id, expires_at) VALUES(?1, ?2, ?3)
                 ON CONFLICT(admin_id) DO UPDATE SET pending_id=excluded.pending_id, expires_at=excluded.expires_at",
                params![ADMIN_ID, pid, expires],
            )?;
            Ok(())
        })
        .await?;

        bot.send_message(ChatId(ADMIN_ID), "✏️ Send the exact text to post (within 5 minutes).")
            .await?;
        return Ok(());
    }

    if let Some(rest) = data.strip_prefix("ignore:") {
        let pid = rest.to_string();

        let chat_id_opt: Option<i64> = db_call(state.db_path.clone(), move |conn| {
            let cid: Option<i64> = conn
                .query_row("SELECT chat_id FROM pending WHERE id=?1", params![pid], |r| r.get(0))
                .optional()?;
            Ok(cid)
        })
        .await?;

        let pid2 = rest.to_string();
        db_call(state.db_path.clone(), move |conn| {
            conn.execute("DELETE FROM pending WHERE id=?1", params![pid2])?;
            Ok(())
        })
        .await?;

        if let Some(chat_id) = chat_id_opt {
            db_call(state.db_path.clone(), move |conn| {
                bump_group_counter(&conn, chat_id, "ignored_count", 1)?;
                inc_stat(&conn, "ignored_total", 1)?;
                Ok(())
            })
            .await?;
        }

        bot.send_message(ChatId(ADMIN_ID), "🗑 Ignored.").await?;
        return Ok(());
    }

    // --- Group settings entry ---
    if let Some(rest) = data.strip_prefix("gset:") {
        let chat_id: i64 = rest.parse()?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    // --- Button-only group settings actions ---
    // Toggle enabled
    if let Some(rest) = data.strip_prefix("tgen:") {
        let chat_id: i64 = rest.parse()?;
        db_call(state.db_path.clone(), move |conn| {
            let s = get_group_settings(&conn, chat_id)?;
            set_group_enabled(&conn, chat_id, !s.enabled)?;
            Ok(())
        })
        .await?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    // Toggle notify-only
    if let Some(rest) = data.strip_prefix("toggle_notify:") {
        let chat_id: i64 = rest.parse()?;
        db_call(state.db_path.clone(), move |conn| {
            let s = get_group_settings(&conn, chat_id)?;
            set_group_notify_only(&conn, chat_id, !s.notify_only)?;
            Ok(())
        })
        .await?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    // Set random chance: setp:<chat_id>:<p>
    if let Some(rest) = data.strip_prefix("setp:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() == 2 {
            let chat_id: i64 = parts[0].parse()?;
            let p: f32 = parts[1].parse()?;
            // clamp to [0, 1]
            let p = p.clamp(0.0, 1.0);
            db_call(state.db_path.clone(), move |conn| {
                set_group_random_chance(&conn, chat_id, p)?;
                Ok(())
            })
            .await?;
            show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        }
        return Ok(());
    }

    // Set threshold: sett:<chat_id>:<t>
    if let Some(rest) = data.strip_prefix("sett:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() == 2 {
            let chat_id: i64 = parts[0].parse()?;
            let t: f32 = parts[1].parse()?;
            // clamp to sane range
            let t = t.clamp(0.0, 1.0);
            db_call(state.db_path.clone(), move |conn| {
                set_group_threshold(&conn, chat_id, t)?;
                Ok(())
            })
            .await?;
            show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        }
        return Ok(());
    }

    // Mute: mute:<chat_id>:<secs>
    if let Some(rest) = data.strip_prefix("mute:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() == 2 {
            let chat_id: i64 = parts[0].parse()?;
            let secs: i64 = parts[1].parse()?;
            let until = now + secs.max(0);
            db_call(state.db_path.clone(), move |conn| {
                set_group_muted_until(&conn, chat_id, until)?;
                Ok(())
            })
            .await?;
            show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        }
        return Ok(());
    }

    // Clear alert cooldown: clr_alert:<chat_id>
    if let Some(rest) = data.strip_prefix("clr_alert:") {
        let chat_id: i64 = rest.parse()?;
        db_call(state.db_path.clone(), move |conn| {
            update_last_alert_at(&conn, chat_id, 0)?;
            Ok(())
        })
        .await?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    // Clear post cooldown: clr_post:<chat_id>
    if let Some(rest) = data.strip_prefix("clr_post:") {
        let chat_id: i64 = rest.parse()?;
        db_call(state.db_path.clone(), move |conn| {
            update_last_post_at(&conn, chat_id, 0)?;
            Ok(())
        })
        .await?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    // Unmute: unmute:<chat_id>
    if let Some(rest) = data.strip_prefix("unmute:") {
        let chat_id: i64 = rest.parse()?;
        db_call(state.db_path.clone(), move |conn| {
            set_group_muted_until(&conn, chat_id, 0)?;
            Ok(())
        })
        .await?;
        show_group_settings(&bot, &state, chat_id, q.message.clone()).await?;
        return Ok(());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    pretty_env_logger::init();

    let bot_token = env::var("TG_BOT_TOKEN").context("Missing TG_BOT_TOKEN")?;
    let openrouter_key = env::var("OPENROUTER_API_KEY").context("Missing OPENROUTER_API_KEY")?;

    let state = AppState {
        db_path: "bot.sqlite".to_string(),
        http: reqwest::Client::new(),
        openrouter_key,
    };

    init_db(&state.db_path)?;

    let bot = Bot::new(bot_token);

    let handler = dptree::entry()
        .branch(
            Update::filter_message()
                .branch(
                    dptree::filter(|m: Message| m.chat.is_group() || m.chat.is_supergroup())
                        .endpoint(|bot: Bot, state: AppState, msg: Message| async move {
                            if let Err(e) = handle_group_message(bot, state, msg).await {
                                error!("group handler error: {:?}", e);
                            }
                            Ok::<(), anyhow::Error>(())
                        }),
                )
                .branch(
                    dptree::filter(|m: Message| m.chat.is_private())
                        .endpoint(|bot: Bot, state: AppState, msg: Message| async move {
                            if msg.chat.id.0 != ADMIN_ID {
                                return Ok::<(), anyhow::Error>(());
                            }
                            if let Err(e) = handle_admin_dm_text(bot, state, msg).await {
                                error!("admin dm handler error: {:?}", e);
                            }
                            Ok::<(), anyhow::Error>(())
                        }),
                ),
        )
        .branch(
            Update::filter_callback_query()
                .endpoint(|bot: Bot, state: AppState, q: CallbackQuery| async move {
                    if let Err(e) = handle_callback(bot, state, q).await {
                        error!("callback handler error: {:?}", e);
                    }
                    Ok::<(), anyhow::Error>(())
                }),
        );

    info!("Bot started. Admin id: {}", ADMIN_ID);
    info!("Models: classify='{}' draft='{}'", OR_MODEL_CLASSIFY, OR_MODEL_DRAFT);

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    Ok(())
}

// --- rusqlite optional helper ---
trait OptionalRow<T> {
    fn optional(self) -> Result<Option<T>>;
}

impl<T> OptionalRow<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_panel_keyboard_has_core_buttons() {
        let kb = panel_keyboard();
        let labels: Vec<String> = kb
            .inline_keyboard
            .iter()
            .flatten()
            .map(|b| b.text.clone())
            .collect();

        for expected in [
            "📋 List groups",
            "🧾 Pending count",
            "📊 Stats",
            "❓ Help",
            "🔔 Unmute expired",
            "🧹 Clear pending",
        ] {
            assert!(
                labels.iter().any(|label| label == expected),
                "missing button: {}",
                expected
            );
        }
    }

    #[test]
    fn group_settings_keyboard_has_back_and_unmute() {
        let chat_id = 123;
        let s = GroupSettings {
            enabled: true,
            muted_until: 0,
            threshold: 0.72,
            last_alert_at: 0,
            last_post_at: 0,
            random_chance: 0.05,
            notify_only: false,
        };

        let kb = group_settings_keyboard(chat_id, &s);
        let callbacks: Vec<String> = kb
            .inline_keyboard
            .iter()
            .flatten()
            .filter_map(|b| match &b.kind {
                teloxide::types::InlineKeyboardButtonKind::CallbackData(data) => Some(data.clone()),
                _ => None,
            })
            .collect();

        assert!(callbacks.iter().any(|c| c == "panel"));
        let unmute = format!("unmute:{}", chat_id);
        assert!(callbacks.iter().any(|c| c == &unmute));
    }
}
