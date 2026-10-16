-- ============================================
-- DepGuard - 扫描任务会话元数据表（M1）
-- 把散落的会话信息（归属用户/状态/结果/用量）收口到一张表
-- ============================================

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,            -- thread_id
    user_id TEXT NOT NULL,
    title TEXT,                     -- 人类可读标题（来自第一句提问）
    repo_url TEXT,
    status TEXT DEFAULT 'pending',  -- pending/running/done/failed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME,
    error TEXT,
    token_usage INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0
);
