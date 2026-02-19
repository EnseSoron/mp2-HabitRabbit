CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nickname TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- USER PASSWORDS (1:1)
CREATE TABLE user_pasw (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    passw_hash TEXT NOT NULL
);

-- HABITS DICTIONARY
CREATE TABLE habits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    habit_name TEXT NOT NULL UNIQUE
);

-- USER HABITS (user config)
CREATE TABLE user_habits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    habit_id UUID NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    frequency_type TEXT NOT NULL,       -- например: daily / weekly
    times_per_week INT,                 -- используется если weekly
    start_date DATE NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- HABIT LOGS (checkins)
CREATE TABLE habit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_habit_id UUID NOT NULL REFERENCES user_habits(id) ON DELETE CASCADE,

    check_date DATE NOT NULL,
    status BOOLEAN NOT NULL DEFAULT true,

    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- 1 отметка на 1 привычку в 1 день
CREATE UNIQUE INDEX uniq_habit_log_per_day
ON habit_logs(user_habit_id, check_date);

-- ускорение выборок
CREATE INDEX idx_user_habits_user_id ON user_habits(user_id);
CREATE INDEX idx_habit_logs_user_habit_id ON habit_logs(user_habit_id);
CREATE INDEX idx_habit_logs_check_date ON habit_logs(check_date);
