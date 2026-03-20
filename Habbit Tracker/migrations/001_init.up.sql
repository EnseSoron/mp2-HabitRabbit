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
    passw_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- HABITS DICTIONARY
CREATE TABLE habits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    habit_name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- USER HABITS (user config)
CREATE TABLE user_habits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    habit_id UUID NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    frequency_type TEXT NOT NULL DEFAULT 'daily',
    schedule_type TEXT NOT NULL DEFAULT 'daily' 
        CHECK (schedule_type IN ('daily', 'weekly', 'monthly', 'interval', 'custom')),
    schedule_config JSONB,
    schedule_text TEXT,
    
    times_per_week INT CHECK (
        (frequency_type = 'weekly' AND times_per_week IS NOT NULL AND times_per_week BETWEEN 1 AND 7)
        OR (frequency_type != 'weekly' AND times_per_week IS NULL)
    ),
    start_date DATE NOT NULL DEFAULT CURRENT_DATE,
    goal INT DEFAULT 1,

    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- HABIT LOGS (checkins)
CREATE TABLE habit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_habit_id UUID NOT NULL REFERENCES user_habits(id) ON DELETE CASCADE,

    check_date DATE NOT NULL,
    status BOOLEAN NOT NULL DEFAULT true,
    notes TEXT,
    value NUMERIC,

    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- Индексы для ускорения
CREATE UNIQUE INDEX uniq_habit_log_per_day ON habit_logs(user_habit_id, check_date);
CREATE INDEX idx_user_habits_user_id ON user_habits(user_id);
CREATE INDEX idx_user_habits_composite ON user_habits(user_id, created_at DESC);
CREATE INDEX idx_habit_logs_user_habit_id ON habit_logs(user_habit_id);
CREATE INDEX idx_habit_logs_check_date ON habit_logs(check_date);
CREATE INDEX idx_user_pasw_email ON user_pasw(email);

-- Триггер для обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_habits_updated_at BEFORE UPDATE ON user_habits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_habit_logs_updated_at BEFORE UPDATE ON habit_logs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();