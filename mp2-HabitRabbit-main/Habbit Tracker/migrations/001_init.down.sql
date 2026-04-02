-- Удаляем триггеры
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_user_habits_updated_at ON user_habits;
DROP TRIGGER IF EXISTS update_habit_logs_updated_at ON habit_logs;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Удаляем индексы
DROP INDEX IF EXISTS uniq_habit_log_per_day;
DROP INDEX IF EXISTS idx_user_habits_user_id;
DROP INDEX IF EXISTS idx_user_habits_composite;
DROP INDEX IF EXISTS idx_habit_logs_user_habit_id;
DROP INDEX IF EXISTS idx_habit_logs_check_date;
DROP INDEX IF EXISTS idx_user_pasw_email;

-- Удаляем таблицы в правильном порядке (с учетом зависимостей)
DROP TABLE IF EXISTS habit_logs CASCADE;
DROP TABLE IF EXISTS user_habits CASCADE;
DROP TABLE IF EXISTS habits CASCADE;
DROP TABLE IF EXISTS user_pasw CASCADE;
DROP TABLE IF EXISTS users CASCADE;