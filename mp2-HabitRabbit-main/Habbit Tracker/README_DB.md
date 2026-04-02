# Habit Tracker – подключение к PostgreSQL

## 1) Применить миграции

Если у тебя уже есть база и пользователь, можно прогнать миграцию через `psql`.

### PowerShell пример
```powershell
# строка подключения (пример)
$env:DATABASE_URL = "postgres://USER:PASS@localhost:5432/DBNAME?sslmode=disable"

# прогон миграции
psql "$env:DATABASE_URL" -f .\migrations\001_init.up.sql
```

### CMD пример
```bat
set DATABASE_URL=postgres://USER:PASS@localhost:5432/DBNAME?sslmode=disable
psql "%DATABASE_URL%" -f .\migrations\001_init.up.sql
```

> Если расширение `uuid-ossp` не ставится из-за прав — дай роли права, либо включи расширение от суперпользователя.

## 2) Запуск API

### PowerShell
```powershell
$env:DATABASE_URL = "postgres://USER:PASS@localhost:5432/DBNAME?sslmode=disable"
$env:JWT_SECRET   = "any_secret"

go run .\cmd\server
```

## 3) Проверка

```powershell
curl http://localhost:8080/health

# регистрация
curl -Method POST http://localhost:8080/register -ContentType "application/json" -Body '{"email":"a@a.ru","username":"a","password":"password123"}'

# логин
curl -Method POST http://localhost:8080/login -ContentType "application/json" -Body '{"email":"a@a.ru","password":"password123"}'
```
