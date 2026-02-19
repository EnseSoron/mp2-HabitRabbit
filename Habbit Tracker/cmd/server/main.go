package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // Не показываем в JSON
	CreatedAt time.Time `json:"created_at"`
}

type Habit struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"` // привязываем привычку к пользователю
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
}

// данные в jwt токене
type JWTClaims struct {
	UserID               string `json:"user_id"`
	Username             string `json:"username"`
	jwt.RegisteredClaims        //Стандартные поля JWT (дата выдачи, срок и т.д.)
}

// ЗАПРОСЫ И ОТВЕТЫ
// запрос на регистрацию
type RegisterRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// запрос на вход
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ответ при успешном входе
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// ответ с ошибкой тип если чет не то
type ErrorResponse struct {
	Error string `json:"error"`
}

var (
	db        *sql.DB
	jwtSecret = []byte("nado_sdelat_v_.env")
)

func main() {
	// ENV
	if v := strings.TrimSpace(os.Getenv("JWT_SECRET")); v != "" {
		jwtSecret = []byte(v)
	}

	// DB
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		log.Fatal("DATABASE_URL is required (e.g. postgres://user:pass@localhost:5432/dbname?sslmode=disable)")
	}

	var err error
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("DB open error:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal("DB ping error:", err)
	}

	// Публичные маршруты (без авторизации)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	// Защищенные маршруты (требуют авторизации)
	http.HandleFunc("/me", authMiddleware(handleGetCurrentUser))
	http.HandleFunc("/habits", authMiddleware(handleHabits))
	http.HandleFunc("/habits/", authMiddleware(handleHabits))
	//инфо о сервере
	log.Println(" Доступные endpoint'ы:")
	log.Println("")
	log.Println(" Публичные (без токена):")
	log.Println("   POST /register - Регистрация")
	log.Println("   POST /login    - Вход")
	log.Println("")
	log.Println(" Защищенные (требуют Bearer токен):")
	log.Println("   GET  /me       - Информация о текущем пользователе")
	log.Println("   GET  /habits   - Мои привычки")
	log.Println("   POST /habits   - Создать привычку")
	log.Println("   GET  /habits/{id} - Получить привычку")
	log.Println("   PUT  /habits/{id} - Обновить привычку")
	log.Println("   DELETE /habits/{id} - Удалить привычку")
	log.Println("")
	log.Println("Сервер запущен на http://localhost:8080")
	log.Println("UUID пример: " + uuid.New().String())

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) //хеширование так называемое
	return string(bytes), err
}

// проверяем пароль с хешем
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// генерируем токен
func generateJWT(user User) (string, error) {
	claims := JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Токен на 24 часа
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "habit-tracker-api",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

// verifyJWT проверяет JWT токен и возвращает claims
func verifyJWT(tokenString string) (*JWTClaims, error) {
	// Парсим токен
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	// Извлекаем claims
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}

// проверяем JWT токен и добавляет user_id в контекст
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Извлекаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Authorization header is required"})
			return
		}

		// Формат: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Authorization header format must be: Bearer <token>"})
			return
		}

		tokenString := parts[1]

		// Проверяем токен
		claims, err := verifyJWT(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		// Добавляем user_id в контекст запроса
		// Для простоты используем заголовок
		r.Header.Set("X-User-ID", claims.UserID)

		// Вызываем следующий обработчик
		next(w, r)
	}
}

// извлекает user_id из запроса
func getUserIDFromRequest(r *http.Request) string {
	return r.Header.Get("X-User-ID")
}

// --- DB helpers ---

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "db unreachable"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func dbGetUserByEmail(ctx context.Context, email string) (*User, string, error) {
	// returns user + password hash
	q := `
		SELECT u.id::text, p.email, u.nickname, p.passw_hash, u.created_at
		FROM user_pasw p
		JOIN users u ON u.id = p.user_id
		WHERE lower(p.email) = lower($1)
		LIMIT 1
	`
	var u User
	var passHash string
	if err := db.QueryRowContext(ctx, q, email).Scan(&u.ID, &u.Email, &u.Username, &passHash, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, "", nil
		}
		return nil, "", err
	}
	return &u, passHash, nil
}

func dbGetUserByID(ctx context.Context, id string) (*User, error) {
	q := `
		SELECT u.id::text, p.email, u.nickname, u.created_at
		FROM users u
		JOIN user_pasw p ON p.user_id = u.id
		WHERE u.id = $1
		LIMIT 1
	`
	var u User
	if err := db.QueryRowContext(ctx, q, id).Scan(&u.ID, &u.Email, &u.Username, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// обработчик регистрации
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON format"})
		return
	}

	// Валидация
	req.Email = strings.TrimSpace(req.Email)
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Email, username and password are required"})
		return
	}

	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Password must be at least 6 characters"})
		return
	}

	// Проверяем, не занят ли email
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	existing, _, err := dbGetUserByEmail(ctx, req.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	if existing != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Email already registered"})
		return
	}

	// Хешируем пароль
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	// Создаем пользователя (users + user_pasw) транзакцией
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	defer tx.Rollback()

	var user User
	user.Email = req.Email
	user.Username = req.Username

	qUser := `INSERT INTO users (nickname) VALUES ($1) RETURNING id::text, created_at`
	if err := tx.QueryRowContext(ctx, qUser, req.Username).Scan(&user.ID, &user.CreatedAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	qPass := `INSERT INTO user_pasw (user_id, email, passw_hash) VALUES ($1, $2, $3)`
	if _, err := tx.ExecContext(ctx, qPass, user.ID, req.Email, hashedPassword); err != nil {
		// скорее всего UNIQUE по email
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Email already registered"})
		return
	}
	if err := tx.Commit(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	// Генерируем JWT токен
	token, err := generateJWT(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	// Отправляем ответ
	response := LoginResponse{Token: token, User: user}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleLogin - вход пользователя
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON format"})
		return
	}

	// Валидация
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Email and password are required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	user, passHash, err := dbGetUserByEmail(ctx, req.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid email or password"})
		return
	}

	// Проверяем пароль
	if !checkPasswordHash(req.Password, passHash) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid email or password"})
		return
	}

	// Генерируем JWT токен
	token, err := generateJWT(*user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	// Отправляем ответ
	response := LoginResponse{
		Token: token,
		User:  *user,
	}

	json.NewEncoder(w).Encode(response)
}

// инфо о текущем пользователе
func handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	userID := getUserIDFromRequest(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	currentUser, err := dbGetUserByID(ctx, userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	if currentUser == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "User not found"})
		return
	}

	json.NewEncoder(w).Encode(currentUser)
}

// добавить привычки/получить инфо о привычках
func handleHabits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID := getUserIDFromRequest(r)
	if userID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Authentication required"})
		return
	}

	//проверяем метод
	switch r.Method {
	case "GET":
		handleGetHabits(w, r, userID)

	case "POST":
		handlePostHabit(w, r, userID)

	default:
		// Если метод не GET и не POST
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed. Use GET or POST",
		})
	}
}

func handleGetHabits(w http.ResponseWriter, r *http.Request, userID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	q := `
		SELECT uh.id::text, uh.user_id::text, h.habit_name, uh.created_at
		FROM user_habits uh
		JOIN habits h ON h.id = uh.habit_id
		WHERE uh.user_id = $1
		ORDER BY uh.created_at DESC
	`
	rows, err := db.QueryContext(ctx, q, userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	defer rows.Close()

	userHabits := make([]Habit, 0)
	for rows.Next() {
		var h Habit
		if err := rows.Scan(&h.ID, &h.UserID, &h.Title, &h.CreatedAt); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		userHabits = append(userHabits, h)
	}
	json.NewEncoder(w).Encode(userHabits)
}

// handlePostHabit - создаем привычку для текущего пользователя
func handlePostHabit(w http.ResponseWriter, r *http.Request, userID string) {
	type HabitRequest struct {
		Title string `json:"title"`
	}

	var req HabitRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid JSON format",
		})
		return
	}

	// Валидация: проверяем обязательные поля
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Title is required",
		})
		return
	}

	if len(req.Title) > 100 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Title too long (max 100 characters)",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	defer tx.Rollback()

	// 1) ensure habit exists in dictionary
	var habitDictID string
	qInsHabit := `
		INSERT INTO habits (habit_name)
		VALUES ($1)
		ON CONFLICT (habit_name) DO UPDATE SET habit_name = EXCLUDED.habit_name
		RETURNING id::text
	`
	if err := tx.QueryRowContext(ctx, qInsHabit, req.Title).Scan(&habitDictID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	// 2) link to user
	var habit Habit
	qUserHabit := `
		INSERT INTO user_habits (habit_id, user_id, frequency_type, times_per_week, start_date)
		VALUES ($1, $2, 'daily', NULL, CURRENT_DATE)
		RETURNING id::text, created_at
	`
	if err := tx.QueryRowContext(ctx, qUserHabit, habitDictID, userID).Scan(&habit.ID, &habit.CreatedAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	if err := tx.Commit(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	habit.UserID = userID
	habit.Title = req.Title

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(habit)
}

func handleHabit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID := getUserIDFromRequest(r)
	if userID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Authentication required"})
		return
	}

	habitID := extractHabitID(r.URL.Path)

	if habitID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Habit ID is required in URL",
		})
		return
	}

	// проверяем корректность uuid
	if _, err := uuid.Parse(habitID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid UUID format",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// читаем привычку из БД и получаем habit_id (из справочника)
	qGet := `
		SELECT uh.id::text, uh.user_id::text, h.habit_name, uh.created_at, uh.habit_id::text
		FROM user_habits uh
		JOIN habits h ON h.id = uh.habit_id
		WHERE uh.id = $1 AND uh.user_id = $2
		LIMIT 1
	`
	var habit Habit
	var habitDictID string
	if err := db.QueryRowContext(ctx, qGet, habitID, userID).Scan(&habit.ID, &habit.UserID, &habit.Title, &habit.CreatedAt, &habitDictID); err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Habit not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(&habit)
		return

	case "PUT", "PATCH":
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"})
			return
		}

		// Для простоты: и PUT и PATCH принимают {"title":"..."}
		var body struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
			return
		}
		body.Title = strings.TrimSpace(body.Title)
		if body.Title == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Title is required"})
			return
		}
		if len(body.Title) > 100 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Title too long (max 100 characters)"})
			return
		}

		qUpd := `UPDATE habits SET habit_name = $1 WHERE id = $2`
		if _, err := db.ExecContext(ctx, qUpd, body.Title, habitDictID); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Habit name already exists"})
			return
		}
		habit.Title = body.Title
		json.NewEncoder(w).Encode(&habit)
		return

	case "DELETE":
		qDel := `DELETE FROM user_habits WHERE id = $1 AND user_id = $2`
		res, err := db.ExecContext(ctx, qDel, habitID, userID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		aff, _ := res.RowsAffected()
		if aff == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Habit not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use GET, PUT, PATCH or DELETE"})
		return
	}
}

// extractHabitID извлекает ID из URL пути
func extractHabitID(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}
