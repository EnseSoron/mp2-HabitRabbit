package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/swaggo/files"
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"

	_ "habit-tracker/docs"
)

// @title Habit Tracker API
// @version 1.0.0
// @description API для мобильного приложения трекера привычек
// @description Позволяет управлять пользователями, привычками и отслеживать их выполнение

// @contact.name Разработчик
// @contact.email support@habittracker.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Для доступа к защищенным эндпоинтам необходимо добавить заголовок: Authorization: Bearer {ваш-jwt-токен}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // Не показываем в JSON
	CreatedAt time.Time `json:"created_at"`
}

type HabitAchievement struct {
	ID          string    `json:"id"`
	Code        string    `json:"code"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	RuleType    string    `json:"rule_type,omitempty"`
	RuleValue   int       `json:"rule_value,omitempty"`
	EarnedAt    time.Time `json:"earned_at"`
}

type CheckIn struct {
	ID        string     `json:"id"`
	CheckDate string     `json:"check_date"`
	Status    bool       `json:"status"`
	Notes     string     `json:"notes,omitempty"`
	Value     *float64   `json:"value,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type Habit struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	ScheduleType string          `json:"schedule_type"`
	Schedule     json.RawMessage `json:"schedule,omitempty" swaggertype:"object"`
	ScheduleText string          `json:"schedule_text,omitempty"`

	CurrentStreak     int                `json:"current_streak"`
	BestStreak        int                `json:"best_streak"`
	CompletedCount    int                `json:"completed_count"`
	LastCompletedDate string             `json:"last_completed_date,omitempty"`
	Achievements      []HabitAchievement `json:"achievements,omitempty"`

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

type CreateHabitRequest struct {
	Title        string          `json:"title" binding:"required"`
	Description  string          `json:"description"`
	ScheduleType string          `json:"schedule_type"` // daily, weekly, monthly, interval, custom
	Schedule     json.RawMessage `json:"schedule,omitempty"`
}

type CheckInRequest struct {
	CheckDate string   `json:"check_date"`
	Status    *bool    `json:"status"`
	Notes     string   `json:"notes"`
	Value     *float64 `json:"value"`
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
	http.HandleFunc("/habits/", authMiddleware(handleHabit))
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)
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

// handleHealth проверка работоспособности сервера
// @Summary Проверка здоровья
// @Description Проверяет, работает ли сервер и доступна ли база данных
// @Tags system
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "статус сервера"
// @Failure 503 {object} ErrorResponse "База данных недоступна"
// @Router /health [get]
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

// RegisterUser обрабатывает регистрацию нового пользователя
// @Summary Регистрация нового пользователя
// @Description Создает нового пользователя в системе. Email должен быть уникальным.
// @Description Пароль должен быть минимум 6 символов.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Данные пользователя"
// @Success 201 {object} LoginResponse "Пользователь успешно создан, возвращается токен"
// @Failure 400 {object} ErrorResponse "Неверный формат JSON или невалидные данные"
// @Failure 409 {object} ErrorResponse "Email уже зарегистрирован"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /register [post]
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

// LoginUser авторизует пользователя
// @Summary Вход в систему
// @Description Аутентификация пользователя по email и паролю
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Учетные данные"
// @Success 200 {object} LoginResponse "Успешный вход, возвращается JWT токен"
// @Failure 400 {object} ErrorResponse "Неверный формат запроса"
// @Failure 401 {object} ErrorResponse "Неверный email или пароль"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /login [post]
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

// GetCurrentUser возвращает информацию о текущем пользователе
// @Summary Получить информацию о себе
// @Description Возвращает данные авторизованного пользователя
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} User "Информация о пользователе"
// @Failure 401 {object} ErrorResponse "Не авторизован или неверный токен"
// @Failure 404 {object} ErrorResponse "Пользователь не найден"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /me [get]
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

//Валидация расписания

func validateSchedule(req CreateHabitRequest) error {
	// Если schedule пустой, но тип требует конфигурации
	if len(req.Schedule) == 0 {
		if req.ScheduleType != "daily" && req.ScheduleType != "" {
			return fmt.Errorf("schedule config required for %s type", req.ScheduleType)
		}
		return nil
	}

	// Парсим в структуру для проверки
	var config struct {
		Days  []int    `json:"days"`
		Every int      `json:"every"`
		Dates []string `json:"dates"`
	}

	if err := json.Unmarshal(req.Schedule, &config); err != nil {
		return fmt.Errorf("invalid schedule format: %v", err)
	}

	switch req.ScheduleType {
	case "daily", "":
		// нет доп параметров
		return nil

	case "weekly":
		if len(config.Days) == 0 {
			return fmt.Errorf("weekly schedule requires days array")
		}
		for _, day := range config.Days {
			if day < 1 || day > 7 {
				return fmt.Errorf("days must be 1-7 (1=Monday, 7=Sunday), got %d", day)
			}
		}
		return nil

	case "monthly":
		if len(config.Days) == 0 {
			return fmt.Errorf("monthly schedule requires days array")
		}
		for _, day := range config.Days {
			if day < 1 || day > 31 {
				return fmt.Errorf("days must be 1-31, got %d", day)
			}
		}
		return nil

	case "interval":
		if config.Every < 1 {
			return fmt.Errorf("interval must be positive, got %d", config.Every)
		}
		return nil

	case "custom":
		if len(config.Dates) == 0 {
			return fmt.Errorf("custom schedule requires dates array")
		}
		for _, date := range config.Dates {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return fmt.Errorf("dates must be in YYYY-MM-DD format: %s", date)
			}
		}
		return nil

	default:
		return fmt.Errorf("invalid schedule type: %s", req.ScheduleType)
	}
}

// текст для ScheduleText
func generateScheduleText(req CreateHabitRequest) string {
	if len(req.Schedule) == 0 {
		return "Каждый день"
	}

	var config struct {
		Days  []int    `json:"days"`
		Every int      `json:"every"`
		Dates []string `json:"dates"`
	}

	// Игнорируем ошибку, если не удалось распарсить - вернем "По расписанию"
	if err := json.Unmarshal(req.Schedule, &config); err != nil {
		return "По расписанию"
	}

	switch req.ScheduleType {
	case "daily", "":
		return "Каждый день"
	case "weekly":
		days := []string{}
		dayNames := []string{"Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"}
		for _, d := range config.Days {
			if d >= 1 && d <= 7 {
				days = append(days, dayNames[d-1])
			}
		}
		if len(days) == 0 {
			return "По неделям"
		}
		return strings.Join(days, ", ")
	case "monthly":
		days := []string{}
		for _, d := range config.Days {
			days = append(days, fmt.Sprintf("%d число", d))
		}
		return strings.Join(days, ", ")
	case "interval":
		return fmt.Sprintf("Каждые %d дня(ей)", config.Every)
	case "custom":
		return fmt.Sprintf("%d дат(ы)", len(config.Dates))
	default:
		return "Неизвестно"
	}
}

// handleHabits обрабатывает запросы к коллекции привычек
// @Summary Управление привычками
// @Description Обрабатывает GET и POST запросы для привычек пользователя
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} Habit "Список привычек (для GET)"
// @Success 201 {object} Habit "Созданная привычка (для POST)"
// @Failure 400 {object} ErrorResponse "Неверный запрос"
// @Failure 401 {object} ErrorResponse "Не авторизован"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /habits [get]
// @Router /habits [post]
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

// GetUserHabits возвращает все привычки текущего пользователя
// @Summary Получить список привычек
// @Description Возвращает массив всех привычек авторизованного пользователя
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} Habit "Список привычек пользователя"
// @Failure 401 {object} ErrorResponse "Не авторизован"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /habits [get]
func handleGetHabits(w http.ResponseWriter, r *http.Request, userID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	q := `
		SELECT 
			uh.id::text, 
			uh.user_id::text, 
			h.habit_name, 
			h.description,
			COALESCE(uh.schedule_type, 'daily') as schedule_type,
			uh.schedule_config,
			uh.schedule_text,
			COALESCE(uh.current_streak, 0),
			COALESCE(uh.best_streak, 0),
			COALESCE(uh.completed_count, 0),
			uh.last_completed_date,
			uh.created_at
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
		var desc sql.NullString
		var scheduleConfig []byte
		var scheduleText sql.NullString
		var lastCompleted sql.NullTime

		if err := rows.Scan(
			&h.ID, &h.UserID, &h.Title, &desc,
			&h.ScheduleType, &scheduleConfig, &scheduleText,
			&h.CurrentStreak, &h.BestStreak, &h.CompletedCount, &lastCompleted,
			&h.CreatedAt,
		); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}

		if desc.Valid {
			h.Description = desc.String
		}
		if scheduleText.Valid {
			h.ScheduleText = scheduleText.String
		}
		if scheduleConfig != nil {
			h.Schedule = json.RawMessage(scheduleConfig)
		}
		if lastCompleted.Valid {
			h.LastCompletedDate = lastCompleted.Time.Format("2006-01-02")
		}

		achievements, err := getHabitAchievements(ctx, h.ID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		h.Achievements = achievements

		userHabits = append(userHabits, h)
	}
	json.NewEncoder(w).Encode(userHabits)
}

// CreateHabit создает новую привычку
// @Summary Создать привычку
// @Description Создает новую привычку для текущего пользователя
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateHabitRequest true "Данные привычки"
// @Success 201 {object} Habit "Созданная привычка"
// @Failure 400 {object} ErrorResponse "Неверный формат запроса или невалидные данные"
// @Failure 401 {object} ErrorResponse "Не авторизован"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /habits [post]
func handlePostHabit(w http.ResponseWriter, r *http.Request, userID string) {
	var req CreateHabitRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
		return
	}

	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Title is required"})
		return
	}
	if req.ScheduleType == "" {
		req.ScheduleType = "daily"
	}
	validTypes := map[string]bool{"daily": true, "weekly": true, "monthly": true, "interval": true, "custom": true}
	if !validTypes[req.ScheduleType] {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid schedule type"})
		return
	}
	if err := validateSchedule(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}
	if len(req.Title) > 100 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Title too long (max 100 characters)"})
		return
	}
	if len(req.Description) > 1000 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Description too long (max 1000 characters)"})
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
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var habitDictID string
	qInsHabit := `
		INSERT INTO habits (habit_name, description)
		VALUES ($1, $2)
		ON CONFLICT (habit_name) DO UPDATE 
		SET description = EXCLUDED.description
		RETURNING id::text
	`
	if err := tx.QueryRowContext(ctx, qInsHabit, req.Title, req.Description).Scan(&habitDictID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	scheduleText := generateScheduleText(req)
	var habit Habit
	qUserHabit := `
		INSERT INTO user_habits (
			habit_id, user_id, frequency_type, 
			schedule_type, schedule_config, schedule_text, start_date
		)
		VALUES ($1, $2, 'daily', $3, $4, $5, CURRENT_DATE)
		RETURNING id::text, created_at
	`
	var scheduleJSON interface{}
	if len(req.Schedule) > 0 {
		scheduleJSON = req.Schedule
	}
	if err := tx.QueryRowContext(ctx, qUserHabit, habitDictID, userID, req.ScheduleType, scheduleJSON, scheduleText).Scan(&habit.ID, &habit.CreatedAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	var habitCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_habits WHERE user_id = $1`, userID).Scan(&habitCount); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	if habitCount == 1 {
		if err := awardAchievementByCodeTx(ctx, tx, habit.ID, "first_habit"); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to commit transaction"})
		return
	}
	committed = true

	habit.UserID = userID
	habit.Title = req.Title
	habit.Description = req.Description
	habit.ScheduleType = req.ScheduleType
	habit.Schedule = req.Schedule
	habit.ScheduleText = scheduleText

	achievements, err := getHabitAchievements(ctx, habit.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	habit.Achievements = achievements

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(habit)
}

// handleHabit обрабатывает запросы к конкретной привычке
// @Summary Управление конкретной привычкой
// @Description Получение, обновление или удаление привычки по ID
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "ID привычки (UUID)"
// @Param body body object true "Данные для обновления привычки"
// @Success 200 {object} Habit "Информация о привычке (для GET)"
// @Success 204 "Привычка успешно удалена (для DELETE)"
// @Failure 400 {object} ErrorResponse "Неверный формат ID"
// @Failure 401 {object} ErrorResponse "Не авторизован"
// @Failure 403 {object} ErrorResponse "Нет доступа к этой привычке"
// @Failure 404 {object} ErrorResponse "Привычка не найдена"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка сервера"
// @Router /habits/{id} [get]
// @Router /habits/{id} [put]
// @Router /habits/{id} [patch]
// @Router /habits/{id} [delete]
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
		json.NewEncoder(w).Encode(map[string]string{"error": "Habit ID is required in URL"})
		return
	}
	if _, err := uuid.Parse(habitID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid UUID format"})
		return
	}

	subresource := extractHabitSubresource(r.URL.Path)
	if subresource == "checkins" {
		handleHabitCheckins(w, r, userID, habitID)
		return
	}
	if subresource == "achievements" {
		handleHabitAchievements(w, r, userID, habitID)
		return
	}
	if subresource != "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Unknown endpoint"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	habit, habitDictID, err := loadOwnedHabit(ctx, userID, habitID)
	if err != nil {
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
		json.NewEncoder(w).Encode(habit)
		return

	case "PUT", "PATCH":
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"})
			return
		}

		var body struct {
			Title        string          `json:"title"`
			Description  string          `json:"description"`
			ScheduleType string          `json:"schedule_type"`
			Schedule     json.RawMessage `json:"schedule"`
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
		if len(body.Description) > 1000 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Description too long (max 1000 characters)"})
			return
		}

		qUpd := `UPDATE habits SET habit_name = $1, description = $2 WHERE id = $3`
		if _, err := db.ExecContext(ctx, qUpd, body.Title, body.Description, habitDictID); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Habit name already exists"})
			return
		}

		if body.ScheduleType != "" || len(body.Schedule) > 0 {
			scheduleType := body.ScheduleType
			if scheduleType == "" {
				scheduleType = habit.ScheduleType
			}
			schedulePayload := body.Schedule
			if len(schedulePayload) == 0 {
				schedulePayload = habit.Schedule
			}
			tmpReq := CreateHabitRequest{ScheduleType: scheduleType, Schedule: schedulePayload}
			if err := validateSchedule(tmpReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
				return
			}
			scheduleText := generateScheduleText(tmpReq)
			if _, err := db.ExecContext(ctx, `UPDATE user_habits SET schedule_type = $1, schedule_config = $2, schedule_text = $3 WHERE id = $4`, scheduleType, schedulePayload, scheduleText, habitID); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
				return
			}
			if err := recalculateHabitProgress(ctx, habitID); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
				return
			}
		}

		updatedHabit, _, err := loadOwnedHabit(ctx, userID, habitID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		updatedHabit.Title = body.Title
		updatedHabit.Description = body.Description
		json.NewEncoder(w).Encode(updatedHabit)
		return

	case "DELETE":
		res, err := db.ExecContext(ctx, `DELETE FROM user_habits WHERE id = $1 AND user_id = $2`, habitID, userID)
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

func extractHabitSubresource(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

type habitScheduleConfig struct {
	Days  []int    `json:"days"`
	Every int      `json:"every"`
	Dates []string `json:"dates"`
}

type habitProgressMeta struct {
	ScheduleType string
	ScheduleRaw  []byte
	StartDate    time.Time
}

func recalculateHabitProgress(ctx context.Context, userHabitID string) error {
	meta, err := getHabitProgressMeta(ctx, userHabitID)
	if err != nil {
		return err
	}

	completedDates, completedCount, lastCompletedDate, err := getCompletedDatesMap(ctx, userHabitID)
	if err != nil {
		return err
	}

	currentStreak, bestStreak, err := calculateStreakBySchedule(meta, completedDates)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
		UPDATE user_habits
		SET current_streak = $1,
			best_streak = $2,
			completed_count = $3,
			last_completed_date = $4,
			updated_at = now()
		WHERE id = $5
	`, currentStreak, bestStreak, completedCount, lastCompletedDate, userHabitID)
	return err
}

func getHabitProgressMeta(ctx context.Context, userHabitID string) (*habitProgressMeta, error) {
	q := `
		SELECT COALESCE(schedule_type, 'daily'), schedule_config, start_date
		FROM user_habits
		WHERE id = $1
		LIMIT 1
	`

	var meta habitProgressMeta
	var raw []byte
	if err := db.QueryRowContext(ctx, q, userHabitID).Scan(&meta.ScheduleType, &raw, &meta.StartDate); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("habit not found")
		}
		return nil, err
	}
	meta.ScheduleRaw = raw
	return &meta, nil
}

func getCompletedDatesMap(ctx context.Context, userHabitID string) (map[string]bool, int, interface{}, error) {
	q := `
		SELECT check_date
		FROM habit_logs
		WHERE user_habit_id = $1 AND status = true
		ORDER BY check_date ASC
	`

	rows, err := db.QueryContext(ctx, q, userHabitID)
	if err != nil {
		return nil, 0, nil, err
	}
	defer rows.Close()

	completed := make(map[string]bool)
	count := 0
	var lastDate time.Time
	for rows.Next() {
		var d time.Time
		if err := rows.Scan(&d); err != nil {
			return nil, 0, nil, err
		}
		d = normalizeDate(d)
		completed[d.Format("2006-01-02")] = true
		count++
		lastDate = d
	}
	if err := rows.Err(); err != nil {
		return nil, 0, nil, err
	}
	if count == 0 {
		return completed, 0, nil, nil
	}
	return completed, count, lastDate, nil
}

func calculateStreakBySchedule(meta *habitProgressMeta, completed map[string]bool) (int, int, error) {
	horizon := getProgressHorizon(meta.StartDate, completed)
	switch meta.ScheduleType {
	case "", "daily", "interval":
		return calculateDailyStreak(meta.StartDate, horizon, completed), calculateBestDailyStreak(meta.StartDate, horizon, completed), nil
	case "weekly":
		cfg, err := parseHabitScheduleConfig(meta.ScheduleRaw)
		if err != nil {
			return 0, 0, err
		}
		return calculateWeeklyStreak(meta.StartDate, horizon, completed, cfg.Days), calculateBestWeeklyStreak(meta.StartDate, horizon, completed, cfg.Days), nil
	case "monthly":
		cfg, err := parseHabitScheduleConfig(meta.ScheduleRaw)
		if err != nil {
			return 0, 0, err
		}
		return calculateMonthlyStreak(meta.StartDate, horizon, completed, cfg.Days), calculateBestMonthlyStreak(meta.StartDate, horizon, completed, cfg.Days), nil
	case "custom":
		cfg, err := parseHabitScheduleConfig(meta.ScheduleRaw)
		if err != nil {
			return 0, 0, err
		}
		return calculateCustomStreak(horizon, completed, cfg.Dates), calculateBestCustomStreak(horizon, completed, cfg.Dates), nil
	default:
		return 0, 0, fmt.Errorf("unsupported schedule type: %s", meta.ScheduleType)
	}
}

func parseHabitScheduleConfig(raw []byte) (*habitScheduleConfig, error) {
	if len(raw) == 0 {
		return &habitScheduleConfig{}, nil
	}
	var cfg habitScheduleConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid schedule config: %w", err)
	}
	return &cfg, nil
}

func calculateDailyStreak(startDate, horizon time.Time, completed map[string]bool) int {
	if len(completed) == 0 {
		return 0
	}
	cursor, ok := getLastCompletedOnOrBefore(horizon, completed)
	if !ok {
		return 0
	}
	start := normalizeDate(startDate)
	if cursor.Before(start) {
		return 0
	}
	streak := 0
	for !cursor.Before(start) {
		if !completed[cursor.Format("2006-01-02")] {
			break
		}
		streak++
		cursor = cursor.AddDate(0, 0, -1)
	}
	return streak
}

func calculateBestDailyStreak(startDate, today time.Time, completed map[string]bool) int {
	best, current := 0, 0
	for d := normalizeDate(startDate); !d.After(today); d = d.AddDate(0, 0, 1) {
		if completed[d.Format("2006-01-02")] {
			current++
			if current > best {
				best = current
			}
		} else {
			current = 0
		}
	}
	return best
}

func calculateWeeklyStreak(startDate, today time.Time, completed map[string]bool, days []int) int {
	expected := buildWeeklyExpectedDates(startDate, today, days)
	return calculateCurrentExpectedStreak(expected, completed)
}

func calculateBestWeeklyStreak(startDate, today time.Time, completed map[string]bool, days []int) int {
	expected := buildWeeklyExpectedDates(startDate, today, days)
	return calculateBestExpectedStreak(expected, completed)
}

func calculateMonthlyStreak(startDate, today time.Time, completed map[string]bool, days []int) int {
	expected := buildMonthlyExpectedDates(startDate, today, days)
	return calculateCurrentExpectedStreak(expected, completed)
}

func calculateBestMonthlyStreak(startDate, today time.Time, completed map[string]bool, days []int) int {
	expected := buildMonthlyExpectedDates(startDate, today, days)
	return calculateBestExpectedStreak(expected, completed)
}

func calculateCustomStreak(today time.Time, completed map[string]bool, dates []string) int {
	expected := buildCustomExpectedDates(today, dates)
	return calculateCurrentExpectedStreak(expected, completed)
}

func calculateBestCustomStreak(today time.Time, completed map[string]bool, dates []string) int {
	expected := buildCustomExpectedDates(today, dates)
	return calculateBestExpectedStreak(expected, completed)
}

func buildWeeklyExpectedDates(startDate, today time.Time, days []int) []time.Time {
	allowed := make(map[int]bool)
	for _, d := range days {
		if d >= 1 && d <= 7 {
			allowed[d] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	var expected []time.Time
	for d := normalizeDate(startDate); !d.After(today); d = d.AddDate(0, 0, 1) {
		wd := int(goWeekdayToISO(d.Weekday()))
		if allowed[wd] {
			expected = append(expected, d)
		}
	}
	return expected
}

func buildMonthlyExpectedDates(startDate, today time.Time, days []int) []time.Time {
	allowed := make(map[int]bool)
	for _, d := range days {
		if d >= 1 && d <= 31 {
			allowed[d] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	var expected []time.Time
	for d := normalizeDate(startDate); !d.After(today); d = d.AddDate(0, 0, 1) {
		if allowed[d.Day()] {
			expected = append(expected, d)
		}
	}
	return expected
}

func buildCustomExpectedDates(horizon time.Time, dates []string) []time.Time {
	var expected []time.Time
	seen := make(map[string]bool)
	for _, raw := range dates {
		d, err := time.Parse("2006-01-02", raw)
		if err != nil {
			continue
		}
		d = normalizeDate(d)
		if d.After(horizon) {
			continue
		}
		key := d.Format("2006-01-02")
		if seen[key] {
			continue
		}
		seen[key] = true
		expected = append(expected, d)
	}
	for i := 0; i < len(expected); i++ {
		for j := i + 1; j < len(expected); j++ {
			if expected[j].Before(expected[i]) {
				expected[i], expected[j] = expected[j], expected[i]
			}
		}
	}
	return expected
}

func calculateCurrentExpectedStreak(expected []time.Time, completed map[string]bool) int {
	if len(expected) == 0 {
		return 0
	}
	lastIdx := len(expected) - 1
	for lastIdx >= 0 && !completed[expected[lastIdx].Format("2006-01-02")] {
		lastIdx--
	}
	if lastIdx < 0 {
		return 0
	}
	streak := 0
	for i := lastIdx; i >= 0; i-- {
		if !completed[expected[i].Format("2006-01-02")] {
			break
		}
		streak++
	}
	return streak
}

func calculateBestExpectedStreak(expected []time.Time, completed map[string]bool) int {
	best, current := 0, 0
	for _, d := range expected {
		if completed[d.Format("2006-01-02")] {
			current++
			if current > best {
				best = current
			}
		} else {
			current = 0
		}
	}
	return best
}
func getProgressHorizon(startDate time.Time, completed map[string]bool) time.Time {
	horizon := normalizeDate(time.Now())
	if horizon.Before(normalizeDate(startDate)) {
		horizon = normalizeDate(startDate)
	}
	for raw := range completed {
		d, err := time.Parse("2006-01-02", raw)
		if err != nil {
			continue
		}
		d = normalizeDate(d)
		if d.After(horizon) {
			horizon = d
		}
	}
	return horizon
}

func getLastCompletedOnOrBefore(horizon time.Time, completed map[string]bool) (time.Time, bool) {
	var last time.Time
	found := false
	for raw := range completed {
		d, err := time.Parse("2006-01-02", raw)
		if err != nil {
			continue
		}
		d = normalizeDate(d)
		if d.After(horizon) {
			continue
		}
		if !found || d.After(last) {
			last = d
			found = true
		}
	}
	return last, found
}

func normalizeDate(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func goWeekdayToISO(w time.Weekday) int {
	if w == time.Sunday {
		return 7
	}
	return int(w)
}

func loadOwnedHabit(ctx context.Context, userID, habitID string) (*Habit, string, error) {
	qGet := `
		SELECT 
			uh.id::text, 
			uh.user_id::text, 
			h.habit_name,
			h.description,
			COALESCE(uh.schedule_type, 'daily') as schedule_type,
			uh.schedule_config,
			uh.schedule_text,
			COALESCE(uh.current_streak, 0),
			COALESCE(uh.best_streak, 0),
			COALESCE(uh.completed_count, 0),
			uh.last_completed_date,
			uh.created_at,
			uh.habit_id::text
		FROM user_habits uh
		JOIN habits h ON h.id = uh.habit_id
		WHERE uh.id = $1 AND uh.user_id = $2
		LIMIT 1
	`
	var habit Habit
	var desc sql.NullString
	var scheduleConfig []byte
	var scheduleText sql.NullString
	var lastCompleted sql.NullTime
	var habitDictID string
	if err := db.QueryRowContext(ctx, qGet, habitID, userID).Scan(
		&habit.ID, &habit.UserID, &habit.Title, &desc,
		&habit.ScheduleType, &scheduleConfig, &scheduleText,
		&habit.CurrentStreak, &habit.BestStreak, &habit.CompletedCount, &lastCompleted,
		&habit.CreatedAt, &habitDictID,
	); err != nil {
		return nil, "", err
	}
	if desc.Valid {
		habit.Description = desc.String
	}
	if scheduleText.Valid {
		habit.ScheduleText = scheduleText.String
	}
	if scheduleConfig != nil {
		habit.Schedule = json.RawMessage(scheduleConfig)
	}
	if lastCompleted.Valid {
		habit.LastCompletedDate = lastCompleted.Time.Format("2006-01-02")
	}
	achievements, err := getHabitAchievements(ctx, habit.ID)
	if err != nil {
		return nil, "", err
	}
	habit.Achievements = achievements
	return &habit, habitDictID, nil
}

// handleHabitCheckins управляет отметками выполнения привычки
// @Summary История и отметки выполнения привычки
// @Description Возвращает историю check-in привычки или добавляет/обновляет отметку выполнения по дате
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "ID привычки (UUID)"
// @Param request body CheckInRequest false "Данные выполнения для POST"
// @Success 200 {array} CheckIn "Список отметок для GET"
// @Success 200 {object} Habit "Обновленная привычка после POST"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /habits/{id}/checkins [get]
// @Router /habits/{id}/checkins [post]
func handleHabitCheckins(w http.ResponseWriter, r *http.Request, userID, habitID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if _, _, err := loadOwnedHabit(ctx, userID, habitID); err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Habit not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.QueryContext(ctx, `
			SELECT id::text, check_date, status, notes, value, created_at, updated_at
			FROM habit_logs
			WHERE user_habit_id = $1
			ORDER BY check_date DESC, created_at DESC
		`, habitID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		defer rows.Close()

		items := make([]CheckIn, 0)
		for rows.Next() {
			var c CheckIn
			var checkDate time.Time
			var notes sql.NullString
			var value sql.NullFloat64
			var updatedAt sql.NullTime
			if err := rows.Scan(&c.ID, &checkDate, &c.Status, &notes, &value, &c.CreatedAt, &updatedAt); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
				return
			}
			c.CheckDate = checkDate.Format("2006-01-02")
			if notes.Valid {
				c.Notes = notes.String
			}
			if value.Valid {
				v := value.Float64
				c.Value = &v
			}
			if updatedAt.Valid {
				tm := updatedAt.Time
				c.UpdatedAt = &tm
			}
			items = append(items, c)
		}
		json.NewEncoder(w).Encode(items)
		return

	case "POST":
		var req CheckInRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON format"})
			return
		}
		checkDate := strings.TrimSpace(req.CheckDate)
		if checkDate == "" {
			checkDate = time.Now().Format("2006-01-02")
		}
		parsedDate, err := time.Parse("2006-01-02", checkDate)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "check_date must be in YYYY-MM-DD format"})
			return
		}
		status := true
		if req.Status != nil {
			status = *req.Status
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()

		var valueArg interface{}
		if req.Value != nil {
			valueArg = *req.Value
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO habit_logs (user_habit_id, check_date, status, notes, value)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (user_habit_id, check_date)
			DO UPDATE SET status = EXCLUDED.status, notes = EXCLUDED.notes, value = EXCLUDED.value, updated_at = now()
		`, habitID, parsedDate, status, strings.TrimSpace(req.Notes), valueArg); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}

		if err := recalculateHabitProgressTx(ctx, tx, habitID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		if err := awardAchievementsForHabitTx(ctx, tx, userID, habitID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		if err := tx.Commit(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to commit transaction"})
			return
		}
		committed = true

		updatedHabit, _, err := loadOwnedHabit(ctx, userID, habitID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
			return
		}
		json.NewEncoder(w).Encode(updatedHabit)
		return

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use GET or POST"})
		return
	}
}

// handleHabitAchievements возвращает достижения привычки
// @Summary Получить достижения привычки
// @Description Возвращает список достижений, полученных по конкретной привычке
// @Tags habits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "ID привычки (UUID)"
// @Success 200 {array} HabitAchievement
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /habits/{id}/achievements [get]
func handleHabitAchievements(w http.ResponseWriter, r *http.Request, userID, habitID string) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use GET"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, _, err := loadOwnedHabit(ctx, userID, habitID); err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Habit not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	achievements, err := getHabitAchievements(ctx, habitID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}
	json.NewEncoder(w).Encode(achievements)
}

func getHabitAchievements(ctx context.Context, userHabitID string) ([]HabitAchievement, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ha.id::text, ad.code, ad.title, ad.description, ad.rule_type, COALESCE(ad.rule_value, 0), ha.earned_at
		FROM habit_achievements ha
		JOIN achievement_definitions ad ON ad.id = ha.achievement_id
		WHERE ha.user_habit_id = $1
		ORDER BY ha.earned_at ASC
	`, userHabitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]HabitAchievement, 0)
	for rows.Next() {
		var a HabitAchievement
		var desc sql.NullString
		if err := rows.Scan(&a.ID, &a.Code, &a.Title, &desc, &a.RuleType, &a.RuleValue, &a.EarnedAt); err != nil {
			return nil, err
		}
		if desc.Valid {
			a.Description = desc.String
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

func awardAchievementByCodeTx(ctx context.Context, tx *sql.Tx, userHabitID, code string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO habit_achievements (user_habit_id, achievement_id)
		SELECT $1, ad.id
		FROM achievement_definitions ad
		WHERE ad.code = $2
		ON CONFLICT (user_habit_id, achievement_id) DO NOTHING
	`, userHabitID, code)
	return err
}

func awardAchievementsForHabitTx(ctx context.Context, tx *sql.Tx, userID, userHabitID string) error {
	var currentStreak, completedCount int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(current_streak,0), COALESCE(completed_count,0) FROM user_habits WHERE id = $1 AND user_id = $2`, userHabitID, userID).Scan(&currentStreak, &completedCount); err != nil {
		return err
	}
	if completedCount >= 1 {
		if err := awardAchievementByCodeTx(ctx, tx, userHabitID, "first_checkin"); err != nil {
			return err
		}
	}
	if currentStreak >= 7 {
		if err := awardAchievementByCodeTx(ctx, tx, userHabitID, "streak_7"); err != nil {
			return err
		}
	}
	if currentStreak >= 30 {
		if err := awardAchievementByCodeTx(ctx, tx, userHabitID, "streak_30"); err != nil {
			return err
		}
	}
	if completedCount >= 10 {
		if err := awardAchievementByCodeTx(ctx, tx, userHabitID, "complete_10"); err != nil {
			return err
		}
	}
	if completedCount >= 50 {
		if err := awardAchievementByCodeTx(ctx, tx, userHabitID, "complete_50"); err != nil {
			return err
		}
	}
	return nil
}

func recalculateHabitProgressTx(ctx context.Context, tx *sql.Tx, userHabitID string) error {
	meta, err := getHabitProgressMetaTx(ctx, tx, userHabitID)
	if err != nil {
		return err
	}
	completedDates, completedCount, lastCompletedDate, err := getCompletedDatesMapTx(ctx, tx, userHabitID)
	if err != nil {
		return err
	}
	currentStreak, bestStreak, err := calculateStreakBySchedule(meta, completedDates)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE user_habits
		SET current_streak = $1,
			best_streak = $2,
			completed_count = $3,
			last_completed_date = $4,
			updated_at = now()
		WHERE id = $5
	`, currentStreak, bestStreak, completedCount, lastCompletedDate, userHabitID)
	return err
}

func getHabitProgressMetaTx(ctx context.Context, tx *sql.Tx, userHabitID string) (*habitProgressMeta, error) {
	var meta habitProgressMeta
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(schedule_type, 'daily'), schedule_config, start_date FROM user_habits WHERE id = $1 LIMIT 1`, userHabitID).Scan(&meta.ScheduleType, &raw, &meta.StartDate); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("habit not found")
		}
		return nil, err
	}
	meta.ScheduleRaw = raw
	return &meta, nil
}

func getCompletedDatesMapTx(ctx context.Context, tx *sql.Tx, userHabitID string) (map[string]bool, int, interface{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT check_date
		FROM habit_logs
		WHERE user_habit_id = $1 AND status = true
		ORDER BY check_date ASC
	`, userHabitID)
	if err != nil {
		return nil, 0, nil, err
	}
	defer rows.Close()
	completed := make(map[string]bool)
	count := 0
	var lastDate time.Time
	for rows.Next() {
		var d time.Time
		if err := rows.Scan(&d); err != nil {
			return nil, 0, nil, err
		}
		d = normalizeDate(d)
		completed[d.Format("2006-01-02")] = true
		count++
		lastDate = d
	}
	if err := rows.Err(); err != nil {
		return nil, 0, nil, err
	}
	if count == 0 {
		return completed, 0, nil, nil
	}
	return completed, count, lastDate, nil
}
