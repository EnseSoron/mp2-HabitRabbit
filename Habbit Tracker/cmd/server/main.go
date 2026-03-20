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

type Habit struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"` // привязываем привычку к пользователю
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	ScheduleType string          `json:"schedule_type"`                           // daily, weekly, monthly, interval, custom
	Schedule     json.RawMessage `json:"schedule,omitempty" swaggertype:"object"` // конфигурация в JSON
	ScheduleText string          `json:"schedule_text,omitempty"`                 // "Каждый понедельник"

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

		if err := rows.Scan(
			&h.ID, &h.UserID, &h.Title, &desc,
			&h.ScheduleType, &scheduleConfig, &scheduleText, &h.CreatedAt,
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

	if req.ScheduleType == "" {
		req.ScheduleType = "daily"
	}

	// Проверяем schedule_type
	validTypes := map[string]bool{"daily": true, "weekly": true, "monthly": true, "interval": true, "custom": true}
	if !validTypes[req.ScheduleType] {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid schedule type"})
		return
	}

	// Валидация расписания
	if err := validateSchedule(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	if len(req.Title) > 100 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Title too long (max 100 characters)",
		})
		return
	}

	if len(req.Description) > 1000 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Description too long (max 1000 characters)",
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

	// 1. Словарь привычек
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

	// Генерируем текст расписания ДО вставки
	scheduleText := generateScheduleText(req)

	// 2. Связь с пользователем + расписание
	var habit Habit
	qUserHabit := `
    INSERT INTO user_habits (
        habit_id, user_id, frequency_type, 
        schedule_type, schedule_config, schedule_text, start_date
    )
    VALUES ($1, $2, 'daily', $3, $4, $5, CURRENT_DATE)
    RETURNING id::text, created_at
`

	// schedule_config может быть NULL
	var scheduleJSON interface{}
	if len(req.Schedule) > 0 {
		scheduleJSON = req.Schedule
	} else {
		scheduleJSON = nil
	}

	if err := tx.QueryRowContext(ctx, qUserHabit,
		habitDictID, userID, req.ScheduleType, scheduleJSON, scheduleText,
	).Scan(&habit.ID, &habit.CreatedAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
		return
	}

	habit.UserID = userID
	habit.Title = req.Title
	habit.Description = req.Description
	habit.ScheduleType = req.ScheduleType
	habit.Schedule = req.Schedule
	habit.ScheduleText = generateScheduleText(req) // новая функция

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
		SELECT 
			uh.id::text, 
			uh.user_id::text, 
			h.habit_name,
			h.description,
			COALESCE(uh.schedule_type, 'daily') as schedule_type,
			uh.schedule_config,
			uh.schedule_text,
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
	var habitDictID string

	err := db.QueryRowContext(ctx, qGet, habitID, userID).Scan(
		&habit.ID, &habit.UserID, &habit.Title, &desc,
		&habit.ScheduleType, &scheduleConfig, &scheduleText, &habit.CreatedAt,
		&habitDictID,
	)
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

	if desc.Valid {
		habit.Description = desc.String
	}

	if scheduleText.Valid {
		habit.ScheduleText = scheduleText.String
	}

	if scheduleConfig != nil {
		habit.Schedule = json.RawMessage(scheduleConfig)
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

		// Обновляем расписание в user_habits если передано
		if body.ScheduleType != "" || len(body.Schedule) > 0 {
			scheduleType := body.ScheduleType
			if scheduleType == "" {
				scheduleType = habit.ScheduleType
			}

			scheduleText := scheduleType
			if len(body.Schedule) > 0 {
				// Валидация нового расписания
				tmpReq := CreateHabitRequest{
					ScheduleType: scheduleType,
					Schedule:     body.Schedule,
				}
				if err := validateSchedule(tmpReq); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
					return
				}
				scheduleText = generateScheduleText(tmpReq)
			}

			qUpdSchedule := `
				UPDATE user_habits 
				SET schedule_type = $1, schedule_config = $2, schedule_text = $3
				WHERE id = $4
			`
			if _, err := db.ExecContext(ctx, qUpdSchedule,
				scheduleType, body.Schedule, scheduleText, habitID,
			); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(ErrorResponse{Error: "Internal server error"})
				return
			}

			habit.ScheduleType = scheduleType
			habit.Schedule = body.Schedule
			habit.ScheduleText = scheduleText
		}

		habit.Title = body.Title
		habit.Description = body.Description
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
