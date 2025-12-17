package main

import (
	"fmt"
	"net/http"
)

// Типо вместо базы данных так называемый словарь (имя пользователя:пароль)
var users = map[string]string{
	"admin":       "admin",
	"user":        "qwerty123",
	"XyJlurAH4EK": "1234",
}

func main() {

	http.HandleFunc("/", homePage)

	http.HandleFunc("/login", login)

	http.HandleFunc("/secret", secretPage)

	http.HandleFunc("/logout", logoutPage)

	fmt.Println("Сервер запущен на http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

// функция для главной странички
func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<h1>Добро пожаловать</h1>
<p><a href="/login">Войти</a> | <a href="/secret">Секретная страница</a></p>`) //это всё HTML
}

// страница с логином
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" { //типо если = GET отправляем какой то запрос серверу типо "покажи страничку"
		fmt.Fprintf(w, `
        <h1>Вход в систему</h1>
        <form method="POST">
            Логин: <input type="text" name="username"><br>
            Пароль: <input type="password" name="password"><br>
            <input type="submit" value="Войти">
        </form>
        `)
	} else { //если r.Method не = GET(тут у нас POST) берем с сайта информацию о том че написано в логине и пароле
		username := r.FormValue("username")
		password := r.FormValue("password")

		correctPassword, exists := users[username] //ищем пароль по username если чётко то exist == true

		if exists {
			if correctPassword == password {
				//если все чётко делаем куки
				cookie := http.Cookie{
					Name:  "username",
					Value: username,
				}
				//отправляем куки в браузер
				http.SetCookie(w, &cookie)
				fmt.Fprintf(w, `
                <h1>Успешный вход!</h1>
                <p>Привет, %s!</p>
                <a href="/secret">Перейти к секретной странице</a>
                `, username)
				return //выход из функции
			}
		}
		fmt.Fprintf(w, `
        <h1>Ошибка!</h1>
        <p>Неверный логин или пароль</p>
        <a href="/login">Попробовать снова</a>
        `)
	}
}

func secretPage(w http.ResponseWriter, r *http.Request) {
	// Проверяем есть ли куки с именем пользователя
	cookie, err := r.Cookie("username")
	if err != nil {
		fmt.Fprintf(w, `
        <h1>Доступ запрещен!</h1>
        <p>Вы должны <a href="/login">войти в систему</a></p>
        `)
		return
	}

	// Если куки есть показываем секретную страницу
	fmt.Fprintf(w, `
    <h1>Секретная страница</h1>
    <p>Добро пожаловать, %s!</p>
    <pre>⣿⣿⣿⡟⠁⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠈⢻⣿⣿⣿
⣿⣿⠋⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠙⣿⣿
⣿⠃⠄⠄⠄⠄⠄⠄⠄⠄⠉⠉⠛⠿⠿⠿⠿⠛⠉⠉⠄⠄⠄⠄⠄⠄⠄⠄⠘⣿
⡟⢀⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⣴⣦⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⡀⢻
⠇⢸⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⡇⠘
⠄⢸⣿⡄⠄⠄⠄⠄⠄⠄⠄⠄⣰⣿⣿⣿⣿⣆⠄⠄⠄⠄⠄⠄⠄⠄⢠⣿⡇⠄
⡆⢸⣿⣿⣷⣦⣤⣀⣀⣤⣤⣾⣿⣿⣿⣿⣿⣿⣷⣤⣤⣀⣀⣤⣴⣶⣿⣿⡇⢠
⣧⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⣼
⣿⡄⠸⣿⣿⣿⣿⣿⡈⠙⠻⠿⣿⣿⣿⣿⣿⣿⠿⠟⠋⢁⣿⣿⣿⣿⣿⠇⢠⣿
⣿⣿⣄⠘⢿⣿⣿⣿⣿⣦⣄⡀⠄⠄⠈⠁⠄⠄⢀⣠⣴⣿⣿⣿⣿⡿⠃⣠⣿⣿
⣿⣿⣿⣧⡀⠙⢿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣶⣾⣿⣿⣿⣿⣿⡿⠋⢀⣴⣿⣿</pre>
   <p><a href="/logout">Выйти</a> | <a href="/">На главную</a></p>
    `, cookie.Value)
}

// выйти из аккаунта
func logoutPage(w http.ResponseWriter, r *http.Request) {
	//удаляем куки
	cookie := http.Cookie{
		Name:   "username",
		Value:  "",
		MaxAge: -1, // отрицательное значение = удалить куки
	}

	http.SetCookie(w, &cookie)

	fmt.Fprintf(w, `
    <h1>Вы вышли из системы</h1>
    <a href="/">На главную</a>
    `)
}
