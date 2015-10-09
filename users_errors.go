package authorization;

import (
	"encoding/json"
	"fmt"
)

/**
	Ошибка запроса
**/
type RequestError struct {
	ErrorIndex int		// Индекс ошибки
	ErrorText string	// Текст ошибки
	InsideError string  // Текст из объекта error
	Successfull bool  // Успех
}

// json`ит 
func (r* RequestError) json() (jsText string) {
	r.Successfull = false
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", b)
}

func (r* RequestError) Json() (string) {
	return r.json()
}

// Пользователь не зарегестрирован
func UserIsNotRegistered(userID int) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 1
	r.ErrorText = fmt.Sprintf("Пользователь %d не зарегестрирован", userID)
	return r
}

// Пользователь уже зарегестрирован
func UserAlredyRegistered(login string) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 2
	r.ErrorText = fmt.Sprintf("Пользователь %s уже зарегестрирован", login)
	return r
}

// Внутренняя ошибка сервера
func InternalServerError(err string) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 3
	r.ErrorText = "Внутренняя ошибка сервера"
	r.InsideError = err
	return r
}

// Неверный пароль
func IncorrectPassword() (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 4
	r.ErrorText = "Неверный пароль"
	return r
}

// Недостаточно прав
func AccessDenied() (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 5
	r.ErrorText = "Доступ запрещен"
	return r
}

// Неверный логин
// Пользователь не зарегестрирован
func  UndefinedLogin(login string) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 6
	r.ErrorText = fmt.Sprintf("Неверный логин: %s", login)
	return r
}

// Пользователь не авторизован
func UserIsNotAuthorized(userID int) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 7
	r.ErrorText = fmt.Sprintf("Пользователь %d не авторизован", userID)
	return r
}

// Истек срок жизник токена
func TokenIsNotAlive(userID int) (*RequestError) {
	r := &RequestError {}
	r.ErrorIndex = 8
	r.ErrorText = fmt.Sprintf("Маркер для пользователя %d удален, истек ttl", userID)
	return r 
}

//конфликт ip адресов
func IPConflict(userID int) (*RequestError) {
	r := &RequestError{}
	r.ErrorIndex = 9
	r.ErrorText = fmt.Sprintf("Маркер для пользователя %d удален, конфликт ip адресов", userID)
	return r
}

func IncorrectHTTPMethod() (*RequestError) {
	return &RequestError{10, "Неподдерживаемый http метод", "", false}
}

func IncorrectInpData() (*RequestError) {
	return &RequestError{11, "Некорректные входные данные", "", false}
}

func IncorrectToken() (*RequestError) {
	return &RequestError{12, "Неверный токен", "", false}
}