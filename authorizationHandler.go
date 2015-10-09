package authorization;

import (
	"net"
	"net/http"
	"strconv"
	"fmt"
	"encoding/json"
)

type AuthorizeResponse struct {
	UserID int
	Token string
	Successfull bool
}

// type RegisterResponse struct {
	// UserID int 
	// Successfull bool
// }

func jsonInterface(u interface{}) (jsText string) {
	b, err := json.Marshal(u)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", b)
}

// Авторизует пользователей и запросы
type Authenticator struct {
	_usersData* UsersDB
	_tokenStorage* TokenStorage
}

// хандлеры для обработки токенов и пользователей и паролей
func CreateAuthenticator(rUsersDB* UsersDB) (auth* Authenticator) {
	tokenStorage := CreateStorage()
	return &Authenticator{ rUsersDB, tokenStorage }
}

func (auth *Authenticator) GetStorage() *TokenStorage {
	return auth._tokenStorage
}

// Авторизация пользователя, 
// Проверяет логин и пароль пользователя
// В случае успеха возвращает токен, который надо вернуть пользователю
func (auth *Authenticator) AuthorizationRequest(w http.ResponseWriter, r *http.Request) (ok bool, response *AuthorizeResponse) {	

	if (auth._usersData == nil) {
		return false, nil
	}
	if (r.Method != "POST") {
		return false, nil
	}
	userLogin := r.FormValue("UserLogin")
	password  := r.FormValue("UserPassword")

	if (userLogin == "" || password == "") {
		return false, nil
	}

	userID, pasError := auth._usersData.CheckPassword(userLogin, password)
	if pasError != nil {
		return false, nil
	}
	ip,_,_ := net.SplitHostPort(r.RemoteAddr)
	token := <- auth._tokenStorage.NewToken(int32(userID), ip)

	if token.Error != nil {
		return false, nil
	}
	resp := &AuthorizeResponse{userID, token.TokenInfo.token, true}
	return true, resp
}

// Аутентификация пользователя
// Проверяет токен пользователя
func (auth *Authenticator) AuthenticateRequest(w http.ResponseWriter, r *http.Request) (ok bool, errText string) {
	if (auth._tokenStorage == nil) {
		return false, InternalServerError("_tokenStorage=nil").json()
	}
	var userID, token string

	if (r.Method == "POST" || r.Method == "PUT") {
		userID = r.FormValue("UserID")
		token  = r.FormValue("UserToken")
	} else {
		userID = r.URL.Query().Get("UserID")
		token  = r.URL.Query().Get("UserToken")
	}

	if (userID == "" || token == "") {
		return false, IncorrectInpData().json()
	}

	uidConv, err := strconv.ParseInt(userID, 10, 32)
	if (err != nil) {
		return false, InternalServerError(err.Error()).json()
	}

	ip,_,_ := net.SplitHostPort(r.RemoteAddr)
	res, terr := auth._tokenStorage.CompareToken(int32(uidConv), ip, token)
	if res == true {
		return true, ""
	}
	if (terr != nil) {
		return false, terr.Json()
	}
	return false, IncorrectToken().json()
}

// Запрос на регистрацию пользователя
func (auth *Authenticator) RegisterRequest(w http.ResponseWriter, r *http.Request) (ok bool, response *AuthorizeResponse) {
	if auth._usersData == nil {
		return false, nil
	}
	if (r.Method != "POST") {
		return false, nil
	}
	userLogin := r.FormValue("UserLogin")
	password  := r.FormValue("UserPassword")
	fName     := r.FormValue("FirstName")
	lName     := r.FormValue("LastName")
	RefID	  := r.FormValue("UserID")
	if (userLogin == "" || password == "") {
		return false, nil
	}
	RefIDInt, cerr := strconv.ParseInt(RefID, 10, 32)
	if (cerr != nil) {
		RefIDInt = 0
	}
	newUser := &User { FirstName: fName, LastName: lName, Password: password, Login: userLogin, ReferalID: int(RefIDInt) }
	reqError := auth._usersData.CreateUser(newUser)
	if reqError != nil {
		return false, nil
	}

	// resp := RegisterResponse {newUser.ID, true}	
	return auth.AuthorizationRequest(w, r)
}