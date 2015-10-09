package authorization;

import (
	"time"
	"strconv"
	"crypto/md5"
	"math/rand"
	"io"
	"fmt"
)

const (
	CMD_READ   = 0				    // Комманда на чтение токена
	CMD_CREATE = 1 					// Комманда на создание токена
	CMD_REMOVE = 2 				    // Комманда на удаление токена
	CMD_CHECK_ALL_TOKENS = 3 	    // Проверка всех токенов, запускать по расписанию, например раз в день	
	CMD_CHECK_ALL_TOKENS_BEGIN = 4  // Начало процедуры CMD_CHECK_ALL_TOKENS
	CMD_CHECK_ALL_TOKENS_END = 5 	// Конец процедуры CMD_CHECK_ALL_TOKENS

	ERR_NO_ERR			   = 0
	ERR_UNDEFINED_USER_ID  = 1; 	// Пользователь не зарегестрирован
	ERR_TOKEN_IS_NOT_ALIVE = 2;		// Токен не живет, после этого запроса он будет удален 
	ERR_TOKEN_INCORRECT_IP = 3; 	// Ip адреса не совпадают, после этого запроса токен будет удален
)

//------------------------------------------
type Token struct {	
	UnixTime int64  // Время создания токена 	
	UserID   int32  // Идентефикатор ползователя
	token    string // Маркер пересылаемый пользователю
	Ip 		 string // Ip адрес с которго авторизивался
}

// Данные для выполенени комманды с кэшем токена
type TokenData struct {
	UserID int32    		    // Идентефикатор пользователя, которому потенциально преднадлежит токен
	Command int     		    // Что с ним сделать create или remove
	ReturnChannel chan TokenRef // Канал для передачи комманд
	Ip string 				    // IP адрес, к которому привязан токен, токен может быть только один
}

// Данные, которые возвращаются пользователю
type TokenRef struct {
	Error *TokenError // Ошибка
	TokenInfo *Token  // Инфа про токен
}

// Ошибка токена
type TokenError struct {
	ErrorCode int 			// Код ошибки 
	RequestedUserID int32   // ID пользователя у кот запрашивали данные
}

// Событие
type Event struct {
	CallCommand int 	  // Комманда, которая, возможно, была выполнена
	ErrorInfo *TokenError // Ошибка которая возможно произошла
	TokenInfo *Token      // Токен, который, возможно был создан
	UnixTime int64	      // Время генерирования события
}

// Хранение токенов
type TokenStorage struct {
		// Данные о ключах в кэше
		_KeysTTL	int64					

		// Колбэки
		_EventReader func(Event) // Для логирования

		// ---
	    _TokenCache   map[string]*Token   // token -> Token
		_TokenIDCache map[int32]*Token    // UserID -> token  

		// Каналы		
		_TokenWriterChannel chan TokenData // для отправки запроса
}

// Сгенерировать ошибку в общем виде
func (te *TokenError) GenerateRequestError() (*RequestError) {
	switch te.ErrorCode {
		case ERR_UNDEFINED_USER_ID: return UserIsNotAuthorized(int(te.RequestedUserID))
		case ERR_TOKEN_IS_NOT_ALIVE: return TokenIsNotAlive(int(te.RequestedUserID))
		case ERR_TOKEN_INCORRECT_IP: return IPConflict(int(te.RequestedUserID))
	}
	return nil
}

// Выдергивает комманды из канала по очереди
// Сделано с целью потокобезопасности
func (storage *TokenStorage) _Serve() {
	for {
		tData := <-storage._TokenWriterChannel

		switch tData.Command {
			case CMD_CREATE:
				storage._MakeToken(tData)
				break
			case CMD_READ:
				storage._CheckToken(tData)
				break	
			case CMD_REMOVE:
				storage._RemoveToken(tData, true, false)	
				break
			case CMD_CHECK_ALL_TOKENS:
				storage._CheckAllTokens(tData)
				break	
		}		
	}
}

// Сработало событие - это для логирования
func (storage *TokenStorage) _CallEvent(callCommand int, errorInfo *TokenError, tokenInfo *Token) {
	if (storage._EventReader == nil) {
		return ;
	}
	ut := time.Now().Unix()	
	event := Event{ callCommand, errorInfo, tokenInfo, ut }
	storage._EventReader(event)
}

// Пытается прочитать токен
func (storage *TokenStorage) _CheckAllTokens(tData TokenData) {
	storage._CallEvent(CMD_CHECK_ALL_TOKENS_BEGIN, nil, nil)
	for user := range storage._TokenIDCache {
		token := TokenData {user, CMD_READ, nil, ""}
		storage._CheckToken(token)
	}	
	storage._CallEvent(CMD_CHECK_ALL_TOKENS_END, nil, nil)
}

// Возвращает токен
func (storage *TokenStorage) _MakeToken(tData TokenData) {	
	// Проверяем, что токен существует
	// Если существует - удаляем
	storage._RemoveToken(tData, false, true)

	random := rand.Intn(32000)

	buf := &Token {}
	buf.UserID   = tData.UserID
	buf.UnixTime = time.Now().Unix()
	buf.Ip = tData.Ip

	h := md5.New()
	io.WriteString(h, strconv.FormatInt(buf.UnixTime, 10))
	io.WriteString(h, strconv.Itoa(int(buf.UserID)))	
	io.WriteString(h, strconv.Itoa(random))	
	data := h.Sum(nil)
	buf.token = fmt.Sprintf("%x", data)

	storage._TokenCache[buf.token]    = buf
	storage._TokenIDCache[buf.UserID] = buf

	storage._CallEvent(CMD_CREATE, nil, buf)

	// Вызываем колбэк с нужной функцией		
	if (tData.ReturnChannel != nil) {
		tData.ReturnChannel <- TokenRef { nil, buf };
	}
}

// Проверяет токен ttl (time to live)
func (storage *TokenStorage) _CheckToken(tData TokenData) {
    current   := time.Now().Unix()	
	token, ok := storage._TokenIDCache[tData.UserID]
	if (!ok) {
		
		err := &TokenError {}
		err.ErrorCode = ERR_UNDEFINED_USER_ID
		err.RequestedUserID = tData.UserID		
		storage._CallEvent(CMD_READ, err, nil)
		if (tData.ReturnChannel != nil) {
			tData.ReturnChannel <- TokenRef {  err, nil  }
		}
		return 
	}
	
	IsTokenLive := (current < token.UnixTime+storage._KeysTTL)
	var err *TokenError = nil
	if (!IsTokenLive) {
		storage._RemoveToken(tData, false, true)		
		err = &TokenError {}
		err.ErrorCode = ERR_TOKEN_IS_NOT_ALIVE
		err.RequestedUserID = tData.UserID	
		storage._CallEvent(CMD_READ, err, nil)	
		if (tData.ReturnChannel != nil) {
			tData.ReturnChannel <- TokenRef {  err, nil  }
		}
		return 
	}	
	if (tData.Ip != token.Ip) {
		storage._RemoveToken(tData, false, true)		
		err = &TokenError {}
		err.ErrorCode = ERR_TOKEN_INCORRECT_IP
		err.RequestedUserID = tData.UserID	
		storage._CallEvent(CMD_READ, err, nil)	
		if (tData.ReturnChannel != nil) {
			tData.ReturnChannel <- TokenRef {  err, nil  }
		}
		return 		
	}

	storage._CallEvent(CMD_READ, nil, token)	
	if (tData.ReturnChannel != nil) {
		tData.ReturnChannel <- TokenRef {  nil, token  }
	}
}

// Удаление токена
func (storage *TokenStorage) _RemoveToken(tData TokenData, resultToChannel bool, onlyCheck bool) {
	tokenEx, tokenExists := storage._TokenIDCache[tData.UserID]

	if (tokenExists == true) {
		delete(storage._TokenIDCache, tData.UserID)	
		tkValue := tokenEx.token

		_, tkExistsInTokenCache := storage._TokenCache[tkValue]
		if (tkExistsInTokenCache) {
			delete(storage._TokenCache, tkValue)
		}
		storage._CallEvent(CMD_REMOVE, nil, tokenEx)	
		if (resultToChannel) {
			if (tData.ReturnChannel != nil) {
				tData.ReturnChannel <- TokenRef {  nil, tokenEx  }
			}
		}		
	} else
	if (!onlyCheck) {		
		err := &TokenError {}
		err.ErrorCode = ERR_UNDEFINED_USER_ID
		err.RequestedUserID = tData.UserID		
		storage._CallEvent(CMD_REMOVE, err, nil)	
		if (resultToChannel) {
			if (tData.ReturnChannel != nil) {
				tData.ReturnChannel <- TokenRef {  err, nil  }
			}
		}
	}
}

//*************************************************************************************
// Публичной API
//*************************************************************************************

// Создает новое хранилище токенов
func CreateStorage() (storage *TokenStorage) {
	storage = &TokenStorage{}
    storage._TokenCache   	    = make(map[string](*Token))
	storage._TokenIDCache	    = make(map[int32]*Token)
	storage._TokenWriterChannel = make(chan TokenData)
	storage._KeysTTL			= 60*60*24;
	go storage._Serve()

	return storage
}

// задаем колбэк
// Потоконебезопасно. Вызывать только из основной рутины
func (storage *TokenStorage) SetEventReader(callback func (Event)) {
	storage._EventReader = callback
}

// Задаем ttl
// Потоконебезопасно. Вызывать только из основной рутины
func (storage *TokenStorage) SetTTL(ttl int64) {
	storage._KeysTTL = ttl;
}

//Создание токена для пользователя
func (storage *TokenStorage) NewToken(UserID int32, IpAddress string) (chan TokenRef) {
	ret  := make(chan TokenRef)
	tData := TokenData {UserID, CMD_CREATE, ret, IpAddress}
	storage._TokenWriterChannel <- tData
	return ret
}

// Чтение токена
func (storage *TokenStorage) ReadToken(UserID int32, IpAddress string) (chan TokenRef) {
	ret := make(chan TokenRef)
	tData := TokenData {UserID, CMD_READ, ret, IpAddress}
	storage._TokenWriterChannel <- tData
	return ret
}

// Удаление токена
// Возвращает UserID у которого удален токен
func (storage *TokenStorage) DeleteToken(UserID int32) (chan TokenRef) {
	ret := make(chan TokenRef)
	tData := TokenData {UserID, CMD_REMOVE, ret, ""}
	storage._TokenWriterChannel <- tData
	return ret
}

// проверяет ВСЕ токены в кэше на ttl
// Токены умершие удаляются из кэша
func (storage *TokenStorage) CheckAllTokens() {
	tData := TokenData {-1, CMD_CHECK_ALL_TOKENS, nil, ""}
	storage._TokenWriterChannel <- tData
}

// Сравнение токенов (проверка его валидности)
func (storage *TokenStorage) CompareToken(UserID int32, IpAddress string, token string) (result bool, e* RequestError) {
	t := <- storage.ReadToken(UserID, IpAddress)	
	var re *RequestError = nil
	if (t.Error != nil) {
		re = t.Error.GenerateRequestError()
		return false, re;
	}
	return t.TokenInfo.token == token, nil
}
//*************************************************************************************