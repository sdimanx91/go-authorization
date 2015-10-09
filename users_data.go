package authorization;

import (
	"time"
	"github.com/jinzhu/gorm"	
	_ "github.com/go-sql-driver/mysql"
	// "fmt"
)

/**
 * Модуль для работы со списком пользователей
 *  - Получение данных
 *  - Добавление данных
 *  - Удаление данных
 *  - Модификация данных
 **/

// Данные одного пользователя
type User struct {
	ID int				  	  							 // ИД пользвоателя в базе данных (PK)
	CreationDateUT time.Time  							 // UnixTime Создания
	ReferalID int 		  	  							 // Кто зарегестрировал
	Login string		 	  `sql:"type:varchar(255)"`  // Имя ползователя, для авторизации
	Password string	      	  `sql:"type:varchar(1024)"` // Пароль, для авторизации
	FirstName string	  	  `sql:"type:varchar(255)"`  // Имя 
	LastName string 	  	  `sql:"type:varchar(255)"`  // Фамилия
}

type RowUser struct {
	ID int				  	  							 // ИД пользвоателя в базе данных (PK)
	CreationDateUT int64     							 // UnixTime Создания	
	Login string		 	  `sql:"type:varchar(255)"`  // Имя ползователя, для авторизации
	FirstName string	  	  `sql:"type:varchar(255)"`  // Имя 
	LastName string 	  	  `sql:"type:varchar(255)"`  // Фамилия
}

// Базовая конфигурация
type UsersDB struct {
 	_db *gorm.DB // База данных собсно
}

// Инициализация базы
func InitUsersDB() (userDB *UsersDB, rErr *RequestError) {
	db, err := gorm.Open("mysql", "root:root@unix(/Applications/MAMP/tmp/mysql/mysql.sock)/avokado?charset=utf8&parseTime=True&loc=Local")	
	
	if (err != nil) {
		return nil, InternalServerError(err.Error())	
	}
	// if !db.HasTable(&User{}) {
	db.CreateTable(&User{})
	// }
	udb := &UsersDB{&db}
	return udb, nil
}

// Поиск по идентефикатору
func (users *UsersDB) GetUserByUserID( userID int ) (user *User, exists *RequestError) {
	_user := &User {}
	users._db.First(_user, userID)
	var err *RequestError = nil
	if (_user.ID != userID) {
		err = UserIsNotRegistered(userID)
	}
	return _user, err
}

// Поиск пользователя по имени пользователя
func (users *UsersDB) GetUserByLogin(login string) (user *User, exists *RequestError) {
	var count int
	_user := &User {}
	users._db.Where("Login=?",login).First(&_user).Count(&count)
	var err *RequestError = nil
	if (count == 0) {
		err = UndefinedLogin(login)
	}
	return _user, err
}

// Изменить данные пользователя
// Внутри UserData ID которого нужно обновить
func (users *UsersDB) SetUserData(d User, password string) (r* RequestError) {
	data := d
	if(password != "") {
		newPswd, err := Crypt(password)
		if (err != nil) {
			return InternalServerError(err.Error())		
		}
		data.Password = newPswd
	}
	var count int
	users._db.Model(&d).UpdateColumns(data).Count(&count)
	if (count == 0) {
		return UserIsNotRegistered(d.ID)
	}
	return nil
}

// Создать пользователя
// ID не указывать
// В структуре должно быть поле
func (users *UsersDB) CreateUser(data *User )  (*RequestError) {
	_, errExists := users.GetUserByLogin(data.Login)
	if (errExists == nil) {
		return UserAlredyRegistered(data.Login)
	}

	crypted, err := Crypt(data.Password)
	if (err != nil) {
		return InternalServerError(err.Error())
	}
	data.Password = crypted
	data.CreationDateUT = time.Now()
	users._db.Create(data)
	return nil
}

// Удаление пользователя
func (users *UsersDB) RemoveUser(data *User) (*RequestError) {
	_, errExists := users.GetUserByUserID(data.ID)
	if (errExists != nil) {
		return errExists
	}
	users._db.Delete(data)
	return nil
}

// Проверка правильности пароля
func (users *UsersDB) CheckPassword(UserLogin string, pas string) (int, *RequestError) {
	user, errExists := users.GetUserByLogin(UserLogin)
	if errExists!=nil {
		return 0, errExists
	}

	check := CheckPasswordCrypt(user.Password, pas)	
	if (!check) {
		return 0, IncorrectPassword()
	}
	id    := user.ID
	return id, nil
}

// Возвращает массив всех пользователей
func (users *UsersDB) GetAllUsers() ([]RowUser) {
	var count int=0
	users._db.Table("users").Count(&count);

	rows, errRaw := users._db.Raw("SELECT * FROM users").Rows()
	if errRaw != nil {
		return make([]RowUser, 0)
	}

	defer rows.Close()

	retUsers := make([]RowUser, count)
	i := 0
	for rows.Next() {
		var ID int	
		var CreationDateUT time.Time 
		var ReferalID int 
		var Login string
		var Password string	 
		var FirstName string
		var LastName string 

    	rows.Scan(&ID, &CreationDateUT, &ReferalID, &Login, &Password, &FirstName, &LastName);
    	retUser := RowUser { ID, CreationDateUT.Unix(), Login, FirstName, LastName } 
    	retUsers[i] = retUser
       	i++    
	}
	return retUsers;
}

// Можно зарегестрировать первого админа
// Ни одной записи об админах
func (users *UsersDB) CanRegisterAdmin() (bool) {
	var count int
	us := make([]User, 0)
	users._db.Find(&us).Count(&count)
	return count == 0
}

