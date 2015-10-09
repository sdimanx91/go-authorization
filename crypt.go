package authorization;

import (
	"golang.org/x/crypto/bcrypt" 
	"fmt"	
)

// Внутри массива байт заполняет 0 
func clear(b []byte) {
    for i := 0; i < len(b); i++ {
        b[i] = 0;
    }
}

// Шифрование пароля bcrypt
func Crypt(password string) (string, error) {
	bp := []byte(password)
    defer clear(bp)
    hashedBytes, err :=  bcrypt.GenerateFromPassword(bp, bcrypt.DefaultCost)    
    return fmt.Sprintf("%s", hashedBytes), err
}

// Проверка пароля (хэш то каждый раз разный)
func CheckPasswordCrypt(hashed, password string) bool {
	bH := []byte(hashed)
	bP := []byte(password)
	return bcrypt.CompareHashAndPassword(bH, bP) == nil
}