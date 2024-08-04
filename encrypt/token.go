package encrypt

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var SECRET_KEY = []byte("gosecretkey")

/*
	type User struct {
		Email    string `json:"email" bson:"email"`
		Password string `json:"password" bson:"password"`
	}
*/
type UserToken struct {
	Email    string
	Password string
	jwt.StandardClaims
}

func GenerateJWT(email string) (token string, err error) {
	claims := &UserToken{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, err
}

func GetHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}
