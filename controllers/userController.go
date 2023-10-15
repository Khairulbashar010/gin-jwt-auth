package controllers

import (
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context)  {

	var body struct {
		Email string
		Password string 
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest,  gin.H{
			"error": "Failed to read body",
		})

		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest,  gin.H{
			"error": "Failed to hash password",
		})

		return
	}

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest,  gin.H{
			"error": "Failed to add user ",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{})
	
}

func Login(c *gin.Context)  {
	var body struct {
		Email		string 
		Password	string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	var user models.User

	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return 
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
    if err != nil {
        // Check for error and return failure response
        if err == bcrypt.ErrMismatchedHashAndPassword {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "Invalid email or password",
            })
			return
        }
    }

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create a token",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}