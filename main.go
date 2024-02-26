package main

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"strings"
)

type User struct {
	gorm.Model
	Email    string `json:"email" gorm:"unique" validate:"email"`
	Name     string `json:"name" validate:"required"`
	Picture  string `json:"picture" validate:"required,endswith=jpg|endswith=png"`
	Password string `json:"password" validate:"required"`
}

var validate *validator.Validate

func main() {
	r := gin.Default()
	db, err := gorm.Open(postgres.Open("host=localhost user=postgres password=esm2000esm dbname=postgres port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{})

	validate = validator.New()

	r.POST("/signup", func(c *gin.Context) {
		var newUser User
		if err := c.BindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate the newUser struct
		if validationErr := validate.Struct(newUser); validationErr != nil {
			var errMsg []string
			for _, err := range validationErr.(validator.ValidationErrors) {
				var fieldError string
				switch err.Tag() {
				case "required":
					fieldError = err.Field() + " is required"
				case "email":
					fieldError = "Invalid email format"
				case "endswith":
					fieldError = err.Field() + " must be a jpg or png file"
				default:
					fieldError = "Invalid value for " + err.Field()
				}
				errMsg = append(errMsg, fieldError)
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": strings.Join(errMsg, ", ")})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
			return
		}
		newUser.Password = string(hashedPassword)

		result := db.Create(&newUser)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
			return
		}

		c.JSON(http.StatusCreated, newUser)
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
