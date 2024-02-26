package main

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
)

type User struct {
	gorm.Model
	Email    string `json:"email" gorm:"unique" validate:"email"`
	Name     string `json:"name" validate:"required"`
	Picture  string `json:"picture" validate:"required,endsWith=jpg|endsWith=png"`
	Password string `json:"password" validate:"required"`
}

func main() {
	r := gin.Default()
	db, err := gorm.Open(postgres.Open("host=localhost user=postgres password=esm2000esm dbname=postgres port=5432 sslmode=disable\n"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{})

	r.POST("/signup", func(c *gin.Context) {
		var newUser User
		if err := c.BindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
