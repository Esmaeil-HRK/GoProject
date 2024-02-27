package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"
)

// User model
type User struct {
	gorm.Model
	Email    string `json:"email" gorm:"unique" validate:"email"`
	Name     string `json:"name" validate:"required"`
	Picture  string `json:"picture" validate:"required,endswith=jpg|endswith=png"`
	Password string `json:"password" validate:"required"`
	IsAdmin  bool   `json:"isAdmin"`
}

// Claims JWT Claims struct
type Claims struct {
	UserID  uint `json:"userId"`
	IsAdmin bool `json:"isAdmin"`
	jwt.StandardClaims
}

var (
	db       *gorm.DB
	validate *validator.Validate
	jwtKey   = []byte("your_secret_key") // Ensure this is securely managed and generated
)

func init() {
	var err error
	// Database initialization
	db, err = gorm.Open(postgres.Open("host=localhost user=postgres password=esm2000esm dbname=postgres port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&User{})

	// Validator initialization
	validate = validator.New()
}

// GenerateToken generates a JWT token for a user
func GenerateToken(user User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:  user.ID,
		IsAdmin: user.IsAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	return tokenString, err
}

// AuthMiddleware authenticates and authorizes users
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized - invalid token"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("isAdmin", claims.IsAdmin)

		c.Next()
	}
}

func main() {
	r := gin.Default()

	r.POST("/signup", func(c *gin.Context) {
		var newUser User
		if err := c.BindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate the new User struct
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

	// Authentication route
	r.POST("/login", func(c *gin.Context) {
		var credentials struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user User
		if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login credentials"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login credentials"})
			return
		}

		tokenString, err := GenerateToken(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Admin route example
	r.GET("/admin/users", AuthMiddleware(), func(c *gin.Context) {
		isAdmin, _ := c.Get("isAdmin")
		if !isAdmin.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})

	// User route example
	r.GET("/user/profile", AuthMiddleware(), func(c *gin.Context) {
		userID, _ := c.Get("userID")
		var user User
		db.First(&user, userID)
		c.JSON(http.StatusOK, user)
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
