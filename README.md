# Go Authentication Service

This Go project demonstrates a simple authentication service using JWT (JSON Web Tokens) for managing user sessions. It utilizes Gin for the web framework, GORM for object-relational mapping, bcrypt for password hashing, and jwt-go for handling JWTs.

## Features

- User signup and login
- Password hashing with bcrypt
- JWT-based authentication
- Middleware for route protection based on user roles (Admin and User)
- Admin can view and modify all users
- Users can view and modify their own data, including custom tags like "new", "premium", etc.

## Prerequisites

- Go (version 1.15 or later recommended)
- PostgreSQL

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourgithubusername/go-authentication-service.git
cd go-authentication-service
```

### 2. Database Configuration

Ensure you have PostgreSQL installed and running on your system. Create a database for the project:

```sql
CREATE DATABASE go_authentication_service;
```

### 3. Environment Variables

Create a `.env` file in the root of your project and add your database connection details and JWT secret key. For example:

```env
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=go_authentication_service
DB_PORT=5432
JWT_SECRET=your_jwt_secret
```

### 4. Install Dependencies

```bash
go mod tidy
```

## Running the Application

To start the server, run:

```bash
go run main.go
```

The server will start listening for requests on `localhost:8080`.

## Endpoints

- **POST /signup**: Register a new user.
  - Body: `{"email": "user@example.com", "name": "John Doe", "picture": "profile.jpg", "password": "password", "isAdmin": false}`
- **POST /login**: Authenticate a user and receive a JWT.
  - Body: `{"email": "user@example.com", "password": "password"}`
- **GET /user/profile**: Retrieve the profile of the currently authenticated user. Requires JWT.
- **GET /admin/users**: Retrieve a list of all users. Requires Admin JWT.
- PUT /user/{id}: Update user information (authenticated users can update their own information; admins can update any user's information).
Body example: {"name": "Updated Name", "tags": "premium"}

