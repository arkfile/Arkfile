package models

import (
    "database/sql"
    "errors"
    "time"

    "golang.org/x/crypto/bcrypt"
)

type User struct {
    ID        int64     `json:"id"`
    Email     string    `json:"email"`
    Password  string    `json:"-"` // Never send password in JSON
    CreatedAt time.Time `json:"created_at"`
}

// CreateUser creates a new user in the database
func CreateUser(db *sql.DB, email, password string) (*User, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    if err != nil {
        return nil, err
    }

    result, err := db.Exec(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        email, hashedPassword,
    )
    if err != nil {
        return nil, err
    }

    id, err := result.LastInsertId()
    if err != nil {
        return nil, err
    }

    return &User{
        ID:        id,
        Email:     email,
        CreatedAt: time.Now(),
    }, nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(db *sql.DB, email string) (*User, error) {
    user := &User{}
    err := db.QueryRow(
        "SELECT id, email, password, created_at FROM users WHERE email = ?",
        email,
    ).Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)

    if err == sql.ErrNoRows {
        return nil, errors.New("user not found")
    }
    if err != nil {
        return nil, err
    }

    return user, nil
}

// VerifyPassword checks if the provided password matches the stored hash
func (u *User) VerifyPassword(password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
    return err == nil
}

// UpdatePassword updates the user's password
func (u *User) UpdatePassword(db *sql.DB, newPassword string) error {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
    if err != nil {
        return err
    }

    _, err = db.Exec(
        "UPDATE users SET password = ? WHERE id = ?",
        hashedPassword, u.ID,
    )
    return err
}
