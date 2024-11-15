package handlers

import (
    "database/sql"
    "io/ioutil"
    "net/http"
    "strings"

    "github.com/labstack/echo/v4"
    "golang.org/x/crypto/bcrypt"

    "github.com/84adam/arkfile/auth"
    "github.com/84adam/arkfile/database"
    "github.com/84adam/arkfile/logging"
    "github.com/84adam/arkfile/storage"
)

// Register handles user registration
func Register(c echo.Context) error {
    var request struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
    }

    // Validate email and password
    if !strings.Contains(request.Email, "@") || len(request.Password) < 8 {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid email or password")
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), 12)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to hash password: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process registration")
    }

    // Store user in database
    _, err = database.DB.Exec(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        request.Email, hashedPassword,
    )
    if err != nil {
        if strings.Contains(err.Error(), "UNIQUE") {
            return echo.NewHTTPError(http.StatusConflict, "Email already registered")
        }
        logging.ErrorLogger.Printf("Failed to create user: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create user")
    }

    database.LogUserAction(request.Email, "registered", "")
    logging.InfoLogger.Printf("User registered: %s", request.Email)
    return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

// Login handles user authentication
func Login(c echo.Context) error {
    var request struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
    }

    // Retrieve user from database
    var hashedPassword string
    err := database.DB.QueryRow(
        "SELECT password FROM users WHERE email = ?",
        request.Email,
    ).Scan(&hashedPassword)

    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
    } else if err != nil {
        logging.ErrorLogger.Printf("Database error during login: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Login failed")
    }

    // Compare passwords
    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(request.Password))
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
    }

    // Generate JWT token
    token, err := auth.GenerateToken(request.Email)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to generate token: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Login failed")
    }

    database.LogUserAction(request.Email, "logged in", "")
    logging.InfoLogger.Printf("User logged in: %s", request.Email)
    return c.JSON(http.StatusOK, map[string]string{"token": token})
}

// UploadFile handles file uploads
func UploadFile(c echo.Context) error {
    email := auth.GetEmailFromToken(c)

    var request struct {
        Filename     string `json:"filename"`
        Data         string `json:"data"`
        PasswordHint string `json:"passwordHint"`
    }

    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
    }

    // Store file in Backblaze
    _, err := storage.MinioClient.PutObject(
        c.Request().Context(),
        storage.BucketName,
        request.Filename,
        strings.NewReader(request.Data),
        int64(len(request.Data)),
        minio.PutObjectOptions{ContentType: "application/octet-stream"},
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to upload file: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to upload file")
    }

    // Store metadata in database
    _, err = database.DB.Exec(
        "INSERT INTO file_metadata (filename, owner_email, password_hint) VALUES (?, ?, ?)",
        request.Filename, email, request.PasswordHint,
    )
    if err != nil {
        // If metadata storage fails, delete the uploaded file
        storage.MinioClient.RemoveObject(c.Request().Context(), storage.BucketName, request.Filename, minio.RemoveObjectOptions{})
        logging.ErrorLogger.Printf("Failed to store file metadata: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process file")
    }

    database.LogUserAction(email, "uploaded", request.Filename)
    logging.InfoLogger.Printf("File uploaded: %s by %s", request.Filename, email)
    return c.JSON(http.StatusOK, map[string]string{"message": "File uploaded successfully"})
}

// DownloadFile handles file downloads
func DownloadFile(c echo.Context) error {
    email := auth.GetEmailFromToken(c)
    filename := c.Param("filename")

    // Verify file ownership
    var ownerEmail string
    err := database.DB.QueryRow(
        "SELECT owner_email FROM file_metadata WHERE filename = ?",
        filename,
    ).Scan(&ownerEmail)

    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "File not found")
    } else if err != nil {
        logging.ErrorLogger.Printf("Database error during download: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process request")
    }

    if ownerEmail != email {
        return echo.NewHTTPError(http.StatusForbidden, "Access denied")
    }

    // Get password hint
    var passwordHint string
    database.DB.QueryRow(
        "SELECT password_hint FROM file_metadata WHERE filename = ?",
        filename,
    ).Scan(&passwordHint)

    // Get file from Backblaze
    object, err := storage.MinioClient.GetObject(
        c.Request().Context(),
        storage.BucketName,
        filename,
        minio.GetObjectOptions{},
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to retrieve file: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
    }
    defer object.Close()

    data, err := ioutil.ReadAll(object)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to read file: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
    }

    database.LogUserAction(email, "downloaded", filename)
    logging.InfoLogger.Printf("File downloaded: %s by %s", filename, email)
    
    return c.JSON(http.StatusOK, map[string]interface{}{
        "data": string(data),
        "passwordHint": passwordHint,
    })
}

// ListFiles returns a list of files owned by the user
func ListFiles(c echo.Context) error {
    email := auth.GetEmailFromToken(c)

    rows, err := database.DB.Query(`
        SELECT filename, password_hint, upload_date 
        FROM file_metadata 
        WHERE owner_email = ?
        ORDER BY upload_date DESC
    `, email)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to list files: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve files")
    }
    defer rows.Close()

    var files []map[string]interface{}
    for rows.Next() {
        var file struct {
            Filename    string
            PasswordHint string
            UploadDate  string
        }
        
        if err := rows.Scan(&file.Filename, &file.PasswordHint, &file.UploadDate); err != nil {
            logging.ErrorLogger.Printf("Error scanning file row: %v", err)
            continue
        }

        files = append(files, map[string]interface{}{
            "filename": file.Filename,
            "passwordHint": file.PasswordHint,
            "uploadDate": file.UploadDate,
        })
    }

    return c.JSON(http.StatusOK, files)
}
