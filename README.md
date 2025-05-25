# Fake AI Checker - Internal Security Tool

A secure ASP.NET Core MVC application designed to simulate AI content detection while performing real security scanning for API keys, tokens, secrets, and other sensitive information in uploaded files and archives.

## ⚠️ Important Security Notice

This tool is designed for **internal security testing purposes only** (or is it lol). It should be used to educate staff about security vulnerabilities and the importance of protecting sensitive information.

## Features

- **Fake AI Detection**: Generates random AI vs Human content percentages
- **Real Security Scanning**: Detects actual API keys, tokens, passwords, and secrets
- **Archive Support**: Scans ZIP, RAR, 7Z, TAR, and GZ files
- **Secure Processing**: Uses sandboxed temporary directories
- **Comprehensive Logging**: Audit trails for all activities
- **Database Storage**: Logs findings to MySQL database
- **Docker Support**: Containerized deployment for security
- **Advanced Authentication**: Secure login with Argon2id hashing, salting, peppering, and JWT tokens
- **Admin Panel**: Protected views for SecurityFindings, AuditLogs, and ScanResults

## Security Measures

1. **File Validation**: Type, size, and name validation
2. **Sandbox Processing**: Isolated temporary directories
3. **Automatic Cleanup**: All files deleted after processing
4. **Audit Logging**: Complete activity tracking
5. **Input Sanitization**: Protection against path traversal
6. **Size Limits**: 50MB maximum file size
7. **Container Security**: Non-root user, restricted permissions
8. **Password Security**: Argon2id hashing algorithm with salting and peppering
9. **JWT Authentication**: Secure token-based authentication with HttpOnly cookies

## Quick Start

### Using Docker (Recommended)

1. **Clone and build:**
   ```bash
   docker-compose up --build -d
   ```

2. **Access the application:**
   - Web interface: http://localhost:8080
   - MySQL: localhost:3306

### Manual Setup

1. **Install dependencies:**
   ```bash
   dotnet restore
   ```

2. **Setup MySQL database:**
   - Create database `FakeAiChecker`
   - Update connection string in `appsettings.json`

3. **Run the application:**
   ```bash
   dotnet run
   ```

## Configuration

### Environment Variables
- `ConnectionStrings__DefaultConnection`: MySQL connection string
- `Security__MaxUploadSizeMB`: Maximum upload size (default: 50)
- `Security__ScanTimeoutMinutes`: Scan timeout (default: 5)
- `JwtSettings__Secret`: Secret key for JWT token signing
- `JwtSettings__Issuer`: Token issuer (default: FakeAiChecker)
- `JwtSettings__Audience`: Token audience (default: FakeAiCheckerUsers)
- `JwtSettings__ExpirationInMinutes`: Token expiration time (default: 120)
- `PasswordSecurity__Pepper`: Secret pepper for password hashing

### Database Configuration
Update `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=FakeAiChecker;Uid=root;Pwd=your_password;"
  },
  "JwtSettings": {
    "Secret": "YourSuperSecretKeyHereMakeItLongAndComplex123!@#",
    "Issuer": "FakeAiChecker",
    "Audience": "FakeAiCheckerUsers",
    "ExpirationInMinutes": 120
  },
  "PasswordSecurity": {
    "Pepper": "SecretPepperForPasswordSecurity456!@#"
  }
}
```

## Usage

1. **Upload File**: Select a file or archive to analyze
2. **View Results**: See fake AI percentages and real security findings
3. **Admin Login**: Access the admin panel via the login page
4. **Review Findings**: View detailed security findings, scan results, and audit logs
5. **Manage Users**: Create additional admin users for secure access

### Admin Access

1. **Login**: Navigate to `/Auth/Login` or click the Admin Login link
2. **Default Credentials**: 
   - Username: Set in `appsettings.json` under `AdminSetup:DefaultUsername`
   - Password: Set in `appsettings.json` under `AdminSetup:DefaultPassword`
3. **Creating New Admins**: Existing admins can create new admin users via the "Add Admin User" option

### API Endpoints

The application also provides secure API endpoints for authentication and token validation:

- `POST /api/auth/login`: Authenticate and receive JWT token
- `POST /api/auth/register`: Create new admin user (requires admin authentication)
- `GET /api/auth/validate`: Validate existing JWT token

## Supported File Types

- **Documents**: .txt, .doc, .docx, .pdf
- **Archives**: .zip, .rar, .7z, .tar, .gz
- **Config Files**: .env, .json, .xml, .yml, .yaml, .config, .ini, .properties

## Security Patterns Detected

- AWS Access Keys and Secret Keys
- GitHub Personal Access Tokens
- Slack Bot Tokens
- Discord Bot Tokens
- Google API Keys
- Firebase Keys
- Stripe API Keys
- Twilio SIDs
- Generic API keys, secrets, tokens, passwords
- Database URLs
- Private keys (RSA, SSH)

## Database Schema

### Tables
- **ScanResults**: File scan metadata and AI percentages
- **SecretFindings**: Detected secrets and their context
- **AuditLogs**: Complete activity audit trail
- **Users**: Admin user accounts with secure password storage

## Development

### Project Structure
```
├── Auth/                # Authentication handlers
├── Controllers/         # MVC Controllers
├── Data/                # Entity Framework DbContext
├── Helpers/             # Helper classes and utilities
├── Middleware/          # Custom middleware components
├── Migrations/          # EF Core database migrations
├── Models/              # Data models and ViewModels
├── Services/            # Business logic services
├── Views/               # Razor views
└── wwwroot/             # Static files
```

### Key Services
- **SecretScannerService**: Core scanning logic
- **AuditService**: Logging and audit trails
- **SecurityService**: Security validations and utilities
- **AuthService**: Authentication and user management with Argon2

## Security Best Practices

1. **Never deploy this publicly** - Internal use only
2. **Use strong database passwords**
3. **Monitor audit logs regularly**
4. **Rotate database credentials**
5. **Keep Docker images updated**
6. **Review findings immediately**
7. **Change default admin credentials**
8. **Use long, complex JWT secrets**
9. **Set secure password policies**
10. **Enable HTTPS in production**