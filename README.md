# Auth_Server

Auth_Server is a Spring Boot-based backend project that provides authentication services, including login, registration, and password management. A super admin is automatically created when the project is run with the credentials `admin@gmail.com` and password `password`.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Contact](#contact)

## Installation

To install and run the Auth_Server, follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/atishojha-404/Auth_Server.git
    cd Auth_Server
    ```

2. Install dependencies and build the project:
    ```sh
    ./mvnw clean install
    ```

3. Set up the MailDev mail server:
    ```sh
    sudo docker run -p 1080:1080 -p 1025:1025 maildev/maildev
    ```

4. Run the application:
    ```sh
    ./mvnw spring-boot:run
    ```

## Usage

The Auth_Server provides several API endpoints for authentication and user management. Below are the key endpoints:

- **Register**: `POST /api/v1/auth/register`
- **Authenticate**: `POST /api/v1/auth/authenticate`
- **Activate Account**: `GET /api/v1/auth/activate-account`
- **Change Password via Email**: `POST /api/v1/auth/change-password-email`
- **Confirm Password Change Token**: `POST /api/v1/auth/Change-password-token-confirm`
- **Change Password**: `POST /api/v1/auth/change-password`
- **Get Current Logged-in User**: `GET /api/v1/auth/get-current-logged-in-user`

### Example Requests

**Register a new admin:**
```sh
curl -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" -d '{"email":"adminuser@gmail.com", "password":"newpassword"}'
```

## Features

- **Admin Registration and Login**: Allows Super Admin to register admin and log in.
- **Super Admin Auto-Creation**: A super admin account is automatically created on startup with predefined credentials.
- **Password Management**: Features for changing and resetting passwords.
- **Token-Based Authentication**: Secure authentication using tokens.
- **Mail Server Integration**: Uses MailDev for handling email functionalities during development.

## Configuration

The server can be configured using environment variables or application properties in `application-dev.properties`. Here are some key properties you may need to set:

- `spring.datasource.url`: Database URL
- `spring.datasource.username`: Database username
- `spring.datasource.password`: Database password
- `spring.mail.host`: Mail server host
- `spring.mail.port`: Mail server port

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some feature'`)
5. Push to the branch (`git push origin feature/your-feature-name`)
6. Open a pull request


## Contact

If you have any questions or feedback, please feel free to contact me:

- GitHub: [atishojha-404](https://github.com/atishojha-404)
- Email: ojhaatish11@gmail.com
- Website: [ojhaatish.com.np](https://www.ojhaatish.com.np)

