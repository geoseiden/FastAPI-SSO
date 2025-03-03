# FastAPI SSO

FastAPI SSO is a secure single sign-on (SSO) implementation. This repository contains two versions of the project:

1. **Auth0-Based Authentication** (Branch :`main`)
2. **Custom Oauth 2.0 Username-Password and Google Sign-On with GCC** (Branch: `custom-oauth-gcc`)

## Features

| Feature                               | Auth0 Version               | Custom-OAuth-gcc Version       |
|---------------------------------------|-----------------------------|---------------------------------|
| **Authentication Provider**          | Auth0                      | Custom (Username-Password) + GCC for Google Sign-On |
| **Session Management**               | Cookie-based               | Cookie-based                   |
| **API Integration**                  | Auth0 APIs                 | GCC OAuth APIs                 |
| **Architecture**                | Monolithic         | Micro Services(Abstraction Repository)  |
| **Additional Features**              | -                          | Logging, Timestamps Mixin      |

## Requirements

| Requirement              | Auth0 Version       | Custom-OAuth-gcc Version |
|--------------------------|---------------------|---------------------------|
| **Python Version**       | 3.7+               | 3.7+                     |
| **Dependencies**         | FastAPI, Auth0 SDK | FastAPI, OAuth Libraries |
| **Cloud Provider**       | Auth0              | GCC                      |

---

# Auth0-Based Authentication (Main Branch)

## Installation

1. Clone the repository and switch to the main branch:
    ```bash
    git clone https://github.com/yourusername/fastapi-sso.git
    cd fastapi-sso
    git checkout main
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv env
    source env/bin/activate   # On Windows use `env\Scripts\activate`
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file in the root directory and add your Auth0 credentials:
    ```env
    AUTH0_URL=https://your-auth0-domain
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret
    ```

## Running the Application

1. Start the FastAPI server:
    ```bash
    uvicorn main:server --reload
    ```

2. Open your browser and navigate to [http://localhost:8000/login](http://localhost:8000/login) to start the authentication process.

## Auth0 Setup

1. Log in to your Auth0 account and create a new application:
    - **Name:** FastAPI SSO
    - **Application Type:** Regular Web Application

2. In the application settings, set the following:
    - **Allowed Callback URLs:** `http://localhost:8000/callback`
    - **Allowed Logout URLs:** `http://localhost:8000`

3. Go to the **APIs** section and create a new API (for example):
    - **Name (example):** Renol Orders API
    - **Identifier (example):** `https://renol.com/orders/api`

4. In the API settings, create permissions as needed.

5. In the **Applications** section, link the "FastAPI SSO" application to the "Renol Orders API".

6. Update your `.env` file with your Auth0 credentials:
    ```env
    AUTH0_URL=https://your-auth0-domain
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret
    ```

# Custom Oauth 2.0 with Google Sign-On (Branch: `custom-oauth-gcc`)

## Installation

1. Clone the repository and switch to the `custom-oauth-gcc` branch:
    ```bash
    git clone https://github.com/yourusername/fastapi-sso.git
    cd fastapi-sso
    git checkout custom-oauth-gcc
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv env
    source env/bin/activate   # On Windows use `env\Scripts\activate`
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file in the root directory and add your credentials:
    ```env
    GCC_CLIENT_ID=your-gcc-client-id
    GCC_CLIENT_SECRET=your-gcc-client-secret
    JWT_SECRET_KEY=your-jwt-secret-key
    ```

## Running the Application

1. Start the FastAPI server:
    ```bash
    uvicorn main:app --reload
    ```

2. Open your browser and navigate to [http://localhost:8000/login](http://localhost:8000/login) to start the authentication process.

## GCC Setup

1. Log in to your Google Cloud Console and create a new project.

2. Enable the **Google OAuth API** for your project.

3. Create OAuth credentials:
    - **Application Type:** Web Application
    - **Authorized Redirect URIs:** `http://localhost:8000/callback`

4. Note the **Client ID** and **Client Secret** and add them to your `.env` file.

## Additional Features

- **Abstraction Repository Pattern:** The application uses an abstraction repository to decouple data access logic from the main codebase, ensuring better maintainability and scalability.

- **Logging:** Built-in logging mechanism to monitor application activity and errors.

- **Timestamps Mixin:** A reusable mixin for adding `created_at` and `updated_at` timestamps to database models.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
