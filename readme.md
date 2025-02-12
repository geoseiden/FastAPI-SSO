# FastAPI SSO

FastAPI SSO is a secure single sign-on (SSO) implementation using FastAPI and Auth0. This project provides a simple way to implement authentication and authorization in your FastAPI applications with Auth0.

## Features
- Single Sign-On (SSO) using Auth0
- Secure token validation
- Easy integration with your FastAPI application
- Cookie-based session management

## Requirements
- Python 3.7+
- FastAPI
- Auth0 account

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/fastapi-sso.git
   cd fastapi-sso

2. Create and activate a virtual environment:
    ```bash
    python -m venv env
    source env/bin/activate   # On Windows use `env\Scripts\activate`
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
4. Create a .env file in the root directory and add your Auth0 credentials:
    ```bash
    AUTH0_URL=https://your-auth0-domain
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret

# Running the Application

1. Start the FastAPI server:
    ```bash
    uvicorn main:server --reload
2. Open your browser and navigate to http://localhost:8000/login to start the authentication process.

# Auth0 Setup
1. Log in to your Auth0 account and create a new application:

    Name: FastAPI SSO

    Application Type: Regular Web Application

2. In the application settings, set the following:

    Allowed Callback URLs: http://localhost:8000/callback

    Allowed Logout URLs: http://localhost:8000

3. Go to the "APIs" section and create a new API (for example):

    Name(example): Renol Orders API

    Identifier(example): https://renol.com/orders/api

4. In the API settings, create permissions as needed.

5. In the "Applications" section, link the "FastAPI SSO" application to the "Renol Orders API".
6. Update your .env file with your Auth0 credentials:
    ```env
    AUTH0_URL=https://your-auth0-domain
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret

# Usage

    /login: Redirects to the Auth0 login page.

    /callback: Handles the Auth0 callback and sets the access token cookie.

    /dashboard: Protected endpoint that displays user information.

    /job-check: Protected endpoint that displays a target address after login.

    /logout: Logs out the user and deletes the access token cookie.