# Secure Messaging Flask App

This is a secure messaging web application built with Flask. The application allows users to register, login, and send encrypted messages to each other. The messages are encrypted using RSA and AES encryption algorithms to ensure secure communication.

## Prerequisites

- Python 3.6 or higher
- Flask
- Flask-WTF
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-Login
- cryptography

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/oussamaafnakkar/flash.git
    cd flash
    ```

2. **Create a virtual environment**:
    ```bash
    python -m venv venv
    ```

3. **Activate the virtual environment**:

    On Windows:
    ```bash
    venv\Scripts\activate
    ```

    On macOS/Linux:
    ```bash
    source venv/bin/activate
    ```

4. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

1. **Set up environment variables**:
    Create a `.env` file in the root directory and add the following:
    ```plaintext
    SECRET_KEY=your_secret_key
    ```

2. **Initialize the database**:
    ```bash
    flask db init
    flask db migrate
    flask db upgrade
    ```

## Running the Application

1. **Run the Flask application**:
    ```bash
    flask run
    ```

2. Open a web browser and navigate to `http://127.0.0.1:5000` to see the application in action.

## Features

- User registration and login
- Secure messaging with RSA and AES encryption
- Message inbox for viewing received messages
- User dashboard

## Screenshots

![Main Page](static/flash_logo.png)

## Acknowledgements

- Flask
- Flask-WTF
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-Login
- cryptography

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contact

If you have any questions, feel free to contact me at [oussamaafnakkar2002@gmail.com].
