Overview of My Flask Application: Flash

I am excited to share my latest project, Flash, a secure messaging application built using Flask. This project showcases my skills in web development, encryption techniques, and user authentication. Below is a detailed overview of the app and its features:
Flash: A Secure Messaging Application

Description:
Flash is a secure messaging application designed to provide encrypted communication between users. The app leverages modern encryption techniques to ensure that messages are kept private and secure from unauthorized access.

Key Features:

    User Authentication:
        Registration and login functionality with secure password hashing using werkzeug.security.
        User authentication managed by Flask-Login.

    Message Encryption:
        Utilizes RSA and AES encryption to secure messages.
        RSA key pairs (public and private) are generated for each user upon registration.
        Messages are encrypted using AES encryption, and the AES key is encrypted with the recipient's RSA public key before storage.

    User Dashboard:
        A personalized dashboard for users to manage their messages.
        Users can send and receive messages through a simple and intuitive interface.

    Inbox Management:
        Users can view their received messages in a secure inbox.
        Messages are decrypted using the user's private RSA key upon retrieval.

    Responsive Design:
        The application features a modern and responsive design using Bootstrap.

Technology Stack:

    Backend:
        Flask: A lightweight WSGI web application framework.
        SQLAlchemy: ORM for database management.
        Flask-Migrate: Handling database migrations.
        Flask-WTF: For form validation and CSRF protection.
        Flask-Login: For user session management.

    Frontend:
        HTML/CSS: For structuring and styling the web pages.
        Bootstrap: For responsive and modern UI components.

    Encryption:
        cryptography library: For implementing RSA and AES encryption.
        RSA (Rivest-Shamir-Adleman): Public-key cryptosystem for secure data transmission.
        AES (Advanced Encryption Standard): Symmetric encryption algorithm for encrypting message content.

How It Works:

    Registration:
        Users register with a username, email, and password.
        RSA keys (public and private) are generated and securely stored.

    Sending Messages:
        Users compose a message and select a recipient.
        The message is encrypted using AES encryption, and the AES key is encrypted with the recipient's RSA public key.
        The encrypted message, AES key, and initialization vector (IV) are stored in the database.

    Receiving Messages:
        Users access their inbox to view received messages.
        The app decrypts the AES key using the user's private RSA key, and then decrypts the message content using the AES key.

Flash represents a robust solution for secure communication, leveraging strong encryption standards to ensure user privacy and data security. I am proud of the work that went into developing this application and am excited to continue exploring advancements in secure communication technologies.

Feel free to connect with me to learn more about this project or discuss potential collaborations!
