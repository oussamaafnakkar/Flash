import os
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, RegistrationForm, MessageForm
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from extensions import db
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)

from models import User, Message

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'danger')
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match.', 'danger')
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)

            # Generate RSA keys
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            # Serialize and encrypt the private key
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=BestAvailableEncryption(bytes(app.config['SECRET_KEY'], 'utf-8'))
            )

            # Serialize the public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            user.public_key = public_key_bytes
            user.private_key = private_key_bytes

            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    form = MessageForm()
    if form.validate_on_submit():
        recipient = User.query.filter_by(username=form.recipient_username.data).first()
        if recipient:
            try:
                # Generate AES key and IV
                aes_key = os.urandom(32)  # 256-bit key
                iv = os.urandom(16)  # 128-bit IV

                # Encrypt the message using AES
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_message = encryptor.update(form.message.data.encode()) + encryptor.finalize()

                # Encrypt the AES key using RSA
                public_key = serialization.load_pem_public_key(recipient.public_key)
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Store the encrypted message, encrypted AES key, and IV in the database
                message = Message(sender_id=current_user.id, recipient_id=recipient.id, content=encrypted_message, aes_key=encrypted_aes_key, iv=iv, timestamp=datetime.utcnow())
                db.session.add(message)
                db.session.commit()
                flash('Message sent!', 'success')
            except Exception as e:
                flash(f'Encryption failed: {str(e)}', 'danger')
        else:
            flash('Recipient not found.', 'danger')
    return render_template('messages.html', form=form, user=current_user)

@app.route('/inbox')
@login_required
def inbox():
    try:
        messages = db.session.query(Message, User.username).join(User, Message.sender_id == User.id)\
            .filter(Message.recipient_id == current_user.id)\
            .order_by(Message.timestamp.desc()).all()  # Order by timestamp in descending order

        decrypted_messages = []

        private_key = serialization.load_pem_private_key(
            current_user.private_key,
            password=bytes(app.config['SECRET_KEY'], 'utf-8'),
            backend=default_backend()
        )

        for message, sender_username in messages:
            try:
                aes_key = private_key.decrypt(
                    message.aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(message.iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(message.content) + decryptor.finalize()

                decrypted_messages.append({
                    'content': decrypted_message.decode('utf-8'),
                    'sender': sender_username
                })
            except Exception as e:
                app.logger.error(f"Error decrypting message content: {e}")
                flash(f"There was an error decrypting a message from {sender_username}.", 'danger')

    except Exception as e:
        app.logger.error(f"Error loading private key: {e}")
        flash('There was an error decrypting your messages.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('inbox.html', messages=decrypted_messages)

if __name__ == '__main__':
    app.run(debug=True)

