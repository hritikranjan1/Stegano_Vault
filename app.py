from flask import Flask, request, send_file, jsonify, render_template, url_for, session, redirect
import os
import tempfile
import shutil
from PIL import Image
from stegano import lsb
from PyPDF2 import PdfReader, PdfWriter
from docx import Document
from pydub import AudioSegment
import cv2
import hashlib
import numpy as np
from mutagen.mp4 import MP4
import base64
import logging
import uuid
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import json
from werkzeug.utils import secure_filename
import time
from dotenv import load_dotenv
from datetime import datetime
import random
import string
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from functools import wraps
import bcrypt

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'b66fa4bb9e59cdffcbdb0d9d165305fe2f3ef5c58e857985f97d908c6f647ed6')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Serializer for generating tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Google Drive setup
SCOPES = ['https://www.googleapis.com/auth/drive']
GOOGLE_DRIVE_FOLDER_ID = os.environ.get('GOOGLE_DRIVE_FOLDER_ID', '1J-G2PZgqSzrwT-AGAlBX47xBH96T1me-')

# User data files
DATA_DIR = 'data'
USER_REVIEWS_FILE = os.path.join(DATA_DIR, 'user_reviews.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
OTP_STORAGE_FILE = os.path.join(DATA_DIR, 'otp_storage.json')
PASSWORD_RESET_TOKENS = os.path.join(DATA_DIR, 'password_reset_tokens.json')

# Create data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize data files if they don't exist
for file_path in [USER_REVIEWS_FILE, USERS_FILE, OTP_STORAGE_FILE, PASSWORD_RESET_TOKENS]:
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            if file_path == USERS_FILE:
                json.dump([], f, indent=2)
            elif file_path in [OTP_STORAGE_FILE, PASSWORD_RESET_TOKENS]:
                json.dump({}, f, indent=2)
            else:
                json.dump([], f, indent=2)

def format_json_file(file_path):
    """Reformat JSON file to have proper indentation and line breaks"""
    try:
        with open(file_path, 'r+') as f:
            try:
                data = json.load(f)
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
            except json.JSONDecodeError:
                # If file is empty or invalid, write empty structure
                f.seek(0)
                if file_path == USERS_FILE:
                    json.dump([], f, indent=2)
                else:
                    json.dump({}, f, indent=2)
                f.truncate()
    except Exception as e:
        logger.error(f"Error formatting JSON file {file_path}: {e}")

# Format all JSON files on startup
for file_path in [USER_REVIEWS_FILE, USERS_FILE, OTP_STORAGE_FILE, PASSWORD_RESET_TOKENS]:
    format_json_file(file_path)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Helper functions for user management
def get_user_by_email(email):
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
        for user in users:
            if user['email'] == email:
                return user
        return None
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def save_user(user):
    try:
        with open(USERS_FILE, 'r+') as f:
            users = json.load(f)
            users.append(user)
            f.seek(0)
            json.dump(users, f, indent=2)
            f.truncate()
        return True
    except Exception as e:
        logger.error(f"Error saving user: {e}")
        return False

def update_user_password(email, new_password):
    try:
        with open(USERS_FILE, 'r+') as f:
            users = json.load(f)
            updated = False
            for user in users:
                if user['email'] == email:
                    user['password'] = hash_password(new_password)
                    updated = True
                    break
            if updated:
                f.seek(0)
                json.dump(users, f, indent=2)
                f.truncate()
                return True
        return False
    except Exception as e:
        logger.error(f"Error updating user password: {e}")
        return False

def generate_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))
    try:
        with open(OTP_STORAGE_FILE, 'r+') as f:
            try:
                otp_data = json.load(f)
            except json.JSONDecodeError:
                otp_data = {}
                
            otp_data[email] = {
                'otp': otp,
                'timestamp': datetime.now().isoformat(),
                'verified': False
            }
            f.seek(0)
            json.dump(otp_data, f, indent=2)
            f.truncate()
        return otp
    except Exception as e:
        logger.error(f"Error generating OTP: {e}")
        return None

def verify_otp(email, otp):
    try:
        with open(OTP_STORAGE_FILE, 'r') as f:
            try:
                otp_data = json.load(f)
            except json.JSONDecodeError:
                otp_data = {}
        
        if email not in otp_data:
            return False
        
        stored_otp = otp_data[email]
        
        # Check if OTP is expired (5 minutes)
        otp_time = datetime.fromisoformat(stored_otp['timestamp'])
        if (datetime.now() - otp_time).total_seconds() > 300:
            return False
        
        if stored_otp['otp'] == otp:
            otp_data[email]['verified'] = True
            with open(OTP_STORAGE_FILE, 'w') as f:
                json.dump(otp_data, f, indent=2)
            return True
        return False
    except Exception as e:
        logger.error(f"Error verifying OTP: {e}")
        return False

def is_verified(email):
    try:
        with open(OTP_STORAGE_FILE, 'r') as f:
            try:
                otp_data = json.load(f)
            except json.JSONDecodeError:
                otp_data = {}
        return otp_data.get(email, {}).get('verified', False)
    except Exception as e:
        logger.error(f"Error checking verification status: {e}")
        return False

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_password_reset_token(email):
    token = serializer.dumps(email, salt='password-reset-salt')
    try:
        with open(PASSWORD_RESET_TOKENS, 'r+') as f:
            try:
                tokens = json.load(f)
            except json.JSONDecodeError:
                tokens = {}
            tokens[token] = {
                'email': email,
                'timestamp': datetime.now().isoformat()
            }
            f.seek(0)
            json.dump(tokens, f, indent=2)
            f.truncate()
        return token
    except Exception as e:
        logger.error(f"Error generating password reset token: {e}")
        return None

def verify_password_reset_token(token, max_age=3600):
    try:
        with open(PASSWORD_RESET_TOKENS, 'r') as f:
            try:
                tokens = json.load(f)
            except json.JSONDecodeError:
                tokens = {}
        
        if token not in tokens:
            return None
            
        token_data = tokens[token]
        token_time = datetime.fromisoformat(token_data['timestamp'])
        
        # Check if token is expired
        if (datetime.now() - token_time).total_seconds() > max_age:
            return None
            
        # Verify with serializer
        email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        if email == token_data['email']:
            return email
        return None
    except (SignatureExpired, BadTimeSignature):
        return None
    except Exception as e:
        logger.error(f"Error verifying password reset token: {str(e)}")
        return None

# Authentication routes
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data or 'name' not in data:
        return jsonify({'error': 'Name, email and password are required'}), 400
    
    email = data['email'].lower()
    password = data['password']
    name = data['name'].strip()
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    if get_user_by_email(email):
        return jsonify({'error': 'Email already registered'}), 400
    
    # Generate OTP
    otp = generate_otp(email)
    if not otp:
        return jsonify({'error': 'Failed to generate OTP'}), 500
    
    # Send OTP email
    try:
        msg = Message('Your SteganoVault Verification Code',
                      recipients=[email])
        msg.body = f'Your OTP for SteganoVault is: {otp}\nThis code will expire in 5 minutes.'
        mail.send(msg)
        logger.info(f"OTP sent successfully to {email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {str(e)}")
        return jsonify({'error': 'Failed to send OTP email. Please check your email address.'}), 500
    
    return jsonify({'message': 'OTP sent to your email'}), 200

@app.route('/auth/verify', methods=['POST'])
def verify():
    data = request.get_json()
    if not data or 'email' not in data or 'otp' not in data or 'password' not in data or 'name' not in data:
        return jsonify({'error': 'Name, email, OTP and password are required'}), 400
    
    email = data['email'].lower()
    otp = data['otp']
    password = data['password']
    name = data['name']
    
    if not verify_otp(email, otp):
        return jsonify({'error': 'Invalid or expired OTP'}), 400
    
    # Create user account if not exists
    if not get_user_by_email(email):
        user = {
            'name': name,
            'email': email,
            'password': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'verified': True
        }
        if not save_user(user):
            logger.error(f"Failed to save user {email} after OTP verification")
            return jsonify({'error': 'Failed to create user account'}), 500
    
    return jsonify({'message': 'Email verified successfully'}), 200

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    email = data['email'].lower()
    password = data['password']
    
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not check_password(password, user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not is_verified(email):
        return jsonify({'error': 'Email not verified'}), 403
    
    session['user_id'] = user['email']
    return jsonify({
        'message': 'Login successful', 
        'user': {
            'email': user['email'], 
            'name': user.get('name', ''),
            'verified': user.get('verified', False)
        }
    }), 200

@app.route('/auth/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
        return jsonify({
            'message': 'Logged out successfully',
            'notification': 'You have been logged out successfully'
        }), 200
    return jsonify({'error': 'Not logged in'}), 400

@app.route('/auth/status', methods=['GET'])
def auth_status():
    if 'user_id' in session:
        user = get_user_by_email(session['user_id'])
        if user:
            return jsonify({
                'authenticated': True,
                'user': {
                    'name': user.get('name', ''),
                    'email': user['email'],
                    'verified': user.get('verified', False)
                }
            }), 200
    return jsonify({'authenticated': False}), 200

@app.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    email = data['email'].lower()
    user = get_user_by_email(email)
    
    if not user:
        return jsonify({'error': 'Email not found'}), 404
    
    # Generate password reset token
    token = generate_password_reset_token(email)
    if not token:
        return jsonify({'error': 'Failed to generate password reset token'}), 500
    
    reset_link = f"{request.host_url}auth/reset-password?token={token}"
    
    # Send password reset email
    try:
        msg = Message('Password Reset Request',
                      recipients=[email])
        msg.body = f'To reset your password, click the following link:\n\n{reset_link}\n\nThis link will expire in 1 hour.'
        mail.send(msg)
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        return jsonify({'error': 'Failed to send password reset email'}), 500
    
    return jsonify({'message': 'Password reset link sent to your email'}), 200

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or 'token' not in data or 'new_password' not in data:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    token = data['token']
    new_password = data['new_password']
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    # Verify token
    email = verify_password_reset_token(token)
    if not email:
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    # Update password
    if update_user_password(email, new_password):
        # Remove used token
        try:
            with open(PASSWORD_RESET_TOKENS, 'r+') as f:
                tokens = json.load(f)
                if token in tokens:
                    del tokens[token]
                    f.seek(0)
                    json.dump(tokens, f, indent=2)
                    f.truncate()
        except Exception as e:
            logger.error(f"Error removing used token: {e}")
        
        return jsonify({'message': 'Password updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update password'}), 500

# Reviews endpoints
@app.route('/api/reviews', methods=['GET', 'POST'])
def handle_reviews():
    if request.method == 'GET':
        try:
            with open(USER_REVIEWS_FILE, 'r') as f:
                try:
                    reviews = json.load(f)
                except json.JSONDecodeError:
                    reviews = []
            return jsonify(reviews)
        except Exception as e:
            logger.error(f"Error reading reviews: {e}")
            return jsonify([])
    
    elif request.method == 'POST':
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
            
        try:
            data = request.get_json()
            if not data or 'name' not in data or 'text' not in data or 'rating' not in data:
                return jsonify({"error": "Missing required fields"}), 400
            
            user_email = session.get('user_id', 'anonymous')
            user = get_user_by_email(user_email)
            
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            new_review = {
                "name": data['name'],
                "text": data['text'],
                "rating": int(data['rating']),
                "timestamp": datetime.now().isoformat(),
                "verified": True,
                "user_email": user_email,
                "user_name": user.get('name', 'Anonymous')
            }
            
            with open(USER_REVIEWS_FILE, 'r+') as f:
                try:
                    reviews = json.load(f)
                except json.JSONDecodeError:
                    reviews = []
                reviews.append(new_review)
                f.seek(0)
                json.dump(reviews, f, indent=2)
                f.truncate()
            
            return jsonify({
                "status": "success", 
                "review": new_review,
                "message": "Review submitted successfully!"
            })
        except Exception as e:
            logger.error(f"Error saving review: {e}")
            return jsonify({"error": str(e)}), 500

@app.route('/api/reviews/latest')
def get_latest_reviews():
    try:
        with open(USER_REVIEWS_FILE, 'r') as f:
            try:
                reviews = json.load(f)
            except json.JSONDecodeError:
                reviews = []
        
        # Get verified reviews, sorted by newest first
        verified_reviews = [r for r in reviews if r.get('verified', False)]
        verified_reviews.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify(verified_reviews[:10])
    except Exception as e:
        logger.error(f"Error getting latest reviews: {e}")
        return jsonify([])

@app.route('/api/testimonials')
def get_testimonials():
    try:
        with open(USER_REVIEWS_FILE, 'r') as f:
            try:
                reviews = json.load(f)
            except json.JSONDecodeError:
                reviews = []
        
        # Get verified reviews, sorted by newest first
        verified_reviews = [r for r in reviews if r.get('verified', False)]
        verified_reviews.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Combine with default testimonials
        default_testimonials = [
            {
                "name": "Agent X",
                "text": "SteganoVault made hiding messages so fun and easy!",
                "rating": 5
            },
            {
                "name": "Codebreaker Y",
                "text": "A must-have tool for any spy enthusiast!",
                "rating": 5
            },
            {
                "name": "Security Expert Z",
                "text": "The perfect balance of security and usability.",
                "rating": 4
            }
        ]
        
        combined_testimonials = default_testimonials + verified_reviews[:7]
        
        return jsonify(combined_testimonials)
    except Exception as e:
        logger.error(f"Error getting testimonials: {e}")
        return jsonify([])


# File processing functions
def convert_to_png(input_path):
    """Convert image to PNG format."""
    try:
        img = Image.open(input_path).convert("RGB")
        png_path = input_path.rsplit(".", 1)[0] + "_converted.png"
        img.save(png_path, format="PNG", quality=95)
        return png_path
    except Exception as e:
        logger.error(f"Image Conversion Error: {e}")
        return None

def generate_preview(input_path):
    """Generate a preview image for display."""
    try:
        if input_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            img = Image.open(input_path)
            preview_filename = os.path.basename(input_path).replace(".", "_preview.")
            preview_path = os.path.join('static', preview_filename)
            img.thumbnail((300, 300))
            img.save(preview_path, format="PNG", quality=85)
            return preview_filename  # Return just the filename for URL generation
        return None
    except Exception as e:
        logger.error(f"Preview Generation Error: {e}")
        return None

def encode_image(input_path, message, password, watermark=None):
    try:
        if not input_path.lower().endswith(".png"):
            input_path = convert_to_png(input_path)
        if not input_path:
            return None, None
        
        secret_message = f"{password}:{message}" if password else message
        if watermark:
            secret_message = f"{watermark}:{secret_message}"
            
        encoded_img = lsb.hide(input_path, secret_message)
        output_path = input_path.replace(".png", "_encoded.png")
        encoded_img.save(output_path, format="PNG", quality=95)
        
        preview_filename = generate_preview(output_path)
        return output_path, preview_filename
    except Exception as e:
        logger.error(f"Image Encoding Error: {e}")
        return None, None

def decode_image(input_path, password):
    try:
        preview_filename = generate_preview(input_path)
        extracted_message = lsb.reveal(input_path)
        
        if extracted_message:
            if ":" in extracted_message:
                parts = extracted_message.split(":")
                if len(parts) == 3:  # watermark:password:message
                    stored_password, stored_message = parts[1], parts[2]
                else:  # password:message
                    stored_password, stored_message = parts[0], parts[1]
                
                return stored_message if stored_password == password else "Incorrect password!", preview_filename
            return extracted_message, preview_filename
        return "No hidden message found!", preview_filename
    except Exception as e:
        logger.error(f"Image Decoding Error: {e}")
        return f"Error decoding image: {str(e)}", None

def encode_txt(input_path, message, password):
    try:
        with open(input_path, "r", encoding="utf-8") as file:
            original_content = file.read()
        
        secret_message = f"{password}:{message}" if password else message
        binary_data = ''.join(format(ord(c), '08b') for c in secret_message)
        encoded_message = ''.join("\u200B" if bit == "0" else "\u200D" for bit in binary_data)

        output_path = input_path.replace(".", "_encoded.")
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(original_content + "\n" + encoded_message)
        return output_path
    except Exception as e:
        logger.error(f"TXT Encoding Error: {e}")
        return None

def decode_txt(input_path, password):
    try:
        with open(input_path, "r", encoding="utf-8") as file:
            content = file.read()
        
        binary_data = ''.join("0" if char == "\u200B" else "1" for char in content if char in ["\u200B", "\u200D"])
        if not binary_data:
            return "No hidden message found!"
        
        extracted_message = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data) - len(binary_data) % 8, 8))
        
        if extracted_message and ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"TXT Decoding Error: {e}")
        return f"Error decoding text: {str(e)}"

def encode_docx(input_path, message, password):
    try:
        doc = Document(input_path)
        secret_message = f"{password}:{message}" if password else message
        paragraph = doc.add_paragraph()
        run = paragraph.add_run(secret_message)
        run.font.hidden = True
        
        output_path = input_path.replace(".", "_encoded.")
        doc.save(output_path)
        return output_path
    except Exception as e:
        logger.error(f"DOCX Encoding Error: {e}")
        return None

def decode_docx(input_path, password):
    try:
        doc = Document(input_path)
        extracted_message = ""
        for para in doc.paragraphs:
            for run in para.runs:
                if run.font.hidden:
                    extracted_message += run.text
        
        if extracted_message and ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"DOCX Decoding Error: {e}")
        return f"Error decoding DOCX: {str(e)}"

def encode_pdf(input_path, message, password):
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        secret_message = f"{password}:{message}" if password else message
        writer.add_metadata({"/Message": secret_message})
        
        output_path = input_path.replace(".", "_encoded.")
        with open(output_path, "wb") as output_pdf:
            writer.write(output_pdf)
        return output_path
    except Exception as e:
        logger.error(f"PDF Encoding Error: {e}")
        return None

def decode_pdf(input_path, password):
    try:
        reader = PdfReader(input_path)
        metadata = reader.metadata
        extracted_message = metadata.get("/Message", "") if metadata else ""
        
        if extracted_message and ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"PDF Decoding Error: {e}")
        return f"Error decoding PDF: {str(e)}"

def convert_to_wav(input_path):
    try:
        audio = AudioSegment.from_file(input_path)
        wav_path = input_path.rsplit(".", 1)[0] + "_converted.wav"
        audio.export(wav_path, format="wav", codec="pcm_s16le")
        return wav_path
    except Exception as e:
        logger.error(f"Audio Conversion Error: {e}")
        return None

def encode_audio(input_path, message, password):
    try:
        if not input_path.lower().endswith(".wav"):
            input_path = convert_to_wav(input_path)
        if not input_path:
            return None

        secret_message = f"{password}:{message}" if password else message
        message_bytes = secret_message.encode('utf-8')
        message_length = len(message_bytes)
        binary_length = format(message_length, '032b')
        binary_message = binary_length + ''.join(format(byte, '08b') for byte in message_bytes)

        audio = AudioSegment.from_file(input_path, format="wav")
        samples = audio.get_array_of_samples()
        if len(binary_message) > len(samples):
            return None

        samples_array = np.array(samples, dtype=np.int16)
        for i in range(len(binary_message)):
            samples_array[i] = (samples_array[i] & ~1) | int(binary_message[i])

        encoded_audio = audio._spawn(samples_array.tobytes())
        output_path = input_path.replace(".wav", "_encoded.wav")
        encoded_audio.export(output_path, format="wav", codec="pcm_s16le")
        return output_path
    except Exception as e:
        logger.error(f"Audio Encoding Error: {e}")
        return None

def decode_audio(input_path, password):
    try:
        if not input_path.lower().endswith(".wav"):
            input_path = convert_to_wav(input_path)
        if not input_path:
            return "Error decoding audio!"

        audio = AudioSegment.from_file(input_path, format="wav")
        samples = np.array(audio.get_array_of_samples(), dtype=np.int16)

        binary_length = ''.join(str(sample & 1) for sample in samples[:32])
        message_length = int(binary_length, 2)

        binary_message = ''.join(str(sample & 1) for sample in samples[32:32 + message_length * 8])
        message_bytes = bytes(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message) - len(binary_message) % 8, 8))
        extracted_message = message_bytes.decode('utf-8')

        if extracted_message and ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"Audio Decoding Error: {e}")
        return f"Error decoding audio: {str(e)}"

def encode_video(input_path, message, password):
    try:
        cap = cv2.VideoCapture(input_path)
        if not cap.isOpened():
            raise ValueError("Could not open input video file")
        cap.release()

        secret_message = f"{password}:{message}" if password else message
        encoded_message = base64.b64encode(secret_message.encode('utf-8')).decode('utf-8')

        output_path = input_path.replace(".", "_encoded.")
        shutil.copy2(input_path, output_path)

        video = MP4(output_path)
        video['desc'] = encoded_message
        video.save()

        test_cap = cv2.VideoCapture(output_path)
        if not test_cap.isOpened():
            raise ValueError("Encoded video file is corrupted")
        test_cap.release()

        return output_path
    except Exception as e:
        logger.error(f"Video Encoding Error: {e}")
        return None

def decode_video(input_path, password):
    try:
        cap = cv2.VideoCapture(input_path)
        if not cap.isOpened():
            raise ValueError("Could not open video file")
        cap.release()

        video = MP4(input_path)
        if 'desc' not in video:
            return "No hidden message found!"

        encoded_message = video['desc'][0]
        decoded_bytes = base64.b64decode(encoded_message.encode('utf-8'))
        extracted_message = decoded_bytes.decode('utf-8')

        if ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"Video Decoding Error: {e}")
        return f"Error decoding video: {str(e)}"

def get_drive_service():
    """Initialize Google Drive API service with service account credentials."""
    credentials_json = os.environ.get('GOOGLE_CREDENTIALS')
    if not credentials_json:
        logger.error("GOOGLE_CREDENTIALS environment variable not set")
        return None
    
    try:
        credentials_info = json.loads(credentials_json)
        credentials = service_account.Credentials.from_service_account_info(
            credentials_info,
            scopes=SCOPES
        )
        return build('drive', 'v3', credentials=credentials)
    except Exception as e:
        logger.error(f"Error initializing Drive service: {str(e)}")
        return None

def upload_to_drive(file_path, file_name):
    """Upload a file to Google Drive and return its public URL with ?usp=drivesdk."""
    drive_service = get_drive_service()
    if not drive_service:
        logger.error("Drive service not initialized")
        return None
    
    try:
        file_metadata = {
            'name': file_name,
            'parents': [GOOGLE_DRIVE_FOLDER_ID]
        }
        media = MediaFileUpload(file_path)
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, webViewLink'
        ).execute()
        drive_service.permissions().create(
            fileId=file['id'],
            body={'role': 'reader', 'type': 'anyone'}
        ).execute()
        # Modify the webViewLink to use ?usp=drivesdk instead of ?usp=sharing
        share_url = file['webViewLink'].replace('usp=sharing', 'usp=drivesdk')
        return share_url
    except Exception as e:
        logger.error(f"Failed to upload to Google Drive: {str(e)}")
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encode", methods=["POST"])
def encode():
    if 'file' not in request.files:
        return jsonify({
            "error": "No file uploaded",
            "status": "error"
        }), 400
    
    uploaded_file = request.files['file']
    message = request.form.get("message")
    password = request.form.get("password", "")
    watermark = request.form.get("watermark", "")

    if not message:
        return jsonify({
            "error": "Message is required!",
            "status": "error"
        }), 400

    filename = secure_filename(uploaded_file.filename)
    if not filename:
        return jsonify({
            "error": "Invalid filename!",
            "status": "error"
        }), 400

    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    uploaded_file.save(file_path)

    ext = os.path.splitext(file_path)[1].lower()
    output_file = None
    preview_file = None

    try:
        start_time = time.time()
        
        if ext in [".png", ".jpg", ".jpeg"]:
            output_file, preview_file = encode_image(file_path, message, password, watermark)
        elif ext == ".txt":
            output_file = encode_txt(file_path, message, password)
        elif ext == ".pdf":
            output_file = encode_pdf(file_path, message, password)
        elif ext == ".docx":
            output_file = encode_docx(file_path, message, password)
        elif ext in [".wav", ".mp3"]:
            output_file = encode_audio(file_path, message, password)
        elif ext in [".mp4", ".avi", ".mov"]:
            output_file = encode_video(file_path, message, password)
        else:
            return jsonify({
                "error": "Unsupported file format!",
                "status": "error"
            }), 400

        if output_file and os.path.exists(output_file):
            processing_time = round(time.time() - start_time, 2)
            
            unique_id = str(uuid.uuid4())
            final_filename = f"encoded_{unique_id}_{os.path.basename(output_file)}"
            share_url = upload_to_drive(output_file, final_filename)

            with open(output_file, "rb") as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
            
            response_data = {
                "status": "success",
                "filename": final_filename,
                "checksum": checksum,
                "processing_time": processing_time,
                "preview_url": url_for('static', filename=preview_file) if preview_file else None,
                "share_url": share_url if share_url else None
            }

            response = send_file(output_file, as_attachment=True, download_name=final_filename)
            response.headers["X-Response-Data"] = json.dumps(response_data)
            return response
        
        return jsonify({
            "error": "Failed to encode file!",
            "status": "error"
        }), 500
    except Exception as e:
        logger.error(f"Encode Endpoint Error: {e}")
        return jsonify({
            "error": f"Encoding failed: {str(e)}",
            "status": "error"
        }), 500
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.route("/decode", methods=["POST"])
def decode():
    if 'file' not in request.files:
        return jsonify({
            "error": "No file uploaded",
            "status": "error"
        }), 400
    
    uploaded_file = request.files['file']
    password = request.form.get("password", "")

    filename = secure_filename(uploaded_file.filename)
    if not filename:
        return jsonify({
            "error": "Invalid filename!",
            "status": "error"
        }), 400

    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, filename)
    uploaded_file.save(file_path)

    ext = os.path.splitext(file_path)[1].lower()
    decoded_message = None
    preview_file = None

    try:
        start_time = time.time()
        
        if ext in [".png", ".jpg", ".jpeg"]:
            decoded_message, preview_file = decode_image(file_path, password)
        elif ext == ".txt":
            decoded_message = decode_txt(file_path, password)
        elif ext == ".pdf":
            decoded_message = decode_pdf(file_path, password)
        elif ext == ".docx":
            decoded_message = decode_docx(file_path, password)
        elif ext in [".wav", ".mp3"]:
            decoded_message = decode_audio(file_path, password)
        elif ext in [".mp4", ".avi", ".mov"]:
            decoded_message = decode_video(file_path, password)
        else:
            return jsonify({
                "error": "Unsupported file format!",
                "status": "error"
            }), 400

        processing_time = round(time.time() - start_time, 2)
        
        return jsonify({
            "status": "success",
            "message": decoded_message,
            "preview_url": url_for('static', filename=preview_file) if preview_file else None,
            "processing_time": processing_time
        })
    except Exception as e:
        logger.error(f"Decode Endpoint Error: {e}")
        return jsonify({
            "error": f"Failed to decode file: {str(e)}",
            "status": "error"
        }), 500
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.route('/privacy')
def privacy():
    return jsonify({
        "privacy_policy": "SteganoVault does not store any of your files or messages. All processing happens in your browser and files are deleted immediately after processing. We respect your privacy!"
    })

if __name__ == "__main__":
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    logger.info("Starting SteganoVault server...")
    
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)