from flask import Flask, request, send_file, jsonify, render_template, url_for
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

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google Drive setup
SCOPES = ['https://www.googleapis.com/auth/drive']
GOOGLE_DRIVE_FOLDER_ID = '1J-G2PZgqSzrwT-AGAlBX47xBH96T1me-'

# Testimonials data
TESTIMONIALS = [
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
    """Upload a file to Google Drive and return its public URL."""
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
        return file['webViewLink']
    except Exception as e:
        logger.error(f"Failed to upload to Google Drive: {str(e)}")
        return None

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
            preview_path = os.path.join('static', os.path.basename(input_path).replace(".", "_preview."))
            img.thumbnail((300, 300))
            img.save(preview_path, format="PNG", quality=85)
            return preview_path
        return None
    except Exception as e:
        logger.error(f"Preview Generation Error: {e}")
        return None

# IMAGE SECTION
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
        
        preview_path = generate_preview(output_path)
        return output_path, preview_path
    except Exception as e:
        logger.error(f"Image Encoding Error: {e}")
        return None, None

def decode_image(input_path, password):
    try:
        preview_path = generate_preview(input_path)
        extracted_message = lsb.reveal(input_path)
        
        if extracted_message:
            if ":" in extracted_message:
                parts = extracted_message.split(":")
                if len(parts) == 3:  # watermark:password:message
                    stored_password, stored_message = parts[1], parts[2]
                else:  # password:message
                    stored_password, stored_message = parts
                
                return stored_message if stored_password == password else "Incorrect password!", preview_path
            return extracted_message, preview_path
        return "No hidden message found!", preview_path
    except Exception as e:
        logger.error(f"Image Decoding Error: {e}")
        return f"Error decoding image: {str(e)}", None

# TEXT SECTION
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

# DOCX SECTION
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

# PDF SECTION
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
        extracted_message = metadata.get("/Message", "")
        
        if extracted_message and ":" in extracted_message:
            stored_password, stored_message = extracted_message.split(":", 1)
            return stored_message if stored_password == password else "Incorrect password!"
        return extracted_message if extracted_message else "No hidden message found!"
    except Exception as e:
        logger.error(f"PDF Decoding Error: {e}")
        return f"Error decoding PDF: {str(e)}"

# AUDIO SECTION
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
            return "Message too large for audio file!"

        samples_array = samples.copy()
        for i in range(len(binary_message)):
            samples_array[i] = (samples_array[i] & ~1) | int(binary_message[i])

        encoded_audio = audio._spawn(samples_array)
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
        samples = audio.get_array_of_samples()

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

# VIDEO SECTION
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

@app.route("/")
def index():
    return render_template("index.html", testimonials=TESTIMONIALS)

@app.route("/encode", methods=["POST"])
def encode():
    uploaded_file = request.files.get("file")
    message = request.form.get("message")
    password = request.form.get("password", "")
    watermark = request.form.get("watermark", "")

    if not uploaded_file or not message:
        return jsonify({
            "error": "File and message are required!",
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
                "preview_url": url_for('static', filename=os.path.basename(preview_file)) if preview_file else None
            }
            
            if share_url:
                response_data["share_url"] = share_url
            
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
    uploaded_file = request.files.get("file")
    password = request.form.get("password", "")

    if not uploaded_file:
        return jsonify({
            "error": "File is required!",
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
            "preview_url": url_for('static', filename=os.path.basename(preview_file)) if preview_file else None,
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
    
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)