# Stegano_Vault
# Steganography Tool - Hide and Extract Secret Messages in Files

This project is a **Flask-based web application** that allows users to hide and extract secret messages in various file formats (images, text files, PDFs, DOCX files, audio, and video) using **steganography** techniques. The tool supports password protection for added security.

---

## Features

- **Encode Messages**:
  - Hide secret messages in:
    - Images (PNG, JPG, JPEG)
    - Text files (TXT)
    - PDFs
    - DOCX files
    - Audio files (WAV, MP3)
    - Video files (MP4, AVI, MOV)
  - Optional password protection for encoded messages.

- **Decode Messages**:
  - Extract hidden messages from encoded files.
  - Password verification for protected messages.

- **Supported File Formats**:
  - Images: PNG, JPG, JPEG
  - Text: TXT
  - Documents: PDF, DOCX
  - Audio: WAV, MP3
  - Video: MP4, AVI, MOV

---

## Installation

### Prerequisites

- Python 3.7 or higher
- Pip (Python package manager)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/hritikranjan1/SteganoVault.git
   cd SteganoVault

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```

4. **Access the Application**:
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## Usage

### Encoding a Message

1. **Select a File**:
   - Choose a file (image, text, PDF, DOCX, audio, or video) from your computer.

2. **Enter a Message**:
   - Type the secret message you want to hide in the file.

3. **Set a Password** (Optional):
   - Add a password to protect the hidden message.

4. **Encode**:
   - Click the "Encode" button. The encoded file will be downloaded automatically.

### Decoding a Message

1. **Upload an Encoded File**:
   - Choose the file that contains the hidden message.

2. **Enter the Password** (if applicable):
   - If the message was password-protected, enter the password.

3. **Decode**:
   - Click the "Decode" button. The hidden message will be displayed on the screen.

---

## Supported File Formats and Techniques

| File Type | Encoding Technique                          | Decoding Technique                          |
|-----------|---------------------------------------------|---------------------------------------------|
| Image     | LSB (Least Significant Bit) Steganography   | LSB Extraction                              |
| Text      | Zero-Width Character Steganography          | Zero-Width Character Extraction             |
| PDF       | Metadata Embedding                          | Metadata Extraction                         |
| DOCX      | Hidden Text Formatting                      | Hidden Text Extraction                      |
| Audio     | LSB Steganography (WAV only)                | LSB Extraction                              |
| Video     | LSB Steganography (Blue Channel)            | LSB Extraction                              |

---

## Project Structure

```
SteganoVault/
├── app.py                  # Main Flask application
├── requirements.txt        # List of dependencies
├── README.md               # Project documentation
├── templates/              # HTML templates
│   └── index.html          # Main UI template
└── static/                 # Static files (CSS, JS, etc.)
```

---

## Dependencies

- Flask: Web framework
- Pillow: Image processing
- stegano: LSB steganography for images
- PyPDF2: PDF metadata manipulation
- python-docx: DOCX file manipulation
- pydub: Audio file processing
- opencv-python: Video file processing
- numpy: Numerical operations for video processing

---

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

## Acknowledgments

- Inspired by steganography techniques and tools.
- Built with Flask and Python.
