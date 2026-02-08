#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
import os
import uuid
from datetime import datetime, timedelta
import io
import base64
from functools import wraps
import mimetypes
import unicodedata
import re
import requests
from PIL import Image
import tempfile
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

app = Flask(__name__)
CORS(app)

# Configuration
PRIMARY_API_KEY = os.environ.get('PRIMARY_API_KEY', 'pk_live_mega_converter_primary_key_2024_super_secure_token_xyz789')
SECONDARY_API_KEY = os.environ.get('SECONDARY_API_KEY', 'sk_live_mega_converter_secondary_key_2024_ultra_secure_token_abc456')

# NOUVELLES LIMITES PLUS GRANDES
MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 500 * 1024 * 1024))  # 500MB par défaut
MAX_IMAGE_SIZE = int(os.environ.get('MAX_IMAGE_SIZE', 1000 * 1024 * 1024))  # 1GB pour images
AUTO_COMPRESS_IMAGES = os.environ.get('AUTO_COMPRESS_IMAGES', 'true').lower() == 'true'
MAX_IMAGE_DIMENSION = int(os.environ.get('MAX_IMAGE_DIMENSION', 80000))  # 80000px max par côté

FILE_EXPIRY_HOURS = int(os.environ.get('FILE_EXPIRY_HOURS', 24))
BASE_URL = os.environ.get('BASE_URL', 'https://pdf-converter-server-production.up.railway.app')

# PostgreSQL Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable is required!")

# Créer le pool de connexions PostgreSQL
try:
    db_pool = SimpleConnectionPool(1, 10, DATABASE_URL)
    print("[DB] PostgreSQL connection pool created successfully")
except Exception as e:
    print(f"[ERROR] Failed to create database pool: {e}")
    raise

# Tous les formats acceptés
ALLOWED_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'svg', 'tiff', 'tif',
    # Documents
    'pdf', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
    # Web
    'html', 'htm', 'css', 'js', 'json', 'xml',
    # Fichiers
    'csv', 'md', 'rtf', 'tex',
    # Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    # Vidéos
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv', 'm4v',
    # Audio
    'mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a',
    # Autres
    'exe', 'dmg', 'apk', 'deb', 'rpm'
}

IMAGE_FORMATS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif'}

def get_db_connection():
    """Obtenir une connexion depuis le pool"""
    return db_pool.getconn()

def release_db_connection(conn):
    """Remettre la connexion dans le pool"""
    db_pool.putconn(conn)

def init_database():
    """Initialiser la base de données avec la table files"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id VARCHAR(255) PRIMARY KEY,
                content BYTEA NOT NULL,
                filename VARCHAR(500) NOT NULL,
                original_filename VARCHAR(500),
                content_type VARCHAR(255),
                expiry TIMESTAMP NOT NULL,
                created TIMESTAMP DEFAULT NOW(),
                size_bytes BIGINT,
                was_compressed BOOLEAN DEFAULT FALSE,
                metadata JSONB
            )
        """)
        
        # Index pour nettoyer les fichiers expirés
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_files_expiry ON files(expiry)
        """)
        
        conn.commit()
        print("[DB] Database initialized successfully")
    except Exception as e:
        print(f"[ERROR] Database initialization failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        release_db_connection(conn)

def sanitize_filename(filename):
    """Nettoie le nom de fichier pour éviter les problèmes"""
    if '.' in filename:
        name, ext = filename.rsplit('.', 1)
    else:
        name, ext = filename, ''
    
    name = unicodedata.normalize('NFKD', name)
    name = ''.join([c for c in name if not unicodedata.combining(c)])
    name = re.sub(r'[^\w\s-]', '', name)
    name = re.sub(r'[-\s]+', '_', name)
    name = name[:50]
    
    if ext:
        return f"{name}.{ext}"
    return name

def compress_image(image_content, filename, quality=85, max_dimension=None):
    """Compresse une image pour réduire sa taille"""
    try:
        print(f"[COMPRESS] Tentative de compression: {filename}")
        
        # Ouvrir l'image
        img = Image.open(io.BytesIO(image_content))
        original_format = img.format or 'PNG'
        original_size = len(image_content)
        
        print(f"[COMPRESS] Format: {original_format}, Taille: {img.size}, {original_size/1024/1024:.2f}MB")
        
        # Redimensionner si trop grande
        if max_dimension:
            width, height = img.size
            if width > max_dimension or height > max_dimension:
                ratio = min(max_dimension / width, max_dimension / height)
                new_size = (int(width * ratio), int(height * ratio))
                print(f"[COMPRESS] Redimensionnement de {img.size} vers {new_size}")
                img = img.resize(new_size, Image.Resampling.LANCZOS)
        
        # Convertir en RGB si nécessaire (pour JPEG)
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        
        # Sauvegarder compressé
        output = io.BytesIO()
        save_format = 'JPEG' if original_format in ('JPEG', 'JPG') else 'PNG'
        
        if save_format == 'JPEG':
            img.save(output, format=save_format, quality=quality, optimize=True)
        else:
            img.save(output, format=save_format, optimize=True, compress_level=9)
        
        compressed_content = output.getvalue()
        compressed_size = len(compressed_content)
        
        compression_ratio = (1 - compressed_size / original_size) * 100
        print(f"[COMPRESS] Compressé: {compressed_size/1024/1024:.2f}MB (gain: {compression_ratio:.1f}%)")
        
        # Retourner la version compressée seulement si gain > 10%
        if compression_ratio > 10:
            return compressed_content, True
        else:
            print(f"[COMPRESS] Compression insuffisante, garde l'original")
            return image_content, False
            
    except Exception as e:
        print(f"[COMPRESS] Erreur compression: {e}")
        return image_content, False

def cleanup_old_files():
    """Nettoie les fichiers expirés de la base de données"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM files WHERE expiry < NOW()
            RETURNING id
        """)
        deleted = cursor.fetchall()
        conn.commit()
        if deleted:
            print(f"[DELETE] {len(deleted)} fichiers expirés supprimés")
    except Exception as e:
        print(f"[ERROR] Cleanup failed: {e}")
        conn.rollback()
    finally:
        cursor.close()
        release_db_connection(conn)

def require_api_key(f):
    """Vérification des clés API"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            api_key = request.args.get('api_key')
        if not api_key and request.form:
            api_key = request.form.get('api_key')
        
        if api_key not in [PRIMARY_API_KEY, SECONDARY_API_KEY]:
            return jsonify({
                "error": "Clé API invalide ou manquante",
                "message": "Utilisez une des deux clés API valides"
            }), 401
        
        request.api_key_type = "primary" if api_key == PRIMARY_API_KEY else "secondary"
        return f(*args, **kwargs)
    return decorated_function

def store_file(content, filename, content_type=None, metadata=None):
    """Stocke n'importe quel fichier dans PostgreSQL et retourne une URL"""
    cleanup_old_files()
    
    file_id = str(uuid.uuid4())
    expiry = datetime.now() + timedelta(hours=FILE_EXPIRY_HOURS)
    
    clean_filename = sanitize_filename(filename)
    print(f"[INFO] Nom original: {filename}")
    print(f"[INFO] Nom nettoye: {clean_filename}")
    
    if not content_type:
        content_type = mimetypes.guess_type(clean_filename)[0] or 'application/octet-stream'
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Convertir metadata en JSON si présent
        import json
        metadata_json = json.dumps(metadata) if metadata else None
        
        cursor.execute("""
            INSERT INTO files (id, content, filename, original_filename, content_type, expiry, size_bytes, was_compressed, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            file_id,
            psycopg2.Binary(content) if isinstance(content, bytes) else content,
            clean_filename,
            filename,
            content_type,
            expiry,
            len(content) if isinstance(content, bytes) else 0,
            metadata.get('was_compressed', False) if metadata else False,
            metadata_json
        ))
        
        conn.commit()
        print(f"[DB] File stored: {file_id}")
        
    except Exception as e:
        print(f"[ERROR] Store file failed: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        release_db_connection(conn)
    
    return f"{BASE_URL}/download/{file_id}"

def get_file_extension(filename):
    if not filename or '.' not in filename:
        return None
    return filename.rsplit('.', 1)[1].lower()

# ===== ROUTES =====

@app.route('/')
def home():
    """Page d'accueil"""
    cleanup_old_files()
    
    return jsonify({
        "service": "[FILE] Storage API - PostgreSQL Backend",
        "version": "3.0",
        "status": "[OK] Operationnel",
        "description": "Upload de fichiers avec stockage PostgreSQL persistant",
        "storage": "PostgreSQL (persistent)",
        "features": {
            "large_files": f"[OK] Jusqu'a {MAX_FILE_SIZE/(1024*1024)}MB",
            "huge_images": f"[OK] Images jusqu'a {MAX_IMAGE_SIZE/(1024*1024)}MB",
            "auto_compress": f"[{'OK' if AUTO_COMPRESS_IMAGES else 'OFF'}] Compression auto images",
            "max_dimension": f"[OK] Max {MAX_IMAGE_DIMENSION}px par côté",
            "expiry": f"[OK] Fichiers expires apres {FILE_EXPIRY_HOURS}h"
        },
        "endpoints": {
            "/": "Informations sur le service",
            "/convert": "[POST] Convertir HTML en PDF",
            "/upload": "[POST] Upload un fichier",
            "/upload-from-url": "[POST] Upload depuis une URL",
            "/download/<file_id>": "[GET] Telecharger un fichier",
            "/info/<file_id>": "[GET] Infos sur un fichier",
            "/status": "[GET] Statut du service"
        }
    })

@app.route('/convert', methods=['POST'])
@require_api_key
def convert_html_to_pdf():
    """Convertit HTML en PDF"""
    try:
        data = request.get_json()
        
        if not data or 'html' not in data:
            return jsonify({"error": "HTML content required"}), 400
        
        html_content = data['html']
        filename = data.get('filename', 'document.pdf')
        return_binary = data.get('return_binary', False)
        
        # Importer pdfkit seulement si nécessaire
        try:
            import pdfkit
        except ImportError:
            return jsonify({"error": "pdfkit not installed"}), 500
        
        # Configuration pdfkit
        options = {
            'page-size': 'A4',
            'encoding': 'UTF-8',
            'enable-local-file-access': None
        }
        
        # Convertir HTML en PDF
        pdf_content = pdfkit.from_string(html_content, False, options=options)
        
        if not filename.endswith('.pdf'):
            filename = f"{filename}.pdf"
        
        # Retour binaire direct si demandé
        if return_binary:
            return Response(
                pdf_content,
                mimetype='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename="{sanitize_filename(filename)}"',
                    'Content-Length': str(len(pdf_content))
                }
            )
        
        # Stocker dans PostgreSQL
        download_url = store_file(pdf_content, filename, 'application/pdf')
        
        return jsonify({
            "success": True,
            "filename": sanitize_filename(filename),
            "download_url": download_url,
            "file_id": download_url.split('/')[-1],
            "format": "pdf",
            "size_bytes": len(pdf_content),
            "size_mb": round(len(pdf_content) / (1024 * 1024), 2),
            "content_type": "application/pdf",
            "uploaded_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=FILE_EXPIRY_HOURS)).isoformat(),
            "expiry_hours": FILE_EXPIRY_HOURS,
            "message": "[OK] Fichier uploadé! URL valide pendant 24h"
        })
        
    except Exception as e:
        print(f"[ERROR] convert: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/upload', methods=['POST'])
@require_api_key
def upload():
    """Upload un fichier"""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        filename = file.filename
        content = file.read()
        
        file_ext = get_file_extension(filename)
        is_image = file_ext in IMAGE_FORMATS
        max_size = MAX_IMAGE_SIZE if is_image else MAX_FILE_SIZE
        
        if len(content) > max_size:
            return jsonify({
                "error": "Fichier trop volumineux",
                "file_size_mb": round(len(content) / (1024 * 1024), 2),
                "max_size_mb": round(max_size / (1024 * 1024), 2)
            }), 413
        
        content_type = file.content_type or 'application/octet-stream'
        
        # Compression auto si image volumineuse
        was_compressed = False
        compression_info = {}
        original_size = len(content)
        
        if is_image and AUTO_COMPRESS_IMAGES and original_size > 5 * 1024 * 1024:
            content, was_compressed = compress_image(content, filename, max_dimension=MAX_IMAGE_DIMENSION)
            if was_compressed:
                compression_info = {
                    "compressed": True,
                    "original_size_mb": round(original_size / (1024 * 1024), 2),
                    "compressed_size_mb": round(len(content) / (1024 * 1024), 2),
                    "compression_ratio": round((1 - len(content) / original_size) * 100, 1)
                }
        
        # Stocker
        metadata = {'was_compressed': was_compressed}
        if compression_info:
            metadata['compression_info'] = compression_info
        
        download_url = store_file(content, filename, content_type, metadata)
        
        result = {
            "success": True,
            "filename": sanitize_filename(filename),
            "download_url": download_url,
            "file_id": download_url.split('/')[-1],
            "format": file_ext or "unknown",
            "size_bytes": len(content),
            "size_mb": round(len(content) / (1024 * 1024), 2),
            "content_type": content_type,
            "uploaded_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=FILE_EXPIRY_HOURS)).isoformat()
        }
        
        if was_compressed:
            result["compression"] = compression_info
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[ERROR] upload: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/upload-from-url', methods=['POST'])
@require_api_key
def upload_from_url():
    """Upload un fichier depuis une URL"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({"error": "URL requise"}), 400
        
        file_url = data['url']
        return_binary = data.get('return_binary', False)
        
        if not file_url.startswith(('http://', 'https://')):
            return jsonify({"error": "URL invalide"}), 400
        
        print(f"[URL] Telechargement: {file_url}")
        
        # Télécharger
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(file_url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        
        # Nom du fichier
        filename = 'download'
        if 'content-disposition' in response.headers:
            match = re.search(r'filename[^;=\n]*=([\'\"]?)([^\'\"\n]*)\1', response.headers['content-disposition'])
            if match:
                filename = match.group(2)
        
        if filename == 'download':
            url_path = file_url.split('?')[0]
            url_filename = url_path.split('/')[-1]
            if url_filename and '.' in url_filename:
                filename = url_filename
        
        if 'filename' in data and data['filename']:
            filename = data['filename']
        
        # Lire le contenu
        content = response.content
        file_ext = get_file_extension(filename)
        is_image = file_ext in IMAGE_FORMATS
        max_size = MAX_IMAGE_SIZE if is_image else MAX_FILE_SIZE
        
        if len(content) > max_size:
            return jsonify({
                "error": "Fichier trop volumineux",
                "file_size_mb": round(len(content) / (1024 * 1024), 2),
                "max_size_mb": round(max_size / (1024 * 1024), 2)
            }), 413
        
        content_type = response.headers.get('content-type', 'application/octet-stream')
        
        # Retour binaire direct si demandé
        if return_binary:
            return Response(
                content,
                mimetype=content_type,
                headers={
                    'Content-Disposition': f'attachment; filename="{sanitize_filename(filename)}"',
                    'Content-Length': str(len(content))
                }
            )
        
        # Compression auto si image volumineuse
        was_compressed = False
        compression_info = {}
        original_size = len(content)
        
        if is_image and AUTO_COMPRESS_IMAGES and original_size > 5 * 1024 * 1024:
            content, was_compressed = compress_image(content, filename, max_dimension=MAX_IMAGE_DIMENSION)
            if was_compressed:
                compression_info = {
                    "compressed": True,
                    "original_size_mb": round(original_size / (1024 * 1024), 2),
                    "compressed_size_mb": round(len(content) / (1024 * 1024), 2),
                    "compression_ratio": round((1 - len(content) / original_size) * 100, 1)
                }
        
        # Stocker
        metadata = {'was_compressed': was_compressed}
        if compression_info:
            metadata['compression_info'] = compression_info
        
        download_url = store_file(content, filename, content_type, metadata)
        
        result = {
            "success": True,
            "source_url": file_url,
            "filename": sanitize_filename(filename),
            "download_url": download_url,
            "file_id": download_url.split('/')[-1],
            "format": file_ext or "unknown",
            "size_bytes": len(content),
            "size_mb": round(len(content) / (1024 * 1024), 2),
            "content_type": content_type,
            "uploaded_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=FILE_EXPIRY_HOURS)).isoformat()
        }
        
        if was_compressed:
            result["compression"] = compression_info
        
        return jsonify(result)
        
    except Exception as e:
        print(f"[ERROR] upload-from-url: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/download/<file_id>')
def download(file_id):
    """Télécharge un fichier stocké dans PostgreSQL"""
    cleanup_old_files()
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT * FROM files WHERE id = %s AND expiry > NOW()
        """, (file_id,))
        
        file_data = cursor.fetchone()
        
        if not file_data:
            return jsonify({"error": "Fichier non trouvé ou expiré"}), 404
        
        content = bytes(file_data['content'])
        
        response = Response(
            content,
            mimetype=file_data['content_type'],
            headers={
                'Content-Disposition': f'attachment; filename="{file_data["filename"]}"',
                'Content-Length': str(len(content)),
                'Cache-Control': 'public, max-age=3600'
            }
        )
        
        return response
        
    except Exception as e:
        print(f"[ERROR] download: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        release_db_connection(conn)

@app.route('/info/<file_id>')
def file_info(file_id):
    """Retourne les infos sur un fichier"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, filename, original_filename, content_type, size_bytes, 
                   created, expiry, was_compressed, metadata
            FROM files WHERE id = %s
        """, (file_id,))
        
        file_data = cursor.fetchone()
        
        if not file_data:
            return jsonify({"error": "Fichier non trouvé"}), 404
        
        time_left = file_data['expiry'] - datetime.now()
        
        info = {
            "filename": file_data['filename'],
            "original_filename": file_data['original_filename'],
            "content_type": file_data['content_type'],
            "size_bytes": file_data['size_bytes'],
            "size_mb": round(file_data['size_bytes'] / (1024 * 1024), 2),
            "created": file_data['created'].isoformat(),
            "expires_at": file_data['expiry'].isoformat(),
            "expires_in_hours": max(0, time_left.total_seconds() / 3600),
            "download_url": f"{BASE_URL}/download/{file_id}"
        }
        
        if file_data['was_compressed']:
            info["was_compressed"] = True
            if file_data['metadata']:
                import json
                metadata = json.loads(file_data['metadata'])
                info["compression_info"] = metadata.get('compression_info', {})
        
        return jsonify(info)
        
    except Exception as e:
        print(f"[ERROR] file_info: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        release_db_connection(conn)

@app.route('/status')
def status():
    """Statut du service"""
    cleanup_old_files()
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT COUNT(*) as total_files, 
                   COALESCE(SUM(size_bytes), 0) as total_size
            FROM files WHERE expiry > NOW()
        """)
        stats = cursor.fetchone()
        
        cursor.execute("""
            SELECT id, filename, size_bytes, content_type, was_compressed, 
                   expiry, created
            FROM files 
            WHERE expiry > NOW()
            ORDER BY created DESC
            LIMIT 20
        """)
        recent_files = cursor.fetchall()
        
        files_list = []
        for file_data in recent_files:
            time_left = file_data['expiry'] - datetime.now()
            files_list.append({
                "id": file_data['id'],
                "filename": file_data['filename'],
                "size_mb": round(file_data['size_bytes'] / (1024 * 1024), 2),
                "type": file_data['content_type'],
                "compressed": file_data['was_compressed'],
                "expires_in_hours": max(0, time_left.total_seconds() / 3600),
                "created": file_data['created'].isoformat()
            })
        
        return jsonify({
            "status": "operational",
            "version": "3.0",
            "storage_backend": "PostgreSQL",
            "storage": {
                "files_count": stats['total_files'],
                "total_size_mb": round(stats['total_size'] / (1024 * 1024), 2),
                "recent_files": files_list
            },
            "limits": {
                "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),
                "max_image_size_mb": MAX_IMAGE_SIZE / (1024 * 1024),
                "max_image_dimension": MAX_IMAGE_DIMENSION,
                "auto_compress": AUTO_COMPRESS_IMAGES,
                "file_expiry_hours": FILE_EXPIRY_HOURS
            },
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] status: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        release_db_connection(conn)

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint non trouvé"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Erreur serveur interne"}), 500

# Initialiser la base de données au démarrage
init_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    
    print("="*60)
    print("[FILE] STORAGE SERVER v3.0 - PostgreSQL Backend")
    print("="*60)
    print(f"[OK] Port: {port}")
    print(f"[OK] Storage: PostgreSQL (persistent)")
    print(f"[OK] Taille max fichiers: {MAX_FILE_SIZE/(1024*1024)} MB")
    print(f"[OK] Taille max images: {MAX_IMAGE_SIZE/(1024*1024)} MB")
    print(f"[OK] Dimension max images: {MAX_IMAGE_DIMENSION}px")
    print(f"[OK] Compression auto: {'OUI' if AUTO_COMPRESS_IMAGES else 'NON'}")
    print(f"[OK] Expiration: {FILE_EXPIRY_HOURS} heures")
    print(f"[OK] URL de base: {BASE_URL}")
    print("="*60)
    print("[KEY] CLES API:")
    print(f"   Primary: {PRIMARY_API_KEY[:30]}...{PRIMARY_API_KEY[-3:]}")
    print(f"   Secondary: {SECONDARY_API_KEY[:30]}...{SECONDARY_API_KEY[-3:]}")
    print("="*60)
    
    app.run(host='0.0.0.0', port=port, debug=False)
