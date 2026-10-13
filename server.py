"""Portail pédagogique US1. Python 3.10+, bibliothèque standard uniquement."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
import base64, hashlib, hmac, json, secrets, sqlite3, time

ROOT = Path(__file__).resolve().parent
DB = ROOT / 'campus.sqlite3'
SESSIONS = {}
ATTEMPTS = {}


def initialize():
    with sqlite3.connect(DB) as db:
        db.execute('PRAGMA foreign_keys = ON')
        db.execute('CREATE TABLE IF NOT EXISTS utilisateurs (id INTEGER PRIMARY KEY, nom TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ("professeur","etudiant")))')
        for role, name in [('professeur', 'Professeur'), ('etudiant', 'Étudiant')]:
            salt = secrets.token_hex(16)
            digest = hashlib.pbkdf2_hmac('sha256', b'Campus2026!', bytes.fromhex(salt), 600000).hex()
            db.execute('INSERT OR IGNORE INTO utilisateurs(nom,email,salt,password_hash,role) VALUES(?,?,?,?,?)', (name, role+'@campus.ma', salt, digest, role))
        db.execute('CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL CHECK(category IN ("cours","td")), filename TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, data BLOB NOT NULL, uploaded_by INTEGER NOT NULL, created_at REAL NOT NULL, FOREIGN KEY(uploaded_by) REFERENCES utilisateurs(id))')
        db.execute('CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, professor_id INTEGER NOT NULL, subject TEXT NOT NULL, status TEXT NOT NULL DEFAULT "ouvert", created_at REAL NOT NULL, updated_at REAL NOT NULL, FOREIGN KEY(student_id) REFERENCES utilisateurs(id), FOREIGN KEY(professor_id) REFERENCES utilisateurs(id))')
        db.execute('CREATE TABLE IF NOT EXISTS ticket_messages (id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, sender_role TEXT NOT NULL CHECK(sender_role IN ("professeur","etudiant")), message TEXT NOT NULL, created_at REAL NOT NULL, FOREIGN KEY(ticket_id) REFERENCES tickets(id), FOREIGN KEY(sender_id) REFERENCES utilisateurs(id))')


def serialize_user(row):
    if not row:
        return None
    return {'id': row[0], 'nom': row[1], 'email': row[2], 'role': row[5]}


class Handler(BaseHTTPRequestHandler):
    def session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
        except Exception:
            pass
        sid = cookie['campus'].value if 'campus' in cookie else ''
        if sid not in SESSIONS or SESSIONS[sid]['expires'] < time.time():
            SESSIONS.pop(sid, None)
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {'user': None, 'csrf': secrets.token_urlsafe(32), 'expires': time.time()+3600}
        self.sid = sid
        return SESSIONS[sid]

    def reply(self, status, payload, html=False):
        data = payload if html else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Set-Cookie', f'campus={self.sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    def do_GET(self):
        s = self.session()
        path = self.path.split('?')[0]
        if path == '/api/session':
            return self.reply(200, {'user': s['user'], 'csrf': s['csrf']})
        if path in ('/api/professeur', '/api/etudiant'):
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            if s['user']['role'] != path.rsplit('/', 1)[1]:
                return self.reply(403, {'error': 'Accès refusé.'})
            return self.reply(200, {'user': s['user'], 'message': 'Accès autorisé.'})
        if path == '/api/documents':
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            with sqlite3.connect(DB) as db:
                rows = db.execute('SELECT d.id, d.title, d.category, d.filename, d.mime, d.size, d.uploaded_by, d.created_at, u.nom, u.email FROM documents d JOIN utilisateurs u ON u.id = d.uploaded_by ORDER BY d.created_at DESC').fetchall()
            documents = [{
                'id': row[0],
                'title': row[1],
                'category': row[2],
                'filename': row[3],
                'mime': row[4],
                'size': row[5],
                'uploaded_by': {'id': row[6], 'nom': row[8], 'email': row[9]},
                'created_at': row[7],
            } for row in rows]
            return self.reply(200, {'documents': documents})
        if path.startswith('/api/documents/') and path.endswith('/download'):
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            try:
                doc_id = int(path.split('/')[3])
            except (IndexError, ValueError):
                return self.reply(404, {'error': 'Document introuvable.'})
            with sqlite3.connect(DB) as db:
                row = db.execute('SELECT id, title, category, filename, mime, size, data FROM documents WHERE id=?', (doc_id,)).fetchone()
            if not row:
                return self.reply(404, {'error': 'Document introuvable.'})
            self.send_response(200)
            self.send_header('Content-Type', row[4] or 'application/octet-stream')
            self.send_header('Content-Disposition', f'inline; filename="{row[3]}"')
            self.send_header('Content-Length', str(len(row[6])))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(row[6])
            return
        if path == '/api/tickets':
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            with sqlite3.connect(DB) as db:
                if s['user']['role'] == 'professeur':
                    rows = db.execute('SELECT t.id, t.student_id, t.professor_id, t.subject, t.status, t.created_at, t.updated_at, s.nom as student_name, s.email as student_email, p.nom as professor_name FROM tickets t JOIN utilisateurs s ON s.id = t.student_id JOIN utilisateurs p ON p.id = t.professor_id WHERE t.professor_id=? ORDER BY t.updated_at DESC', (s['user']['id'],)).fetchall()
                else:
                    rows = db.execute('SELECT t.id, t.student_id, t.professor_id, t.subject, t.status, t.created_at, t.updated_at, s.nom as student_name, s.email as student_email, p.nom as professor_name FROM tickets t JOIN utilisateurs s ON s.id = t.student_id JOIN utilisateurs p ON p.id = t.professor_id WHERE t.student_id=? ORDER BY t.updated_at DESC', (s['user']['id'],)).fetchall()
                tickets = []
                for row in rows:
                    messages = db.execute('SELECT sender_id, sender_role, message, created_at FROM ticket_messages WHERE ticket_id=? ORDER BY created_at ASC', (row[0],)).fetchall()
                    tickets.append({
                        'id': row[0],
                        'student': {'id': row[1], 'nom': row[7], 'email': row[8]},
                        'professor': {'id': row[2], 'nom': row[9]},
                        'subject': row[3],
                        'status': row[4],
                        'created_at': row[5],
                        'updated_at': row[6],
                        'messages': [{
                            'sender_id': msg[0],
                            'sender_role': msg[1],
                            'message': msg[2],
                            'created_at': msg[3],
                        } for msg in messages],
                    })
            return self.reply(200, {'tickets': tickets})
        if path == '/':
            return self.reply(200, (ROOT/'index.html').read_bytes(), True)
        return self.reply(404, {'error': 'Page introuvable.'})

    def do_POST(self):
        s = self.session()
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), s['csrf']):
            return self.reply(403, {'error': 'Session invalide. Rechargez la page.'})
        if self.path == '/api/logout':
            SESSIONS.pop(self.sid, None)
            s = self.session()
            return self.reply(200, {'csrf': s['csrf']})
        if self.path == '/api/login':
            ip = self.client_address[0]
            attempts = [t for t in ATTEMPTS.get(ip, []) if t > time.time()-60]
            ATTEMPTS[ip] = attempts
            if len(attempts) >= 10:
                return self.reply(429, {'error': 'Trop de tentatives. Patientez une minute.'})
            try:
                data = self.read_json_body()
                email = str(data.get('email', '')).strip().lower()
                password = data.get('password', '')
                if not isinstance(password, str) or not email or not password:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                return self.reply(400, {'error': 'Renseignez un email et un mot de passe.'})
            with sqlite3.connect(DB) as db:
                row = db.execute('SELECT id,nom,email,salt,password_hash,role FROM utilisateurs WHERE email=?', (email,)).fetchone()
            salt = bytes.fromhex(row[3]) if row else b'0'*16
            digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000).hex()
            if not row or not hmac.compare_digest(digest, row[4]):
                attempts.append(time.time())
                return self.reply(401, {'error': 'Email ou mot de passe incorrect.'})
            SESSIONS.pop(self.sid, None)
            self.sid = secrets.token_urlsafe(32)
            s = {'user': serialize_user(row), 'csrf': secrets.token_urlsafe(32), 'expires': time.time()+3600}
            SESSIONS[self.sid] = s
            ATTEMPTS.pop(ip, None)
            return self.reply(200, {'user': s['user'], 'csrf': s['csrf']})
        if self.path == '/api/upload':
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            if s['user']['role'] != 'professeur':
                return self.reply(403, {'error': 'Seul le professeur peut publier des documents.'})
            try:
                data = self.read_json_body()
                category = str(data.get('category', '')).strip().lower()
                title = str(data.get('title', '')).strip()
                filename = str(data.get('filename', 'document.pdf')).strip() or 'document.pdf'
                mime = str(data.get('mime', 'application/octet-stream')).strip() or 'application/octet-stream'
                raw = data.get('content', '')
                if category not in {'cours', 'td'}:
                    raise ValueError('Type de document invalide.')
                if not title:
                    title = filename
                if not raw:
                    raise ValueError('Aucun fichier transmis.')
                content = base64.b64decode(raw, validate=True)
                if len(content) > 8 * 1024 * 1024:
                    return self.reply(413, {'error': 'Le fichier est trop volumineux (8 Mo maximum).'})
            except Exception as exc:
                return self.reply(400, {'error': str(exc) if str(exc) else 'Données de téléchargement invalides.'})
            with sqlite3.connect(DB) as db:
                db.execute('INSERT INTO documents(title, category, filename, mime, size, data, uploaded_by, created_at) VALUES(?,?,?,?,?,?,?,?)', (title, category, filename, mime, len(content), content, s['user']['id'], time.time()))
            return self.reply(200, {'ok': True, 'message': 'Document publié avec succès.'})
        if self.path == '/api/tickets':
            if not s['user']:
                return self.reply(401, {'error': 'Connexion requise.'})
            try:
                data = self.read_json_body()
            except Exception:
                return self.reply(400, {'error': 'Requête invalide.'})
            subject = str(data.get('subject', '')).strip()
            message = str(data.get('message', '')).strip()
            ticket_id = data.get('ticket_id')
            if ticket_id is not None:
                try:
                    ticket_id = int(ticket_id)
                except ValueError:
                    return self.reply(400, {'error': 'Ticket invalide.'})
                if not message:
                    return self.reply(400, {'error': 'Le message est vide.'})
                with sqlite3.connect(DB) as db:
                    ticket = db.execute('SELECT student_id, professor_id FROM tickets WHERE id=?', (ticket_id,)).fetchone()
                    if not ticket:
                        return self.reply(404, {'error': 'Ticket introuvable.'})
                    if s['user']['role'] == 'professeur' and ticket[1] != s['user']['id']:
                        return self.reply(403, {'error': 'Vous ne pouvez répondre qu’à vos propres tickets.'})
                    if s['user']['role'] == 'etudiant' and ticket[0] != s['user']['id']:
                        return self.reply(403, {'error': 'Vous ne pouvez répondre qu’à vos propres tickets.'})
                    db.execute('INSERT INTO ticket_messages(ticket_id, sender_id, sender_role, message, created_at) VALUES(?,?,?,?,?)', (ticket_id, s['user']['id'], s['user']['role'], message, time.time()))
                    db.execute('UPDATE tickets SET updated_at=? WHERE id=?', (time.time(), ticket_id))
                return self.reply(200, {'ok': True, 'message': 'Réponse enregistrée.'})
            if s['user']['role'] != 'etudiant':
                return self.reply(403, {'error': 'Seuls les étudiants peuvent ouvrir un ticket.'})
            if not subject or not message:
                return self.reply(400, {'error': 'Renseignez l’objet et le message du ticket.'})
            with sqlite3.connect(DB) as db:
                professor = db.execute('SELECT id FROM utilisateurs WHERE role="professeur" ORDER BY id LIMIT 1').fetchone()
                if not professor:
                    return self.reply(500, {'error': 'Aucun professeur n’est enregistré.'})
                now = time.time()
                ticket_id = db.execute('INSERT INTO tickets(student_id, professor_id, subject, status, created_at, updated_at) VALUES(?,?,?,?,?,?)', (s['user']['id'], professor[0], subject, 'ouvert', now, now)).lastrowid
                db.execute('INSERT INTO ticket_messages(ticket_id, sender_id, sender_role, message, created_at) VALUES(?,?,?,?,?)', (ticket_id, s['user']['id'], 'etudiant', message, now))
            return self.reply(200, {'ok': True, 'message': 'Ticket créé avec succès.'})
        return self.reply(404, {'error': 'Page introuvable.'})


if __name__ == '__main__':
    initialize()
    print('Campus : http://localhost:8000', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8000), Handler).serve_forever()
