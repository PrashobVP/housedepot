# app.py — HouseDepot (Flask + MySQL)
from datetime import datetime, timedelta
from decimal import Decimal
import os, random, re
from urllib.parse import quote_plus

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from PIL import Image

# Load .env (optional)
load_dotenv(override=True)

app = Flask(__name__)

# ---- Security: CSRF + rate limits + cookies ----
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # True on HTTPS
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB uploads
)

# ---- Core config (NO DATABASE_URL) ----
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')

DB_NAME = os.getenv('DATABASE')
DB_HOST = os.getenv('HOST')
DB_PORT = os.getenv('PORT', '3306')
DB_USER = os.getenv('USER')
DB_PASS = os.getenv('PASSWORD', '')

encoded_password = quote_plus(DB_PASS or "")
DB_URI = f"mysql+pymysql://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ---- Uploads ----
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.webp'}

def is_image_safe(path):
    try:
        with Image.open(path) as im:
            im.verify()
        return True
    except Exception:
        return False

# ---- Gmail SMTP ----
def _bool(val, default=False):
    if val is None:
        return default
    return str(val).strip().lower() in ('1','true','yes','on')

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = _bool(os.getenv('MAIL_USE_TLS', 'true'), True)
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER') or app.config['MAIL_USERNAME']
app.config['MAIL_DEBUG'] = app.debug

mail = Mail(app)
db = SQLAlchemy(app)

# ---------------- Models ----------------
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)
    image_url = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OtpToken(db.Model):
    __tablename__ = 'otp_tokens'
    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Template globals ----------------
@app.context_processor
def inject_public_settings():
    cart = session.get("cart")
    if isinstance(cart, dict):
        cart_count = sum(int(v) if str(v).isdigit() else 1 for v in cart.values())
    elif isinstance(cart, list):
        cart_count = len(cart)
    else:
        cart_count = 0
    return {
        "WHATSAPP_NUMBER": os.getenv("WHATSAPP_NUMBER", "91XXXXXXXXXX"),
        "MAIL_SENDER": os.getenv("MAIL_DEFAULT_SENDER", ""),
        "CART_COUNT": cart_count,
    }

# ---------------- Cart helpers ----------------
def _get_cart():
    c = session.get('cart')
    if isinstance(c, dict):
        return c
    if isinstance(c, list):  # migrate old list -> dict with qty
        d = {}
        for pid in c:
            d[str(pid)] = d.get(str(pid), 0) + 1
        session['cart'] = d
        return d
    session['cart'] = {}
    return session['cart']

def _save_cart(c):
    session['cart'] = c

# ---------------- OTP helpers ----------------
def send_otp_email(to_email: str, code: str):
    sender_email = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
    try:
        msg = Message('Your HouseDepot admin OTP', recipients=[to_email], sender=sender_email)
        msg.body = f"Your OTP code is: {code}\nThis code expires in 10 minutes."
        mail.send(msg)
    except Exception as e:
        print('[DEV OTP EMAIL FAILED]', code, '->', to_email, 'ERR:', repr(e))

def create_and_email_otp(admin: AdminUser):
    code = f"{random.randint(0, 999999):06d}"
    token = OtpToken(
        admin_user_id=admin.id,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.session.add(token)
    db.session.commit()
    send_otp_email(admin.email, code)

# ---------------- First run ----------------
with app.app_context():
    db.create_all()
    if AdminUser.query.count() == 0:
        admin_password = os.getenv('ADMIN_PASSWORD') or 'adminpass'
        default_admin = AdminUser(
            username='admin',
            email=os.getenv('ADMIN_EMAIL', 'housedepot2@gmail.com'),
            full_name='Admin User',
            password_hash=generate_password_hash(admin_password),
        )
        db.session.add(default_admin)
        db.session.commit()

# ---------------- Routes ----------------
@app.route('/')
def index():
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort','newest')
    page = max(int(request.args.get('page', 1)), 1)
    size = 12

    query = Product.query
    if q:
        if q.isdigit():
            query = query.filter((Product.name.ilike(f'%{q}%')) | (Product.id==int(q)))
        else:
            query = query.filter(Product.name.ilike(f'%{q}%'))

    if sort == 'price-asc':
        query = query.order_by(Product.price.asc(), Product.id.desc())
    elif sort == 'price-desc':
        query = query.order_by(Product.price.desc(), Product.id.desc())
    else:
        query = query.order_by(Product.created_at.desc()) if hasattr(Product, 'created_at') else query.order_by(Product.id.desc())

    total = query.count()
    products = query.offset((page-1)*size).limit(size).all()
    total_pages = max((total + size - 1) // size, 1)

    return render_template('index.html', products=products, page=page, total_pages=total_pages, sort=sort)

# Add to cart (POST + GET)
@app.route('/add_to_cart/<int:product_id>', methods=['POST','GET'])
def add_to_cart(product_id):
    cart = _get_cart()
    cart[str(product_id)] = int(cart.get(str(product_id), 0)) + 1
    _save_cart(cart)
    flash('Product added to cart!', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/product/<int:pid>')
def product_detail(pid):
    p = Product.query.get_or_404(pid)
    return render_template('product_detail.html', p=p)

@app.route('/cart')
def cart():
    c = _get_cart()
    ids = [int(k) for k in c.keys()]
    products = Product.query.filter(Product.id.in_(ids)).all() if ids else []
    items, total = [], Decimal('0.00')
    for p in products:
        qty = int(c.get(str(p.id), 0))
        sub = Decimal(p.price) * qty
        total += sub
        items.append({'product': p, 'qty': qty, 'subtotal': sub})
    return render_template('cart.html', items=items, total=total)

# WhatsApp checkout (POST only)
@app.route('/checkout', methods=['POST'])
def checkout():
    c = _get_cart()
    if not c:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('cart'))

    ids = [int(k) for k in c.keys()]
    products = Product.query.filter(Product.id.in_(ids)).all()
    if not products:
        session['cart'] = {}
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('cart'))

    lines, total = ["Hello, I would like to place an order:", ""], Decimal('0.00')
    for i, p in enumerate(products, start=1):
        qty = int(c.get(str(p.id), 0))
        sub = Decimal(p.price) * qty
        total += sub
        lines.append(f"{i}) [ID:{p.id}] {p.name} × {qty} = ₹{sub:.2f}")
    lines.append("")
    lines.append(f"Total amount: ₹{total:.2f}")
    wa_text = "\n".join(lines)

    wa_number = os.getenv("WHATSAPP_NUMBER", "916282526656")
    wa_url = f"https://wa.me/{wa_number}?text={quote_plus(wa_text)}"

    session['cart'] = {}
    flash('Order initiated. Opening WhatsApp…', 'success')
    return redirect(wa_url)

# ---- Admin auth + OTP ----
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = AdminUser.query.filter_by(username=username).first()
        if not admin or not check_password_hash(admin.password_hash, password):
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        create_and_email_otp(admin)
        session['pending_admin_id'] = admin.id
        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('verify_otp'))
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    pending_id = session.get('pending_admin_id')
    if not pending_id:
        flash('Start by logging in.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        token = OtpToken.query.filter_by(
            admin_user_id=pending_id, code=code, used=False
        ).order_by(OtpToken.created_at.desc()).first()
        if not token:
            flash('Invalid code.', 'danger')
            return render_template('verify_otp.html')
        if token.expires_at < datetime.utcnow():
            flash('Code expired. New OTP sent.', 'warning')
            admin = AdminUser.query.get(pending_id)
            create_and_email_otp(admin)
            return render_template('verify_otp.html')
        token.used = True
        db.session.commit()
        session.pop('pending_admin_id', None)
        session['admin'] = True
        session['admin_id'] = pending_id
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('verify_otp.html')

@app.route('/resend-otp', methods=['POST'])
@limiter.limit("3 per minute")
def resend_otp():
    pending_id = session.get('pending_admin_id')
    if not pending_id:
        return redirect(url_for('login'))
    admin = AdminUser.query.get(pending_id)
    create_and_email_otp(admin)
    flash('OTP resent.', 'info')
    return redirect(url_for('verify_otp'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))

def require_admin():
    if not session.get('admin'):
        flash('Admin access required', 'danger')
        return False
    return True

@app.route('/admin')
def admin_dashboard():
    if not require_admin():
        return redirect(url_for('login'))
    products = Product.query.order_by(Product.created_at.desc()).all()
    recent_otps = OtpToken.query.order_by(OtpToken.created_at.desc()).limit(10).all()
    return render_template('admin_dashboard.html', products=products, recent_otps=recent_otps, now=datetime.utcnow())

@app.route('/admin/add', methods=['GET', 'POST'])
def add_product():
    if not require_admin():
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        price_raw = request.form['price']
        description = request.form.get('description')
        image_file = request.files.get('image')
        try:
            price = Decimal(price_raw)
        except Exception:
            flash('Invalid price.', 'danger')
            return render_template('add_product.html')
        image_url = ''
        if image_file and image_file.filename and os.path.splitext(image_file.filename.lower())[1] in ALLOWED_IMAGE_EXTS:
            fname = secure_filename(image_file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            image_file.save(save_path)
            if not is_image_safe(save_path):
                os.remove(save_path)
                flash('Invalid image file.', 'danger')
                return render_template('add_product.html')
            image_url = f'static/uploads/{fname}'
        new_p = Product(name=name, price=price, description=description, image_url=image_url or 'static/uploads/placeholder.png')
        db.session.add(new_p)
        db.session.commit()
        flash('Product added.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_product.html')

@app.route('/admin/edit/<int:pid>', methods=['GET', 'POST'])
def edit_product(pid):
    if not require_admin():
        return redirect(url_for('login'))
    p = Product.query.get_or_404(pid)
    if request.method == 'POST':
        p.name = request.form['name']
        try:
            p.price = Decimal(request.form['price'])
        except Exception:
            flash('Invalid price.', 'danger')
            return render_template('edit_product.html', product=p)
        p.description = request.form.get('description')
        image_file = request.files.get('image')
        if image_file and image_file.filename and os.path.splitext(image_file.filename.lower())[1] in ALLOWED_IMAGE_EXTS:
            fname = secure_filename(image_file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            image_file.save(save_path)
            if not is_image_safe(save_path):
                os.remove(save_path)
                flash('Invalid image file.', 'danger')
                return render_template('edit_product.html', product=p)
            p.image_url = f'static/uploads/{fname}'
        db.session.commit()
        flash('Product updated.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_product.html', product=p)

@app.route('/admin/delete/<int:pid>', methods=['POST'])
def delete_product(pid):
    if not require_admin():
        return redirect(url_for('login'))
    p = Product.query.get_or_404(pid)
    db.session.delete(p)
    db.session.commit()
    flash('Product deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip()
        message = (request.form.get('message') or '').strip()

        if not name or not email or not message:
            flash('Please fill out all fields.', 'warning')
            return render_template('contact.html', name=name, email=email, message=message)
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash('Please enter a valid email address.', 'warning')
            return render_template('contact.html', name=name, email=email, message=message)

        to_addr = os.getenv('ADMIN_EMAIL', 'housedepot2@gmail.com')

        try:
            msg = Message(
                subject="New contact form message — HouseDepot",
                recipients=[to_addr],
                reply_to=email
            )
            msg.body = (
                "New message from HouseDepot contact form\n\n"
                f"Name: {name}\n"
                f"Email: {email}\n\n"
                f"Message:\n{message}\n"
            )
            safe_msg = message.replace("\n", "<br>")
            msg.html = f"""
                <h3>New contact form message</h3>
                <p><strong>Name:</strong> {name}</p>
                <p><strong>Email:</strong> {email}</p>
                <p><strong>Message:</strong><br>{safe_msg}</p>
            """
            mail.send(msg)
            flash('Thanks! Your message has been sent.', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            flash('Sorry, we could not send your message right now. Please try again later.', 'danger')
            return render_template('contact.html', name=name, email=email, message=message)

    return render_template('contact.html')

# ---- Optional quick SMTP test
@app.route('/admin/test-email')
def admin_test_email():
    if not require_admin():
        return redirect(url_for('login'))
    admin = AdminUser.query.get(session.get('admin_id'))
    target = admin.email if admin else (os.getenv('ADMIN_EMAIL') or app.config.get('MAIL_USERNAME'))
    try:
        msg = Message('HouseDepot SMTP Test', recipients=[target], sender=(app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')))
        msg.body = 'This is a test email from HouseDepot to confirm Gmail SMTP is working.'
        mail.send(msg)
        flash(f'Test email sent to {target}', 'success')
    except Exception as e:
        flash(f'Failed to send test email: {e}', 'danger')
    return redirect(url_for('admin_dashboard'))

# ---- Security headers & favicon
@app.after_request
def add_secure_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options','nosniff')
    resp.headers.setdefault('X-Frame-Options','DENY')
    resp.headers.setdefault('Referrer-Policy','no-referrer-when-downgrade')
    resp.headers.setdefault('Permissions-Policy','geolocation=(), microphone=()')
    return resp

@app.route('/favicon.ico')
def favicon():
    from flask import send_from_directory
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# ---- Error pages
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_err(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
