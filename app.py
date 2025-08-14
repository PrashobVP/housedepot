# app.py — HouseDepot (separate MySQL params, no DATABASE_URL)
from datetime import datetime, timedelta
from decimal import Decimal
import os, random, re
from urllib.parse import quote_plus

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load .env if present (optional).
load_dotenv()

app = Flask(__name__)

# -------- Core config (NO DATABASE_URL) --------
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')

DB_NAME = os.getenv('DATABASE', 'housedepot')
DB_HOST = os.getenv('HOST', '127.0.0.1')   # prefer TCP
DB_PORT = os.getenv('PORT', '3306')
DB_USER = os.getenv('USER', 'root')
DB_PASS = os.getenv('PASSWORD', '')

# Build the MySQL URI from parts (URL-encode user/pass for special chars)
DB_URI = (
    f"mysql+pymysql://{quote_plus(DB_USER)}:{quote_plus(DB_PASS)}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------- Uploads --------
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.webp'}

# -------- Gmail SMTP --------
def _bool(val, default=False):
    if val is None:
        return default
    return str(val).strip().lower() in ('1', 'true', 'yes', 'on')

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

# -------- Models --------
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
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

# -------- Helpers --------
def _ext_ok(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_IMAGE_EXTS

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
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(token)
    db.session.commit()
    send_otp_email(admin.email, code)

# -------- First run: ensure tables and seed admin --------
with app.app_context():
    db.create_all()

    admin = AdminUser.query.filter_by(username='admin').first()
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')

    if not admin:
        if not admin_email or not admin_password:
            raise ValueError("ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env before first run.")
        db.session.add(AdminUser(
            username='admin',
            email=admin_email,
            full_name='Admin User',
            password_hash=generate_password_hash(admin_password),
        ))
        db.session.commit()
        print("✅ Default admin created.")
    else:
        # Auto-repair an empty/malformed hash from earlier runs
        bad = (not admin.password_hash) or (':' not in admin.password_hash)
        if bad:
            if not admin_password:
                raise ValueError("ADMIN_PASSWORD must be set in .env to repair admin hash.")
            admin.email = admin_email or admin.email
            admin.password_hash = generate_password_hash(admin_password)
            db.session.commit()
            print("🔧 Fixed admin hash from .env")

# -------- Routes --------
@app.route('/')
def index():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('index.html', products=products, logo_url=url_for('static', filename='logo.jpg'))

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    cart = session.get('cart', [])
    cart.append(product_id)
    session['cart'] = cart
    flash('Product added to cart!', 'success')
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    ids = session.get('cart', [])
    items = Product.query.filter(Product.id.in_(ids)).all() if ids else []
    total = sum([Decimal(p.price) for p in items]) if items else Decimal('0.00')
    return render_template('cart.html', products=items, total=total)

@app.route('/checkout', methods=['POST'])
def checkout():
    ids = session.get('cart', [])
    if not ids:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('cart'))

    items = Product.query.filter(Product.id.in_(ids)).all()
    if not items:
        session.pop('cart', None)
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('cart'))

    lines = ["Hello, I would like to place an order for the items in my cart:", ""]
    total = Decimal('0.00')
    for i, p in enumerate(items, start=1):
        total += Decimal(p.price)
        price_str = f"₹{p.price:.2f}"
        lines.append(f"{i}) {p.name} — {price_str}")
    lines.append("")
    lines.append(f"Total amount: ₹{total:.2f}")
    wa_text = "\n".join(lines)

    wa_number = "916282526656"  # E.164 without plus sign
    wa_url = f"https://wa.me/{wa_number}?text={quote_plus(wa_text)}"

    session.pop('cart', None)
    flash('Order initiated. Opening WhatsApp…', 'success')

    return render_template('checkout_redirect.html', wa_url=wa_url)

# ---- Admin auth + OTP ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = AdminUser.query.filter_by(username=username).first()

        ok = False
        if admin:
            try:
                ok = check_password_hash(admin.password_hash, password)
            except ValueError:
                ok = False

        if not admin or not ok:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')

        create_and_email_otp(admin)
        session['pending_admin_id'] = admin.id
        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('verify_otp'))
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
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
        if image_file and image_file.filename and _ext_ok(image_file.filename):
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file.filename)
            image_file.save(save_path)
            image_url = f'static/uploads/{image_file.filename}'
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
        price_raw = request.form['price']
        try:
            p.price = Decimal(price_raw)
        except Exception:
            flash('Invalid price.', 'danger')
            return render_template('edit_product.html', product=p)
        p.description = request.form.get('description')
        image_file = request.files.get('image')
        if image_file and image_file.filename and _ext_ok(image_file.filename):
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file.filename)
            image_file.save(save_path)
            p.image_url = f'static/uploads/{image_file.filename}'
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

# Optional: test Gmail quickly
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

if __name__ == '__main__':
    app.run(debug=True)
