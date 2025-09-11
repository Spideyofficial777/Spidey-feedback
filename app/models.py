from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
import secrets
import string
from datetime import datetime, timedelta

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # OTP fields
    otp_code = db.Column(db.String(10))
    otp_expires_at = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_otp(self):
        self.otp_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.otp_expires_at = datetime.utcnow().replace(microsecond=0) + timedelta(minutes=10)
        return self.otp_code
    
    def verify_otp(self, otp):
        if not self.otp_code or not self.otp_expires_at:
            return False
        if datetime.utcnow() > self.otp_expires_at:
            return False
        return self.otp_code == otp
    
    def clear_otp(self):
        self.otp_code = None
        self.otp_expires_at = None

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    status = db.Column(db.String(20), default='new')  # new, reading, responded, resolved
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_reply = db.Column(db.Text)
    replied_at = db.Column(db.DateTime)
    replied_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Additional dynamic fields stored as JSON
    additional_data = db.Column(db.JSON)

class FormField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field_name = db.Column(db.String(50), nullable=False)
    field_type = db.Column(db.String(20), nullable=False)  # text, email, tel, textarea, rating, select
    field_label = db.Column(db.String(100), nullable=False)
    field_placeholder = db.Column(db.String(100))
    field_options = db.Column(db.JSON)  # For select fields
    is_required = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    order_index = db.Column(db.Integer, default=0)
    validation_pattern = db.Column(db.String(200))
    min_length = db.Column(db.Integer)
    max_length = db.Column(db.Integer)
    
    @property
    def options_list(self):
        return self.field_options or []

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    link = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    order_index = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)