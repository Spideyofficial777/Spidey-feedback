import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
oauth = OAuth()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///spidey_feedback.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Mail configuration
    app.config['MAIL_SERVER'] = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('SMTP_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('SMTP_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.environ.get('SMTP_EMAIL')
    app.config['MAIL_PASSWORD'] = os.environ.get('SMTP_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('SMTP_EMAIL')
    
    # App specific config
    app.config['APP_NAME'] = os.environ.get('APP_NAME', 'Spidey Feedback')
    app.config['APP_URL'] = os.environ.get('APP_URL', 'http://localhost:5000')
    app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', 'spideyofficial777@gmail.com')
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    oauth.init_app(app)
    
    # Configure OAuth providers
    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    
    oauth.register(
        name='github',
        client_id=os.environ.get('GITHUB_CLIENT_ID'),
        client_secret=os.environ.get('GITHUB_CLIENT_SECRET'),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )
    
    # Login manager configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Import models
    from app.models import User, Feedback, FormField, Channel
    
    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    from app.main import bp as main_bp
    from app.auth import bp as auth_bp
    from app.feedback import bp as feedback_bp
    from app.admin import bp as admin_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(feedback_bp, url_prefix='/feedback')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_password = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'Admin@1234')
            admin_user = User(
                username='admin',
                email=app.config['ADMIN_EMAIL'],
                password_hash=generate_password_hash(admin_password),
                is_admin=True,
                is_verified=True
            )
            db.session.add(admin_user)
        
        # Create default form fields if not exist
        if FormField.query.count() == 0:
            default_fields = [
                FormField(field_name='name', field_type='text', field_label='Name', is_required=False, order_index=1),
                FormField(field_name='email', field_type='email', field_label='Email', is_required=False, order_index=2),
                FormField(field_name='phone', field_type='tel', field_label='Phone', is_required=False, order_index=3),
                FormField(field_name='subject', field_type='select', field_label='Subject', field_options=['General Inquiry', 'Bug Report', 'Feature Request', 'Support'], is_required=True, order_index=4),
                FormField(field_name='message', field_type='textarea', field_label='Message', is_required=True, order_index=5),
                FormField(field_name='rating', field_type='rating', field_label='Rating', is_required=False, order_index=6)
            ]
            for field in default_fields:
                db.session.add(field)
        
        # Create default channels if not exist
        if Channel.query.count() == 0:
            default_channels = [
                Channel(name='Main Channel', link='https://t.me/spideyofficial', description='Join our main Telegram channel for updates'),
                Channel(name='Support Channel', link='https://t.me/spideysupport', description='Get support and help from our team')
            ]
            for channel in default_channels:
                db.session.add(channel)
        
        db.session.commit()
    
    return app