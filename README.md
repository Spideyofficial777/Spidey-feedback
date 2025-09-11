# Spidey Feedback - Professional Feedback Management System

A secure, beautiful, and highly customizable feedback web application built with Python Flask. Users can submit feedback without registration, with optional user accounts and comprehensive admin panel.

## ✨ Features

### Public Features
- **Anonymous Feedback Submission** - Users can provide feedback without creating accounts
- **Responsive Design** - Mobile-first approach with beautiful UI/UX
- **Anti-Spam Protection** - Rate limiting, honeypot fields, and optional reCAPTCHA
- **Star Rating System** - Interactive 1-5 star rating with accessibility support

### User Account System
- **Registration with Email Verification** - OTP-based email verification flow
- **Multiple Login Options** - Password login or OTP-based email login
- **Password Recovery** - Secure password reset with OTP verification
- **Account Management** - User profile and settings

### Admin Panel
- **Multi-Factor Authentication** - Admin login requires OTP verification via email
- **Feedback Management** - View, respond to, and manage all feedback submissions
- **Form Builder** - Customize feedback forms with drag-and-drop interface
- **User Management** - View and manage user accounts
- **Analytics Dashboard** - Statistics, ratings distribution, and insights
- **Email Templates** - Customizable HTML email templates
- **CSV Export** - Export feedback data for analysis

### Security Features
- **Password Hashing** - Secure password storage with bcrypt
- **CSRF Protection** - Cross-site request forgery protection
- **Rate Limiting** - API endpoint protection against abuse
- **Input Validation** - Comprehensive input sanitization
- **Admin Activity Logging** - Track all admin actions

## 🚀 Quick Start

### Using Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd spidey-feedback
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your SMTP credentials and other settings
   ```

3. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Access the application**
   - Main app: http://localhost:5000
   - Admin login: http://localhost:5000/admin/login

### Manual Setup

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Configure your .env file
   ```

3. **Initialize database**
   ```bash
   flask db upgrade
   ```

4. **Run the application**
   ```bash
   python run.py
   ```

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=development
DATABASE_URL=sqlite:///spidey_feedback.db

# SMTP Configuration
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True

# Admin Configuration
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_DEFAULT_PASSWORD=Change@This@Password

# App Configuration
APP_NAME=Spidey Feedback
APP_URL=http://localhost:5000
```

### Default Admin Credentials

**⚠️ IMPORTANT: Change these immediately after first login**

- **Username**: `admin`
- **Password**: `Admin@1234`
- **Admin Email**: `spideyofficial777@gmail.com`

## 📧 Email Configuration

The application uses SMTP for sending emails. Configure your email provider:

### Gmail Setup
1. Enable 2-Factor Authentication
2. Generate an App Password
3. Use the App Password in `SMTP_PASSWORD`

### Other Providers
- **Outlook**: `smtp.office365.com:587`
- **Yahoo**: `smtp.mail.yahoo.com:587`
- **Custom SMTP**: Configure accordingly

## 🎨 Customization

### Form Builder
Admins can customize the feedback form:
- Add/remove form fields
- Change field types (text, email, textarea, select, rating)
- Set validation rules
- Reorder fields with drag-and-drop

### Email Templates
Customize HTML email templates in `app/templates/email/`:
- `verification.html` - Email verification
- `feedback_confirmation.html` - User thank you
- `admin_notification.html` - Admin alerts
- `admin_otp.html` - Admin OTP
- `password_reset.html` - Password reset

### Channels Management
Add/edit Telegram channels in the admin panel:
- Channel name and description
- Direct links with attractive buttons
- Order management

## 🔒 Security

### Best Practices Implemented
- **Password Security**: bcrypt hashing with salt
- **Session Security**: Secure session management
- **CSRF Protection**: All forms protected
- **Rate Limiting**: Prevents spam and abuse
- **Input Validation**: SQL injection and XSS protection
- **Admin Security**: Multi-step authentication for admin access

### Security Recommendations
1. Use strong, unique passwords
2. Enable HTTPS in production
3. Regular security updates
4. Monitor admin activity logs
5. Use environment variables for secrets

## 📊 Database Schema

### Main Tables
- **Users**: User accounts and authentication
- **Feedback**: Feedback submissions and responses
- **FormFields**: Dynamic form configuration
- **Channels**: Telegram channel management
- **AdminLogs**: Admin activity tracking

## 🎯 API Endpoints

### Public Endpoints
- `GET /` - Homepage
- `GET /feedback/submit` - Feedback form
- `POST /feedback/submit` - Submit feedback
- `GET /channels` - Channel listing

### Authentication Endpoints
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/verify-email` - Email verification
- `POST /auth/forgot-password` - Password recovery

### Admin Endpoints (Protected)
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/feedback` - Feedback management
- `GET /admin/users` - User management
- `GET /admin/form-builder` - Form customization
- `GET /admin/channels` - Channel management

## 🔄 Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   export FLASK_ENV=production
   export DATABASE_URL=postgresql://user:pass@host:port/db
   ```

2. **Database Migration**
   ```bash
   flask db upgrade
   ```

3. **Using Gunicorn**
   ```bash
   gunicorn --workers 4 --bind 0.0.0.0:5000 run:app
   ```

### Docker Production
```bash
docker build -t spidey-feedback .
docker run -d -p 5000:5000 --env-file .env spidey-feedback
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 💬 Support

For support and questions:
- Create an issue on GitHub
- Email: support@spideyfeedback.com
- Telegram: @SpideySupport

## 🔄 Version History

### v1.0.0 (Current)
- Initial release
- Complete feedback system
- Admin panel with OTP authentication
- Form builder
- Email system
- User management
- Security features

---

**Made with ❤️ by the Spidey Team**# Spidey-feedback
