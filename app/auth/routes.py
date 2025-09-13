from flask import render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, current_user
from app.auth import bp
from app.models import User
from app import db, limiter
from app.email_service import send_verification_email, send_otp_email, send_password_reset_email
from datetime import datetime
import secrets
import string

@bp.route('/register', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        if User.query.filter_by(email=email).first():
            errors.append('Email already exists')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        otp = user.generate_otp()
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        if send_verification_email(email, username, otp):
            flash('Registration successful! Please check your email for verification code.', 'success')
            return redirect(url_for('auth.verify_email', user_id=user.id))
        else:
            flash('Registration successful but failed to send verification email. Please contact support.', 'warning')
            return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')

@bp.route('/verify-email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_verified:
        flash('Email already verified. Please login.', 'info')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        if user.verify_otp(otp):
            user.is_verified = True
            user.clear_otp()
            db.session.commit()
            flash('Email verified successfully! You can now login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
    
    return render_template('auth/verify_email.html', user=user)

@bp.route('/resend-otp/<int:user_id>')
@limiter.limit("3 per minute")
def resend_otp(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_verified:
        flash('Email already verified.', 'info')
        return redirect(url_for('auth.login'))
    
    otp = user.generate_otp()
    db.session.commit()
    
    if send_verification_email(user.email, user.username, otp):
        flash('Verification code sent to your email.', 'success')
    else:
        flash('Failed to send verification code. Please try again.', 'error')
    
    return redirect(url_for('auth.verify_email', user_id=user.id))

@bp.route('/login', methods=['GET', 'POST'])
# @limiter.limit("100 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        login_type = request.form.get('login_type', 'password')
        username_or_email = request.form.get('username_or_email', '').strip()
        
        # Find user
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
        
        if not user:
            flash('Invalid credentials', 'error')
            return render_template('auth/login.html')
        
        if not user.is_verified:
            flash('Please verify your email first.', 'warning')
            return redirect(url_for('auth.verify_email', user_id=user.id))
        
        if not user.is_active:
            flash('Your account has been deactivated. Please contact support.', 'error')
            return render_template('auth/login.html')
        
        if login_type == 'password':
            password = request.form.get('password', '')
            if user.check_password(password):
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=True)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.index'))
            else:
                flash('Invalid credentials', 'error')
        
        elif login_type == 'otp':
            otp = user.generate_otp()
            db.session.commit()
            
            if send_otp_email(user.email, user.username, otp):
                flash('OTP sent to your email. Please check and enter below.', 'success')
                return redirect(url_for('auth.verify_login_otp', user_id=user.id))
            else:
                flash('Failed to send OTP. Please try again.', 'error')
    
    return render_template('auth/login.html')

@bp.route('/verify-login-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_login_otp(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        if user.verify_otp(otp):
            user.clear_otp()
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('Invalid or expired OTP.', 'error')
    
    return render_template('auth/verify_login_otp.html', user=user)

@bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            otp = user.generate_otp()
            db.session.commit()
            
            if send_password_reset_email(user.email, user.username, otp):
                flash('Password reset code sent to your email.', 'success')
                return redirect(url_for('auth.reset_password', user_id=user.id))
            else:
                flash('Failed to send reset email. Please try again.', 'error')
        else:
            flash('Email not found.', 'error')
    
    return render_template('auth/forgot_password.html')

@bp.route('/reset-password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not user.verify_otp(otp):
            flash('Invalid or expired OTP.', 'error')
            return render_template('auth/reset_password.html', user=user)
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/reset_password.html', user=user)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', user=user)
        
        user.set_password(new_password)
        user.clear_otp()
        db.session.commit()
        
        flash('Password reset successful! You can now login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', user=user)

@bp.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))