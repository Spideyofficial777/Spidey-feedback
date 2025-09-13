from flask import current_app, render_template
from flask_mail import Message
from app import mail
import logging

def send_email(to, subject, html_body, text_body=None):
    """Send email with error handling"""
    try:
        sender_email = (
            current_app.config.get('MAIL_DEFAULT_SENDER')
            or current_app.config.get('MAIL_USERNAME')
            or "no-reply@example.com"
        )

        msg = Message(
            subject=f"[{current_app.config['APP_NAME']}] {subject}",
            recipients=[to],
            html=html_body,
            body=text_body or "",
            sender=sender_email
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email to {to}: {str(e)}")
        return False



def send_verification_email(email, username, otp):
    """Send email verification OTP"""
    subject = "Verify Your Email"
    html_body = render_template('email/verification.html', 
                               username=username, 
                               otp=otp,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)

def send_otp_email(email, username, otp):
    """Send OTP for login"""
    subject = "Your Login OTP"
    html_body = render_template('email/otp_login.html', 
                               username=username, 
                               otp=otp,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)

def send_password_reset_email(email, username, otp):
    """Send password reset OTP"""
    subject = "Password Reset Request"
    html_body = render_template('email/password_reset.html', 
                               username=username, 
                               otp=otp,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)

def send_admin_otp(email, otp):
    """Send admin OTP"""
    subject = "Admin Access OTP"
    html_body = render_template('email/admin_otp.html', 
                               otp=otp,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)

def send_feedback_confirmation(email, name, feedback):
    """Send feedback confirmation to user"""
    subject = "Thank You for Your Feedback"
    html_body = render_template('email/feedback_confirmation.html', 
                               name=name, 
                               feedback=feedback,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)

def send_admin_notification(feedback):
    """Send feedback notification to admin"""
    subject = f"New Feedback Received (#{feedback.id})"
    html_body = render_template('email/admin_notification.html', 
                               feedback=feedback,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(current_app.config['ADMIN_EMAIL'], subject, html_body)

def send_feedback_reply(email, name, reply, feedback):
    """Send feedback reply to user"""
    subject = f"Reply to Your Feedback (#{feedback.id})"
    html_body = render_template('email/feedback_reply.html', 
                               name=name, 
                               reply=reply,
                               feedback=feedback,
                               app_name=current_app.config['APP_NAME'],
                               app_url=current_app.config['APP_URL'])
    return send_email(email, subject, html_body)