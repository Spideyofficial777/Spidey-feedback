from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.feedback import bp
from app.models import Feedback, FormField, FeedbackSubject
from app import db, limiter
from app.email_service import send_feedback_confirmation, send_admin_notification
import json

@bp.route('/submit', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per minute")
def submit():
    form_fields = FormField.query.filter_by(is_active=True).order_by(FormField.order_index).all()
    subjects = FeedbackSubject.query.filter_by(is_active=True).order_by(FeedbackSubject.order_index).all()
    
    if request.method == 'POST':
        # Basic spam protection - honeypot field
        if request.form.get('website'):  # Hidden honeypot field
            flash('Submission rejected. Please try again.', 'error')
            return redirect(url_for('feedback.submit'))
        
        # Collect form data
        feedback_data = {}
        additional_data = {}
        
        # Process standard fields
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        rating = request.form.get('rating', type=int)
        
        # Validate required fields
        errors = []
        for field in form_fields:
            if field.is_required:
                value = request.form.get(field.field_name, '').strip()
                if not value:
                    errors.append(f'{field.field_label} is required')
        
        if not message:
            errors.append('Message is required')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('feedback/submit.html', form_fields=form_fields)
        
        # Collect additional field data
        for field in form_fields:
            if field.field_name not in ['name', 'email', 'phone', 'message', 'rating']:
                additional_data[field.field_name] = request.form.get(field.field_name, '').strip()
        
        # Create feedback record
        feedback = Feedback(
            name=name or None,
            email=email or None,
            phone=phone or None,
            subject=subject or None,
            message=message,
            rating=rating,
            user_id=current_user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_data=additional_data if additional_data else None
        )
        
        db.session.add(feedback)
        db.session.commit()
        
        # Send emails
        if email:
            send_feedback_confirmation(email, name or 'User', feedback)
        
        send_admin_notification(feedback)
        
        flash('Thank you for your feedback! We will get back to you soon.', 'success')
        return redirect(url_for('feedback.success'))
    
    return render_template('feedback/submit.html', form_fields=form_fields, subjects=subjects)

@bp.route('/success')
def success():
    return render_template('feedback/success.html')

@bp.route('/modal')
def modal():
    form_fields = FormField.query.filter_by(is_active=True).order_by(FormField.order_index).all()
    return render_template('feedback/modal.html', form_fields=form_fields)