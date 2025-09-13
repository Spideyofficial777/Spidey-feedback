from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from app.models import Feedback, FormField, Channel
from app import db
from app.email_service import send_feedback_confirmation, send_admin_notification
from datetime import datetime
import logging

bp = Blueprint('feedback', __name__)

@bp.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    """Submit feedback form - requires login"""
    try:
        form_fields = FormField.query.order_by(FormField.order_index).all()
        channels = Channel.query.filter_by(is_active=True).all()
        
        if request.method == 'POST':
            # Collect form data
            feedback_data = {}
            for field in form_fields:
                value = request.form.get(field.field_name, '').strip()
                if field.is_required and not value:
                    flash(f'{field.field_label} is required', 'error')
                    return render_template('feedback/submit.html', 
                                         form_fields=form_fields,
                                         channels=channels,
                                         form_data=request.form)
                feedback_data[field.field_name] = value
            
            # Create feedback
            feedback = Feedback(
                user_id=current_user.id,
                title=feedback_data.get('subject', 'No Subject'),
                content=feedback_data.get('message', ''),
                rating=int(feedback_data.get('rating', 0)) if feedback_data.get('rating') else None,
                name=feedback_data.get('name', current_user.username),
                email=feedback_data.get('email', current_user.email),
                phone=feedback_data.get('phone', ''),
                status='open'
            )
            
            db.session.add(feedback)
            db.session.commit()
            
            # Send confirmation email
            if current_user.email:
                send_feedback_confirmation(
                    current_user.email,
                    current_user.username,
                    feedback_data.get('message', '')[:100] + '...' if len(feedback_data.get('message', '')) > 100 else feedback_data.get('message', '')
                )
            
            # Send admin notification
            send_admin_notification(feedback)
            
            flash('Thank you for your feedback! We will get back to you soon.', 'success')
            return redirect(url_for('feedback.thank_you'))
        
        return render_template('feedback/submit.html', 
                             form_fields=form_fields,
                             channels=channels)
    
    except Exception as e:
        current_app.logger.error(f"Error submitting feedback: {str(e)}")
        db.session.rollback()
        flash('An error occurred while submitting your feedback. Please try again.', 'error')
        return redirect(url_for('feedback.submit'))

@bp.route('/thank-you')
@login_required
def thank_you():
    """Thank you page after feedback submission"""
    return render_template('feedback/thank_you.html')

@bp.route('/my-feedback')
@login_required
def my_feedback():
    """View user's feedback history"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        feedbacks = Feedback.query.filter_by(user_id=current_user.id)\
            .order_by(Feedback.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('feedback/my_feedback.html', feedbacks=feedbacks)
    
    except Exception as e:
        current_app.logger.error(f"Error loading feedback history: {str(e)}")
        flash('Error loading your feedback history.', 'error')
        return redirect(url_for('main.index'))

@bp.route('/view/<int:feedback_id>')
@login_required
def view_feedback(feedback_id):
    """View specific feedback details"""
    try:
        feedback = Feedback.query.get_or_404(feedback_id)
        
        # Ensure user can only view their own feedback unless admin
        if feedback.user_id != current_user.id and not current_user.is_admin:
            flash('You can only view your own feedback.', 'error')
            return redirect(url_for('feedback.my_feedback'))
        
        return render_template('feedback/view.html', feedback=feedback)
    
    except Exception as e:
        current_app.logger.error(f"Error viewing feedback: {str(e)}")
        flash('Error viewing feedback.', 'error')
        return redirect(url_for('feedback.my_feedback'))