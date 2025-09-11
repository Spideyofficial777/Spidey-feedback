from flask import render_template, request, flash, redirect, url_for, jsonify, make_response, current_app
from flask_login import login_required, current_user
from app.admin import bp
from app.models import User, Feedback, FormField, Channel, AdminLog
from app import db, limiter
from app.email_service import send_admin_otp, send_feedback_reply
from functools import wraps
from datetime import datetime
import csv
import io

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_otp_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('main.index'))
        
        # Check if admin OTP is verified in session
        if not request.cookies.get('admin_otp_verified'):
            return redirect(url_for('admin.verify_admin_access'))
        
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and user.check_password(password):
            # Generate admin OTP
            otp = user.generate_otp()
            db.session.commit()
            
            if send_admin_otp(current_app.config['ADMIN_EMAIL'], otp):
                flash('Admin OTP sent to your registered email. Please check and verify.', 'success')
                return redirect(url_for('admin.verify_admin_otp', user_id=user.id))
            else:
                flash('Failed to send admin OTP. Please try again.', 'error')
        else:
            flash('Invalid admin credentials.', 'error')
    
    return render_template('admin/login.html')

@bp.route('/verify-admin-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_admin_otp(user_id):
    user = User.query.get_or_404(user_id)
    
    if not user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        if user.verify_otp(otp):
            user.clear_otp()
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log admin login
            log = AdminLog(
                admin_id=user.id,
                action='Admin Login',
                details='Successfully logged in with OTP verification',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            from flask_login import login_user
            login_user(user, remember=True)
            
            flash('Admin access granted!', 'success')
            response = make_response(redirect(url_for('admin.verify_admin_access')))
            response.set_cookie('admin_otp_verified', 'true', max_age=3600)  # 1 hour
            return response
        else:
            flash('Invalid or expired OTP.', 'error')
    
    return render_template('admin/verify_admin_otp.html', user=user)

@bp.route('/verify-access')
@admin_required
def verify_admin_access():
    if request.cookies.get('admin_otp_verified'):
        return redirect(url_for('admin.dashboard'))
    
    # Send new OTP
    otp = current_user.generate_otp()
    db.session.commit()
    
    if send_admin_otp(current_app.config['ADMIN_EMAIL'], otp):
        flash('Admin OTP sent to your registered email. Please verify to continue.', 'info')
        return redirect(url_for('admin.verify_admin_otp', user_id=current_user.id))
    else:
        flash('Failed to send admin OTP. Please try again.', 'error')
        return redirect(url_for('admin.admin_login'))

@bp.route('/dashboard')
@admin_otp_required
def dashboard():
    # Get statistics
    total_feedback = Feedback.query.count()
    new_feedback = Feedback.query.filter_by(status='new').count()
    total_users = User.query.filter_by(is_admin=False).count()
    
    # Recent feedback
    recent_feedback = Feedback.query.order_by(Feedback.created_at.desc()).limit(10).all()
    
    # Rating distribution
    rating_stats = {}
    for i in range(1, 6):
        rating_stats[i] = Feedback.query.filter_by(rating=i).count()
    
    return render_template('admin/dashboard.html', 
                         total_feedback=total_feedback,
                         new_feedback=new_feedback,
                         total_users=total_users,
                         recent_feedback=recent_feedback,
                         rating_stats=rating_stats)

@bp.route('/feedback')
@admin_otp_required
def feedback_list():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    query = Feedback.query
    
    if search:
        query = query.filter(
            (Feedback.name.like(f'%{search}%')) |
            (Feedback.email.like(f'%{search}%')) |
            (Feedback.message.like(f'%{search}%'))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    feedback_list = query.order_by(Feedback.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/feedback_list.html', 
                         feedback_list=feedback_list,
                         search=search,
                         status_filter=status_filter)

@bp.route('/feedback/<int:id>')
@admin_otp_required
def feedback_detail(id):
    feedback = Feedback.query.get_or_404(id)
    return render_template('admin/feedback_detail.html', feedback=feedback)

@bp.route('/feedback/<int:id>/update-status', methods=['POST'])
@admin_otp_required
def update_feedback_status(id):
    feedback = Feedback.query.get_or_404(id)
    new_status = request.form.get('status')
    
    if new_status in ['new', 'reading', 'responded', 'resolved']:
        feedback.status = new_status
        db.session.commit()
        
        # Log action
        log = AdminLog(
            admin_id=current_user.id,
            action='Update Feedback Status',
            details=f'Changed feedback #{id} status to {new_status}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Status updated successfully!', 'success')
    else:
        flash('Invalid status.', 'error')
    
    return redirect(url_for('admin.feedback_detail', id=id))

@bp.route('/feedback/<int:id>/reply', methods=['POST'])
@admin_otp_required
def reply_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    reply = request.form.get('reply', '').strip()
    send_email = request.form.get('send_email') == 'on'
    
    if reply:
        feedback.admin_reply = reply
        feedback.replied_at = datetime.utcnow()
        feedback.replied_by = current_user.id
        feedback.status = 'responded'
        db.session.commit()
        
        # Send email if requested and email is available
        if send_email and feedback.email:
            send_feedback_reply(feedback.email, feedback.name or 'User', reply, feedback)
        
        # Log action
        log = AdminLog(
            admin_id=current_user.id,
            action='Reply to Feedback',
            details=f'Replied to feedback #{id}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Reply saved successfully!', 'success')
    else:
        flash('Reply cannot be empty.', 'error')
    
    return redirect(url_for('admin.feedback_detail', id=id))

@bp.route('/feedback/<int:id>/delete', methods=['POST'])
@admin_otp_required
def delete_feedback(id):
    feedback = Feedback.query.get_or_404(id)
    
    # Log action before deletion
    log = AdminLog(
        admin_id=current_user.id,
        action='Delete Feedback',
        details=f'Deleted feedback #{id} from {feedback.email or "anonymous"}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(feedback)
    db.session.commit()
    
    flash('Feedback deleted successfully.', 'success')
    return redirect(url_for('admin.feedback_list'))

@bp.route('/feedback/export')
@admin_otp_required
def export_feedback():
    feedback_list = Feedback.query.order_by(Feedback.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Name', 'Email', 'Phone', 'Message', 'Rating', 'Status', 
        'Created At', 'Admin Reply', 'IP Address'
    ])
    
    # Write data
    for feedback in feedback_list:
        writer.writerow([
            feedback.id,
            feedback.name or '',
            feedback.email or '',
            feedback.phone or '',
            feedback.message,
            feedback.rating or '',
            feedback.status,
            feedback.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            feedback.admin_reply or '',
            feedback.ip_address or ''
        ])
    
    # Log action
    log = AdminLog(
        admin_id=current_user.id,
        action='Export Feedback',
        details='Exported all feedback to CSV',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=feedback_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@bp.route('/form-builder')
@admin_otp_required
def form_builder():
    form_fields = FormField.query.order_by(FormField.order_index).all()
    return render_template('admin/form_builder.html', form_fields=form_fields)

@bp.route('/form-builder/add-field', methods=['POST'])
@admin_otp_required
def add_form_field():
    data = request.get_json()
    
    field = FormField(
        field_name=data.get('field_name'),
        field_type=data.get('field_type'),
        field_label=data.get('field_label'),
        field_placeholder=data.get('field_placeholder'),
        is_required=data.get('is_required', False),
        order_index=FormField.query.count() + 1
    )
    
    if data.get('field_options'):
        field.field_options = data.get('field_options')
    
    db.session.add(field)
    db.session.commit()
    
    # Log action
    log = AdminLog(
        admin_id=current_user.id,
        action='Add Form Field',
        details=f'Added new form field: {field.field_label}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Field added successfully'})

@bp.route('/form-builder/update-field/<int:id>', methods=['POST'])
@admin_otp_required
def update_form_field(id):
    field = FormField.query.get_or_404(id)
    data = request.get_json()
    
    field.field_label = data.get('field_label', field.field_label)
    field.field_placeholder = data.get('field_placeholder', field.field_placeholder)
    field.is_required = data.get('is_required', field.is_required)
    field.is_active = data.get('is_active', field.is_active)
    
    if data.get('field_options'):
        field.field_options = data.get('field_options')
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Field updated successfully'})

@bp.route('/form-builder/delete-field/<int:id>', methods=['POST'])
@admin_otp_required
def delete_form_field(id):
    field = FormField.query.get_or_404(id)
    
    # Log action before deletion
    log = AdminLog(
        admin_id=current_user.id,
        action='Delete Form Field',
        details=f'Deleted form field: {field.field_label}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    
    db.session.delete(field)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Field deleted successfully'})

@bp.route('/users')
@admin_otp_required
def users():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    
    query = User.query.filter_by(is_admin=False)
    
    if search:
        query = query.filter(
            (User.username.like(f'%{search}%')) |
            (User.email.like(f'%{search}%'))
        )
    
    users_list = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/users.html', users_list=users_list, search=search)

@bp.route('/users/<int:id>/toggle-active', methods=['POST'])
@admin_otp_required
def toggle_user_active(id):
    user = User.query.get_or_404(id)
    
    if user.is_admin:
        flash('Cannot deactivate admin users.', 'error')
    else:
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        
        # Log action
        log = AdminLog(
            admin_id=current_user.id,
            action='Toggle User Status',
            details=f'User {user.username} {status}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'User {status} successfully.', 'success')
    
    return redirect(url_for('admin.users'))

@bp.route('/channels')
@admin_otp_required
def channels():
    channels = Channel.query.order_by(Channel.order_index).all()
    return render_template('admin/channels.html', channels=channels)

@bp.route('/channels/add', methods=['POST'])
@admin_otp_required
def add_channel():
    name = request.form.get('name', '').strip()
    link = request.form.get('link', '').strip()
    description = request.form.get('description', '').strip()
    
    if name and link:
        channel = Channel(
            name=name,
            link=link,
            description=description,
            order_index=Channel.query.count() + 1
        )
        db.session.add(channel)
        db.session.commit()
        
        flash('Channel added successfully!', 'success')
    else:
        flash('Name and link are required.', 'error')
    
    return redirect(url_for('admin.channels'))

@bp.route('/channels/<int:id>/delete', methods=['POST'])
@admin_otp_required
def delete_channel(id):
    channel = Channel.query.get_or_404(id)
    db.session.delete(channel)
    db.session.commit()
    
    flash('Channel deleted successfully.', 'success')
    return redirect(url_for('admin.channels'))

@bp.route('/logout')
@admin_required
def admin_logout():
    from flask_login import logout_user
    logout_user()
    response = make_response(redirect(url_for('main.index')))
    response.set_cookie('admin_otp_verified', '', expires=0)
    flash('Admin logged out successfully.', 'info')
    return response