from flask import render_template, current_app
from app.main import bp
from app.models import Channel

@bp.route('/')
def index():
    return render_template('main/index.html')

@bp.route('/channels')
def channels():
    channels = Channel.query.filter_by(is_active=True).order_by(Channel.order_index).all()
    return render_template('main/channels.html', channels=channels)

@bp.route('/about')
def about():
    return render_template('main/about.html')