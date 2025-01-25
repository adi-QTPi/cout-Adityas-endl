from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

from . import db  # Use the existing `db` instance from the app

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # Relationship to DiaryEntry (one-to-many)
    entries = db.relationship('DiaryEntry', backref='author', lazy='dynamic')  # Lazy loading set to 'dynamic' for better querying options


# DiaryEntry model
class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    entry_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Use `utcnow` for timezone consistency
    summary = db.Column(db.Text, nullable=True)
    AIsummary = db.Column(db.Text, nullable=True)

    # Relationship with User (many-to-one) - already managed by the ForeignKey
    # Redundant backref removed because it's handled by `entries` in the User model
