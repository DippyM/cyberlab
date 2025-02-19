from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    progress = db.relationship('Progress', backref='user', lazy=True)
    quiz_results = db.relationship('QuizResult', backref='user', lazy=True)

class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    module = db.Column(db.String(50), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_name = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityLab(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lab_type = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    setup_instructions = db.Column(db.Text)
    solution = db.Column(db.Text)

class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    protocol = db.Column(db.String(10))
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    port = db.Column(db.Integer)
    action = db.Column(db.String(20))  # ALLOW/DENY
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
