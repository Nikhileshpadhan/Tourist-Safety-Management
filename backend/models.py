from extensions import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class Tourist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aadhaar_number = db.Column(db.String(12), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    tourist_id = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    locations = db.relationship('Location', backref='tourist', lazy=True)
    alerts = db.relationship('Alert', backref='tourist', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tourist_id = db.Column(db.Integer, db.ForeignKey('tourist.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tourist_id = db.Column(db.Integer, db.ForeignKey('tourist.id'), nullable=False)
    alert_type = db.Column(db.String(20), default='sos')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
