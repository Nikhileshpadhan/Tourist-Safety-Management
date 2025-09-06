from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from extensions import db
from app import app
from models import Tourist, Location, Alert
import random, string, datetime
from werkzeug.security import generate_password_hash, check_password_hash

# --- Aadhaar-based Registration ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    aadhaar = data.get('aadhaar_number')
    phone = data.get('phone')
    name = data.get('name')
    password = data.get('password')

    # Validate inputs
    if not aadhaar or len(aadhaar) != 12 or not aadhaar.isdigit():
        return jsonify({'msg': 'Invalid Aadhaar number'}), 400
    
    if not phone or len(phone) != 10 or not phone.isdigit():
        return jsonify({'msg': 'Invalid phone number'}), 400
    
    if not name or len(name.strip()) < 2:
        return jsonify({'msg': 'Invalid name'}), 400
    
    if not password or len(password) < 6:
        return jsonify({'msg': 'Password must be at least 6 characters'}), 400

    # Check if already registered
    if Tourist.query.filter_by(aadhaar_number=aadhaar).first():
        return jsonify({'msg': 'Aadhaar already registered'}), 400

    # Generate unique Tourist ID
    tourist_id = 'T' + ''.join(random.choices(string.digits, k=7))
    password_hash = generate_password_hash(password)
    tourist = Tourist(
        aadhaar_number=aadhaar,
        phone=phone,
        name=name,
        tourist_id=tourist_id,
        password_hash=password_hash
    )
    db.session.add(tourist)
    db.session.commit()
    token = create_access_token(identity=tourist_id)
    print(f"[REGISTRATION] New tourist registered: {name} (ID: {tourist_id})")
    return jsonify({'msg': 'Registration successful', 'tourist_id': tourist_id, 'token': token}), 201

# --- Tourist Login ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    tourist_id = data.get('tourist_id')
    password = data.get('password')

    if not tourist_id or not password:
        return jsonify({'msg': 'Tourist ID and password required'}), 400

    tourist = Tourist.query.filter_by(tourist_id=tourist_id).first()
    if not tourist:
        return jsonify({'msg': 'Invalid Tourist ID'}), 401

    if not check_password_hash(tourist.password_hash, password):
        return jsonify({'msg': 'Invalid password'}), 401

    token = create_access_token(identity=tourist_id)
    print(f"[LOGIN] Tourist logged in: {tourist.name} (ID: {tourist_id})")
    return jsonify({'msg': 'Login successful', 'token': token, 'tourist_id': tourist_id}), 200

# --- Location Sharing ---
@app.route('/api/location', methods=['POST'])
@jwt_required()
def location():
    data = request.get_json()
    tourist_id = get_jwt_identity()
    tourist = Tourist.query.filter_by(tourist_id=tourist_id).first()
    if not tourist:
        return jsonify({'msg': 'Invalid tourist'}), 401
    lat = data.get('latitude')
    lng = data.get('longitude')
    if lat is None or lng is None:
        return jsonify({'msg': 'Latitude and longitude required'}), 400
    loc = Location(tourist_id=tourist.id, latitude=lat, longitude=lng)
    db.session.add(loc)
    db.session.commit()
    return jsonify({'msg': 'Location updated'}), 200

# --- SOS Alert ---
@app.route('/api/sos', methods=['POST'])
@jwt_required()
def sos():
    tourist_id = get_jwt_identity()
    tourist = Tourist.query.filter_by(tourist_id=tourist_id).first()
    if not tourist:
        return jsonify({'msg': 'Invalid tourist'}), 401
    alert = Alert(tourist_id=tourist.id, alert_type='sos')
    db.session.add(alert)
    db.session.commit()
    # Simulate notification (console log)
    print(f"[ALERT] SOS from {tourist.name} (ID: {tourist.tourist_id}) at {datetime.datetime.now()}")
    return jsonify({'msg': 'SOS alert sent'}), 200

# --- ML Risk Detection ---
@app.route('/api/risk-detection', methods=['POST'])
@jwt_required()
def risk_detection():
    data = request.get_json()
    tourist_id = get_jwt_identity()
    tourist = Tourist.query.filter_by(tourist_id=tourist_id).first()
    if not tourist:
        return jsonify({'msg': 'Invalid tourist'}), 401
    
    lat = data.get('latitude')
    lng = data.get('longitude')
    if lat is None or lng is None:
        return jsonify({'msg': 'Latitude and longitude required'}), 400
    
    # Simulate ML risk detection based on location
    risk_score = 0
    risk_factors = []
    
    # Check for known risk areas (simplified ML simulation)
    risk_areas = [
        {"name": "Forest Area", "lat": 28.6139, "lng": 77.2090, "radius": 0.01, "risk": 0.8},
        {"name": "Hilly Region", "lat": 30.3753, "lng": 78.0751, "radius": 0.02, "risk": 0.7},
        {"name": "Political Zone", "lat": 28.5355, "lng": 77.3910, "radius": 0.005, "risk": 0.9},
        {"name": "Remote Area", "lat": 25.2048, "lng": 55.2708, "radius": 0.05, "risk": 0.6}
    ]
    
    for area in risk_areas:
        distance = ((lat - area["lat"])**2 + (lng - area["lng"])**2)**0.5
        if distance <= area["radius"]:
            risk_score = max(risk_score, area["risk"])
            risk_factors.append(area["name"])
    
    # Simulate time-based risk (night time = higher risk)
    current_hour = datetime.datetime.now().hour
    if 22 <= current_hour or current_hour <= 5:  # Night time
        risk_score += 0.2
        risk_factors.append("Night Time")
    
    # Simulate weather-based risk (simplified)
    import random
    weather_risk = random.uniform(0, 0.3)
    if weather_risk > 0.2:
        risk_score += weather_risk
        risk_factors.append("Adverse Weather")
    
    risk_score = min(risk_score, 1.0)  # Cap at 1.0
    
    # Determine risk level
    if risk_score >= 0.8:
        risk_level = "HIGH"
        recommendation = "Immediate caution required. Consider leaving the area and inform emergency contacts."
    elif risk_score >= 0.5:
        risk_level = "MEDIUM"
        recommendation = "Stay alert and maintain communication with emergency contacts."
    else:
        risk_level = "LOW"
        recommendation = "Area appears safe. Continue normal activities with basic precautions."
    
    # Log risk detection
    print(f"[ML RISK DETECTION] Tourist {tourist_id} at ({lat}, {lng}): Risk Level {risk_level} (Score: {risk_score:.2f})")
    
    return jsonify({
        'risk_level': risk_level,
        'risk_score': round(risk_score, 2),
        'risk_factors': risk_factors,
        'recommendation': recommendation,
        'location': {'latitude': lat, 'longitude': lng}
    }), 200

# --- Admin Tourists/Alerts Listing ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = create_access_token(identity='admin', additional_claims={'role': 'admin'})
        return jsonify({'msg': 'Admin login successful', 'token': token}), 200
    return jsonify({'msg': 'Invalid admin credentials'}), 401

@app.route('/api/tourists', methods=['GET'])
@jwt_required()
def tourists():
    claims = get_jwt_identity()
    # Only allow admin
    if claims != 'admin':
        return jsonify({'msg': 'Admin only'}), 403
    tourists = Tourist.query.all()
    locations = Location.query.order_by(Location.timestamp.desc()).all()
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    # Map tourist_id to latest location
    latest_locations = {}
    for loc in locations:
        if loc.tourist_id not in latest_locations:
            latest_locations[loc.tourist_id] = loc
    tourists_data = []
    for t in tourists:
        loc = latest_locations.get(t.id)
        tourists_data.append({
            'tourist_id': t.tourist_id,
            'aadhaar_number': t.aadhaar_number[:4] + '****' + t.aadhaar_number[-4:],
            'phone': t.phone,
            'name': t.name,
            'location': {
                'latitude': loc.latitude if loc else None,
                'longitude': loc.longitude if loc else None,
                'timestamp': loc.timestamp.isoformat() if loc else None
            }
        })
    alerts_data = [
        {
            'tourist_id': Tourist.query.get(a.tourist_id).tourist_id,
            'alert_type': a.alert_type,
            'created_at': a.created_at.isoformat(),
            'resolved': a.resolved
        }
        for a in alerts
    ]
    return jsonify({'tourists': tourists_data, 'alerts': alerts_data}), 200
