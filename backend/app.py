from flask import Flask
from flask_cors import CORS
from config import Config
import os
from extensions import db, jwt

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
db.init_app(app)
jwt.init_app(app)

@app.route('/')
def index():
    return 'Smart Tourist Safety System API is running.'

def init_db():
    with app.app_context():
        if not os.path.exists('tourist_safety.db'):
            db.create_all()

if __name__ == "__main__":
    from models import *
    from routes import *
    init_db()
    app.run(debug=True)
