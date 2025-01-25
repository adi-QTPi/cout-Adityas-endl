from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diary.db'

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Register blueprints after initializing extensions
    from .routes import main
    app.register_blueprint(main)

    # Define user_loader function for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User  # Import here to avoid circular import
        return User.query.get(int(user_id))
    with app.app_context():
        db.create_all() 
    return app
