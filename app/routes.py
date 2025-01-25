from flask import Blueprint, render_template, redirect, url_for, request, flash,jsonify
from flask_login import login_user, logout_user, current_user, login_required
from datetime import datetime
from . import db, bcrypt
from .models import User, DiaryEntry
from mira_sdk import MiraClient
from dotenv import load_dotenv
import os
from sqlalchemy import cast, Date,func

load_dotenv()

# Define a blueprint
main = Blueprint('main', __name__)

# Initialize MiraClient
client = MiraClient(config={"API_KEY": os.getenv("API_KEY")})

# Home route
@main.route("/")
def home():
    return render_template("prelogin.html", logged_in=current_user.is_authenticated)

# Registration route
@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        if not username or not password:
            flash("Please fill in all fields", "danger")
            return redirect(url_for("main.register"))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken. Please choose a different one.", "danger")
            return redirect(url_for("main.register"))
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("main.login"))
    
    return render_template("register.html")

# Login route
@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        if not username or not password:
            flash("Please fill in all fields", "danger")
            return redirect(url_for("main.login"))
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("main.postlogin"))
        
        flash("Invalid credentials! Please check your username and password.", "danger")
    
    return render_template("login.html", logged_in=current_user.is_authenticated)
@main.route("/get_entries_by_date", methods=["POST"])
@login_required
def get_entries_by_date():
    date_str = request.json.get("date")  # Expecting the date in "YYYY-MM-DD" format
    if not date_str:
        return jsonify({"error": "No date provided"}), 400
    
    try:
        selected_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        #print(selected_date)
        entry = DiaryEntry.query.filter_by(user_id=1).first()
        formatted_date = db.session.query(func.strftime('%Y-%m-%d', entry.timestamp)).scalar()

        #print("FORMATTED DATE",formatted_date)
        entries = DiaryEntry.query.filter_by(user_id=current_user.id).filter(
        db.func.strftime('%Y-%m-%d', DiaryEntry.timestamp) == selected_date
        ).all()
       # print(entries)
        response = [
            {"timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "text": entry.entry_text, "AIsummary": entry.AIsummary}
            for entry in entries
        ]
        # results = DiaryEntry.query.with_entities(DiaryEntry.AIsummary).filter(
        # db.func.date(DiaryEntry.timestamp) == selected_date
        # ).all()

        # for result in results:
        #     print(result.AIsummary)
        #print(selected_date)

        # entries = DiaryEntry.query.filter(
        # DiaryEntry.user_id == current_user.id,
        # cast(DiaryEntry.timestamp, Date) == selected_date
        # ).all()
        
         # Print entries to verify if data is being retrieved

        return jsonify(response)
    except ValueError:
        return jsonify({"error": "Invalid date format"}), 400

# Dashboard route
@main.route("/postlogin")
@login_required
def postlogin():
    entries = DiaryEntry.query.filter_by(user_id=current_user.id).all()
    return render_template("postlogin.html", entries=entries, logged_in=current_user.is_authenticated)

# New diary entry route
@main.route("/newEntry", methods=["GET", "POST"])
@login_required
def newEntry():
    if request.method == "POST":
        entry_text = request.form["bigTextBox"]
        summary=request.form["smallTextBox"]
        
        if not entry_text:
            flash("Please write an entry.", "danger")
            return redirect(url_for("main.newEntry"))
        
        # Generate AI summary
        try:
            flow_name = "@adi-qtpi/diary-entry-summariser-by-adityas"
            input_data = {"daySpecial": summary, "diaryEntry": entry_text}
            result = client.flow.execute(flow_name, input_data)
            ai_summary = result.get('result', "No summary available.")
        except Exception as e:
            ai_summary = "Error generating summary."
            print(f"Error: {e}")
        
        new_entry = DiaryEntry(
            user_id=current_user.id, 
            entry_text=entry_text, 
            summary=request.form.get("summary"), 
            AIsummary=ai_summary
        )
        db.session.add(new_entry)
        db.session.commit()
        flash("Diary entry created successfully!", "success")
        return redirect(url_for("main.postlogin"))
    
    return render_template("newEntry.html")

# Edit entry route
@main.route("/edit_entry", methods=["GET", "POST"])
@login_required
def edit_entry():
    entries = DiaryEntry.query.filter_by(user_id=current_user.id).all()
    return render_template("edit_entry.html", entries=entries)

# Logout route
@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.home"))

@main.route("/AskAI", methods=["GET", "POST"])
@login_required
def AskAI():
    entries = DiaryEntry.query.filter_by(user_id=current_user.id).all()
    return render_template("AskAI.html", entries=entries)
