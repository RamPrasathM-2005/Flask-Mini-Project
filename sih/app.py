from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from datetime import datetime, date, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file
import io
from sqlalchemy import func, desc

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kerala_health_2025_free_version'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health_records.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# MODELS
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'doctor', 'migrant'

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    origin = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20))
    dob = db.Column(db.Date)
    address = db.Column(db.Text)
    vaccination_status = db.Column(db.String(50))
    
    # ✅ NEW WORKER FIELDS
    occupation = db.Column(db.String(50))
    arrival_date = db.Column(db.Date)
    employer = db.Column(db.String(100))
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    records = db.relationship('HealthRecord', backref='patient', lazy=True, cascade="all, delete-orphan")

class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=date.today)
    symptoms = db.Column(db.Text)
    diagnosis = db.Column(db.Text)
    treatment = db.Column(db.Text)
    notes = db.Column(db.Text)
    disease_type = db.Column(db.String(50))
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.Text)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    message = db.Column(db.Text)
    type = db.Column(db.String(20))  # 'record_added', 'profile_updated'
    is_read = db.Column(db.Boolean, default=False)

# FORMS
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('migrant', 'Migrant Worker'), ('doctor', 'Doctor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    # ✅ WORKER FIELDS - HIDDEN FOR NON-WORKERS
    origin = SelectField('Native State', choices=[
        ('Tamil Nadu', 'Tamil Nadu'), 
        ('Karnataka', 'Karnataka'), 
        ('Andhra Pradesh', 'Andhra Pradesh'),
        ('Telangana', 'Telangana'),
        ('West Bengal', 'West Bengal'),
        ('Bihar', 'Bihar'),
        ('Other', 'Other')
    ], validators=[Optional()])
    
    occupation = SelectField('Occupation', choices=[
        ('Construction', 'Construction Worker'),
        ('Agriculture', 'Agriculture Labour'),
        ('Factory', 'Factory Worker'),
        ('Domestic', 'Domestic Help'),
        ('Other', 'Other')
    ], validators=[Optional()])
    
    arrival_date = DateField('Arrived In Kerala', format='%Y-%m-%d', validators=[Optional()])
    employer = StringField('Employer Name', validators=[Optional()])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user: raise ValidationError('Username taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user: raise ValidationError('Email taken.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PatientForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    origin = SelectField('Origin', choices=[
        ('Tamil Nadu', 'Tamil Nadu'), 
        ('Karnataka', 'Karnataka'), 
        ('Andhra Pradesh', 'Andhra Pradesh'),
        ('Telangana', 'Telangana'),
        ('West Bengal', 'West Bengal'),
        ('Bihar', 'Bihar'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    contact = StringField('Contact', validators=[Optional()])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    address = TextAreaField('Address', validators=[Optional()])
    vaccination_status = StringField('Vaccination Status', validators=[Optional()])
    
    # ✅ NEW WORKER FIELDS
    occupation = SelectField('Occupation', choices=[
        ('Construction', 'Construction Worker'),
        ('Agriculture', 'Agriculture Labour'),
        ('Factory', 'Factory Worker'),
        ('Domestic', 'Domestic Help'),
        ('Other', 'Other')
    ], validators=[Optional()])
    arrival_date = DateField('Arrival Date', format='%Y-%m-%d', validators=[Optional()])
    employer = StringField('Employer', validators=[Optional()])
    
    submit = SubmitField('Save Patient')

class HealthRecordForm(FlaskForm):
    date = DateField('Date', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])
    symptoms = TextAreaField('Symptoms', validators=[Optional()])
    diagnosis = TextAreaField('Diagnosis', validators=[Optional()])
    treatment = TextAreaField('Treatment', validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])
    disease_type = SelectField('Disease Type', choices=[('infectious', 'Infectious'), ('chronic', 'Chronic'), ('other', 'Other')], validators=[Optional()])
    submit = SubmitField('Save Record')

class SearchForm(FlaskForm):
    query = StringField('Search by Name')
    submit = SubmitField('Search')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# HELPER FUNCTIONS
def log_audit(user_id, action, details):
    log = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(log)
    db.session.commit()

def create_notification(patient_id, message, notification_type):
    notification = Notification(patient_id=patient_id, message=message, type=notification_type)
    db.session.add(notification)
    db.session.commit()

def clean_form_data(form_data):
    """Remove 'submit' and 'csrf_token' from form data"""
    return {k: v for k, v in form_data.items() if k not in ['submit', 'csrf_token']}

# ROUTES
@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    search_form = SearchForm()
    patients = Patient.query
    
    if search_form.validate_on_submit():
        if search_form.query.data:
            patients = patients.filter(Patient.name.ilike(f'%{search_form.query.data}%'))
    
    page = request.args.get('page', 1, type=int)
    patients = patients.paginate(page=page, per_page=10, error_out=False)

    if current_user.role == 'admin':
        records = HealthRecord.query.order_by(HealthRecord.date.desc()).limit(10).all()
        infectious_count = HealthRecord.query.filter_by(disease_type='infectious').count()
        users = User.query.all()
        return render_template('admin_dashboard.html', patients=patients, records=records, 
                             infectious_count=infectious_count, search_form=search_form, users=users)
    elif current_user.role == 'doctor':
        return render_template('doctor_dashboard.html', patients=patients, search_form=search_form)
    else:  # migrant
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if patient:
            records = HealthRecord.query.filter_by(patient_id=patient.id).order_by(HealthRecord.date.desc()).all()
            notifications = Notification.query.filter_by(patient_id=patient.id, is_read=False).all()
            return render_template('migrant_dashboard.html', patient=patient, records=records, notifications=notifications)
        return render_template('migrant_dashboard.html', patient=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.flush()
        
        # ✅ WORKER-SPECIFIC: CREATE PATIENT PROFILE
        if form.role.data == 'migrant':
            patient = Patient(
                name=form.username.data.title(),
                age=25, 
                gender='Male',
                origin=form.origin.data or 'Tamil Nadu',
                contact=form.email.data,  # Phone as contact
                occupation=form.occupation.data or 'Construction',
                arrival_date=form.arrival_date.data,
                employer=form.employer.data,
                user_id=user.id
            )
            db.session.add(patient)
            create_notification(patient.id, 'Welcome! Complete your profile.', 'profile_updated')
        
        db.session.commit()
        log_audit(user.id, 'Registration', f'{user.username} registered as {user.role}')
        flash('Account created! Login now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            log_audit(user.id, 'Login', f'{user.username} logged in')
            flash('Welcome back!', 'success')
            return redirect(url_for('home'))
        flash('Invalid email/password!', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    log_audit(current_user.id, 'Logout', f'{current_user.username} logged out')
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    form = PatientForm()
    if form.validate_on_submit():
        patient_data = clean_form_data(form.data)
        patient = Patient(**patient_data)
        db.session.add(patient)
        db.session.flush()  # Get patient.id
        
        # ✅ NEW: AUTO-CREATE MIGRANT LOGIN FOR THIS PATIENT
        if current_user.role == 'admin':
            auto_username = f"{patient.name.lower().replace(' ', '')}_{patient.origin.lower()[:3]}"
            auto_email = f"{auto_username}@migrant.kerala"
            auto_password = "Welcome123"  # DEFAULT PASSWORD
            
            # Create user account
            hashed_password = bcrypt.generate_password_hash(auto_password).decode('utf-8')
            migrant_user = User(
                username=auto_username,
                email=auto_email,
                password=hashed_password,
                role='migrant'
            )
            db.session.add(migrant_user)
            
            # Link to patient
            patient.user_id = migrant_user.id
            db.session.commit()
            
            # Create welcome notification
            create_notification(patient.id, f'Welcome! Your login: {auto_email} | Password: Welcome123', 'profile_updated')
            
            log_audit(current_user.id, 'Add Patient + Migrant Account', f'{patient.name} - {auto_email}')
            flash(f'Patient ADDED + MIGRANT LOGIN CREATED! Email: {auto_email} | Password: Welcome123', 'success')
        else:
            db.session.commit()
            log_audit(current_user.id, 'Add Patient', f'{patient.name} added')
            flash('Patient added!', 'success')
        
        return redirect(url_for('home'))
    return render_template('add_patient.html', form=form, title='Add Patient')

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    patient = Patient.query.get_or_404(patient_id)
    form = PatientForm(obj=patient)
    if form.validate_on_submit():
        patient_data = clean_form_data(form.data)
        for attr, value in patient_data.items():
            setattr(patient, attr, value)
        db.session.commit()
        log_audit(current_user.id, 'Edit Patient', f'{patient.name} updated')
        flash('Patient updated!', 'success')
        return redirect(url_for('patient_detail', patient_id=patient_id))
    return render_template('add_patient.html', form=form, title='Edit Patient')

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
@login_required
def delete_patient(patient_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    patient = Patient.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    log_audit(current_user.id, 'Delete Patient', f'{patient.name} deleted')
    flash('Patient deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/patient/<int:patient_id>')
@login_required
def patient_detail(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    records = HealthRecord.query.filter_by(patient_id=patient_id).order_by(HealthRecord.date.desc()).all()
    return render_template('patient_detail.html', patient=patient, records=records)

@app.route('/add_record/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def add_record(patient_id):
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    patient = Patient.query.get_or_404(patient_id)
    form = HealthRecordForm()
    if form.validate_on_submit():
        record_data = clean_form_data(form.data)
        record = HealthRecord(**record_data, patient_id=patient_id, doctor_id=current_user.id)
        db.session.add(record)
        db.session.commit()
        log_audit(current_user.id, 'Add Record', f'Record for {patient.name}')
        create_notification(patient_id, f'New record: {form.diagnosis.data}', 'record_added')
        flash('Record added!', 'success')
        return redirect(url_for('patient_detail', patient_id=patient_id))
    return render_template('add_record.html', form=form, patient=patient, title='Add Record')

@app.route('/edit_record/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    record = HealthRecord.query.get_or_404(record_id)
    form = HealthRecordForm(obj=record)
    if form.validate_on_submit():
        record_data = clean_form_data(form.data)
        for attr, value in record_data.items():
            setattr(record, attr, value)
        db.session.commit()
        log_audit(current_user.id, 'Edit Record', f'Record {record.id}')
        flash('Record updated!', 'success')
        return redirect(url_for('patient_detail', patient_id=record.patient_id))
    return render_template('add_record.html', form=form, patient=record.patient, title='Edit Record')

@app.route('/delete_record/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    record = HealthRecord.query.get_or_404(record_id)
    patient_id = record.patient_id
    db.session.delete(record)
    db.session.commit()
    log_audit(current_user.id, 'Delete Record', f'Record {record.id}')
    flash('Record deleted!', 'success')
    return redirect(url_for('patient_detail', patient_id=patient_id))

@app.route('/export_patient/<int:patient_id>')
@login_required
def export_patient(patient_id):
    if current_user.role not in ['admin', 'doctor']: return redirect(url_for('home'))
    patient = Patient.query.get_or_404(patient_id)
    records = HealthRecord.query.filter_by(patient_id=patient_id).all()
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, height - 50, f"Patient Report: {patient.name}")
    
    p.setFont("Helvetica", 12)
    y = height - 80
    p.drawString(100, y, f"Age: {patient.age} | Gender: {patient.gender} | Origin: {patient.origin}")
    y -= 20
    p.drawString(100, y, f"Contact: {patient.contact or 'N/A'}")
    y -= 20
    p.drawString(100, y, f"Occupation: {patient.occupation or 'N/A'}")
    
    y -= 40
    p.setFont("Helvetica-Bold", 12)
    p.drawString(100, y, "Health Records:")
    y -= 20
    p.setFont("Helvetica", 10)
    for record in records:
        p.drawString(100, y, f"{record.date}: {record.diagnosis} - {record.treatment}")
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50
    
    p.save()
    buffer.seek(0)
    log_audit(current_user.id, 'Export PDF', f'{patient.name}')
    return send_file(buffer, as_attachment=True, download_name=f"{patient.name}_report.pdf", mimetype='application/pdf')

@app.route('/migrant_profile', methods=['GET', 'POST'])
@login_required
def migrant_profile():
    if current_user.role != 'migrant': return redirect(url_for('home'))
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    if not patient:
        flash('Contact admin!', 'danger')
        return redirect(url_for('home'))
    
    form = PatientForm(obj=patient)
    if form.validate_on_submit():
        patient_data = clean_form_data(form.data)
        for attr, value in patient_data.items():
            setattr(patient, attr, value)
        db.session.commit()
        create_notification(patient.id, 'Profile updated!', 'profile_updated')
        log_audit(current_user.id, 'Update Profile', f'{patient.name}')
        flash('Profile updated!', 'success')
        return redirect(url_for('home'))
    return render_template('migrant_profile.html', form=form)

@app.route('/mark_notification_read/<int:notif_id>')
@login_required
def mark_notification_read(notif_id):
    notification = Notification.query.get_or_404(notif_id)
    notification.is_read = True
    db.session.commit()
    flash('Notification read!', 'success')
    return redirect(url_for('home'))

@app.route('/surveillance')
@login_required
def surveillance():
    if current_user.role != 'admin': return redirect(url_for('home'))
    
    # BASIC STATS
    stats = {
        'total_patients': Patient.query.count(),
        'total_records': HealthRecord.query.count(),
        'infectious_cases': HealthRecord.query.filter_by(disease_type='infectious').count(),
        'vaccinated_patients': Patient.query.filter(Patient.vaccination_status.isnot(None)).count(),
        'recent_alerts_count': db.session.query(HealthRecord).filter(
            HealthRecord.disease_type == 'infectious',
            HealthRecord.date >= date.today() - timedelta(days=7)
        ).count()
    }
    
    # 1. INFECTIOUS CASES BY ORIGIN (BAR CHART)
    origins_query = db.session.query(
        Patient.origin,
        func.count(HealthRecord.id)
    ).join(HealthRecord).filter(
        HealthRecord.disease_type == 'infectious'
    ).group_by(Patient.origin).all()
    
    origins = [row[0] for row in origins_query]
    counts = [row[1] for row in origins_query]
    
    # 2. MONTHLY TRENDS (LINE CHART) - LAST 6 MONTHS
    six_months_ago = date.today() - timedelta(days=180)
    monthly_query = db.session.query(
        func.strftime('%Y-%m', HealthRecord.date).label('month'),
        func.count(HealthRecord.id)
    ).filter(
        HealthRecord.disease_type == 'infectious',
        HealthRecord.date >= six_months_ago
    ).group_by('month').order_by('month').all()
    
    months = [row.month for row in monthly_query]
    monthly_counts = [row[1] for row in monthly_query]
    
    # 3. DISEASE DISTRIBUTION (DOUGHNUT CHART)
    disease_query = db.session.query(
        HealthRecord.disease_type,
        func.count(HealthRecord.id)
    ).filter(HealthRecord.disease_type.isnot(None)).group_by(HealthRecord.disease_type).all()
    
    disease_types = [row[0] or 'Other' for row in disease_query]
    disease_counts = [row[1] for row in disease_query]
    
    # 4. VACCINATION COVERAGE BY ORIGIN (BAR CHART) - ✅ FIXED CASE SYNTAX
    vac_query = db.session.query(
        Patient.origin,
        func.count(Patient.id).label('total'),
        func.sum(db.case((Patient.vaccination_status.isnot(None), 1), else_=0)).label('vaccinated')
    ).group_by(Patient.origin).all()
    
    vac_origins = [row[0] for row in vac_query]
    vac_rates = [(row[2] / row[1] * 100) if row[1] > 0 else 0 for row in vac_query]
    
    # 5. RISK SCORES (TABLE)
    risk_query = db.session.query(
        Patient.origin,
        func.count(HealthRecord.id).label('cases')
    ).join(HealthRecord).filter(
        HealthRecord.disease_type == 'infectious'
    ).group_by(Patient.origin).all()
    
    total_infectious = HealthRecord.query.filter_by(disease_type='infectious').count()
    risk_scores = []
    for origin, cases in risk_query:
        score = (cases / total_infectious * 100) if total_infectious > 0 else 0
        risk_scores.append((origin, round(score, 1)))
    
    # 6. RECENT ALERTS (LAST 7 DAYS)
    recent_alerts_query = db.session.query(HealthRecord, Patient.name).join(Patient).filter(
        HealthRecord.disease_type == 'infectious',
        HealthRecord.date >= date.today() - timedelta(days=7)
    ).order_by(HealthRecord.date.desc()).limit(10).all()
    
    recent_alerts = [(record, name) for record, name in recent_alerts_query]
    
    return render_template('surveillance.html', 
                         stats=stats,
                         origins=origins, counts=counts,
                         months=months, monthly_counts=monthly_counts,
                         disease_types=disease_types, disease_counts=disease_counts,
                         vac_origins=vac_origins, vac_rates=vac_rates,
                         risk_scores=risk_scores,
                         recent_alerts=recent_alerts)

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin': return redirect(url_for('home'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if current_user.role != 'admin': return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    user.role = request.form['role']
    db.session.commit()
    log_audit(current_user.id, 'Change Role', f'{user.username} to {user.role}')
    flash('Role updated!', 'success')
    return redirect(url_for('users'))

@app.route('/audit_logs')
@login_required
def audit_logs():
    if current_user.role != 'admin': return redirect(url_for('home'))
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('audit_logs.html', logs=logs)

# CREATE DATABASE
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)