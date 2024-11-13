from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize the app and login manager
app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:lamis@localhost:5432/Inventory'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)

# Order Model
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    approved_date = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Stock Model
class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    quantity_balance = db.Column(db.Integer, nullable=False)
    date_order_placed = db.Column(db.DateTime, default=datetime.utcnow)
    date_order_approved = db.Column(db.DateTime, nullable=True)

# Initialize Database (If required)
# db.create_all()

# Login manager user_loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='sha256')
        role = request.form['role']
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful, please login!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome {user.username}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Login failed. Check your credentials and try again.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()  # Log the user out
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', orders=orders)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    orders = Order.query.all()
    stocks = Stock.query.all()
    return render_template('admin_dashboard.html', orders=orders, stocks=stocks)

@app.route('/place_order', methods=['GET', 'POST'])
@login_required
def place_order():
    if request.method == 'POST':
        item_name = request.form['item_name']
        quantity = request.form['quantity']
        new_order = Order(item_name=item_name, quantity=quantity, user_id=current_user.id)
        db.session.add(new_order)
        db.session.commit()
        flash('Order placed successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    return render_template('place_order.html')

@app.route('/approve_order/<int:order_id>', methods=['POST'])
@login_required
def approve_order(order_id):
    order = Order.query.get_or_404(order_id)
    if current_user.role == 'admin':
        order.status = 'Approved'
        order.approved_date = datetime.utcnow()
        stock = Stock.query.filter_by(product_name=order.item_name).first()
        if stock and stock.quantity_balance >= order.quantity:
            stock.quantity_balance -= order.quantity
            db.session.commit()
            flash('Order approved and stock updated!', 'success')
        else:
            flash('Not enough stock available!', 'danger')
        return redirect(url_for('admin_dashboard'))
    flash('You are not authorized to approve this order.', 'danger')
    return redirect(url_for('admin_dashboard'))

# Run the application
if __name__ == "__main__":
    app.run(debug=True)
