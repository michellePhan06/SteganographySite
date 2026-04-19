from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, uuid, json
from datetime import datetime
from functools import wraps
 
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(24),
    SQLALCHEMY_DATABASE_URI='sqlite:///steg.db',
    POSTS_FOLDER=os.path.join(os.path.dirname(__file__), 'posts'),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024
)
db = SQLAlchemy(app)
os.makedirs(app.config['POSTS_FOLDER'], exist_ok=True)
 
IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'}
 
# Model stuff
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

#DB
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title= db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    filename = db.Column(db.String(300), nullable=False)
    ext = db.Column(db.String(20))
    params = db.Column(db.Text)   
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
 
    @property
    def is_image(self):
        return (self.ext or '').lower() in IMAGE_EXTS
 
    @property
    def original_ext(self):
        return self.ext
 
# Steganography
# Generate sequence of bit position where data will be embed and extracted
def bit_positions(start, periods, mode, count):
    positions = []
    pos = start
    for i in range(count):
        # Determine step size based on mode
        step = periods[i % len(periods)] if mode == 'cycling' else periods[0]
        # Move to next embedding position
        pos += step
        positions.append(pos)
    return positions
 
def embed(carrier, message, start, periods, mode):
    # Generate bit positions for all message bits
    positions = bit_positions(start, periods, mode, len(message) * 8)
    # check if carrier is large to store message
    if positions and positions[-1] >= len(carrier) * 8:
        raise ValueError("Message too large for carrier with these parameters.")
    result = bytearray(carrier)
    # Embed each bit of the message into carrier bits
    for i, p in enumerate(positions):
        bit = (message[i >> 3] >> (7 - (i & 7))) & 1
        if bit: result[p >> 3] |=  (1 << (7 - (p & 7)))
        else:   result[p >> 3] &= ~(1 << (7 - (p & 7)))
    return bytes(result)

#Extract a hidden binary message from carrier.
def extract(carrier, start, periods, mode, n_bits):
    # Prepare output buffer
    result = bytearray((n_bits + 7) // 8)
    # Regenerate same bit positions used during embedding
    for i, p in enumerate(bit_positions(start, periods, mode, n_bits)):
        # Check if bit at position p is 1
        if (carrier[p >> 3] >> (7 - (p & 7))) & 1:
            result[i >> 3] |= (1 << (7 - (i & 7)))
    return bytes(result)
 
# Basics
 
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if 'uid' not in session:
            flash('Login required.')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrap

# Inject `user` into every template context
def me():
    return User.query.get(session.get('uid'))
@app.context_processor
def inject_user():
    return dict(user=me())
 
# Routes
# home page
@app.route('/')
def index():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)
#authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        # check if user name already taken
        if User.query.filter_by(username=u).first():
            flash('Username already taken.')
        else:
            # create and store new user 
            db.session.add(User(username=u, password=generate_password_hash(p)))
            db.session.commit()
            flash('Account created! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')
 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Look up user and verify password
        u = User.query.filter_by(username=request.form['username'].strip()).first()
        if u and check_password_hash(u.password, request.form['password']):
            session['uid'] = u.id
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html')
 
@app.route('/logout')
def logout():
    # log user out
    session.clear()
    return redirect(url_for('index'))

# submission for steganography post
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        start = int(request.form.get('start', 0))
        mode = request.form.get('mode', 'fixed')
        carrier = request.files.get('carrier')
        message = request.files.get('message')
        # Parse embedding periods
        try:
            periods = [int(x) for x in request.form.get('periods', '8').split(',') if x.strip()]
            if not periods:
                raise ValueError
        except ValueError:
            flash('Invalid period values.')
            return redirect(url_for('submit'))
        # Validate required fields
        if not (title and carrier and message):
            flash('All fields are required.')
            return redirect(url_for('submit'))
        # Read uploaded file data into memory
        carrier_bytes = carrier.read()
        message_bytes = message.read()
        # Attempt to embed message into carrier
        try:
            result = embed(carrier_bytes, message_bytes, start, periods, mode)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('submit'))
        # Generate unique filename and save result
        ext   = os.path.splitext(secure_filename(carrier.filename))[1].lower()
        fname = uuid.uuid4().hex + ext
        with open(os.path.join(app.config['POSTS_FOLDER'], fname), 'wb') as f:
            f.write(result)
        # DB record
        post = Post(
            title=title,
            description=description,
            filename=fname,
            ext=ext,
            user_id=session['uid'],
            params=json.dumps({
                'start':    start,
                'periods':  periods,
                'mode':     mode,
                'msg_bits': len(message_bytes) * 8
            })
        )
        db.session.add(post)
        db.session.commit()
        flash('File posted successfully!')
        return redirect(url_for('view_post', post_id=post.id))
 
    return render_template('submit.html')
#view post
@app.route('/post/<int:post_id>')
def view_post(post_id):
    post   = Post.query.get_or_404(post_id)
    params = json.loads(post.params)
    return render_template('post.html', post=post, params=params)
 
@app.route('/extract/<int:post_id>', methods=['POST'])
@login_required
def do_extract(post_id):
    post   = Post.query.get_or_404(post_id)
    params = json.loads(post.params)
    # Load stored file
    with open(os.path.join(app.config['POSTS_FOLDER'], post.filename), 'rb') as f:
        data = f.read()
    try:
        # Extract hidden message
        msg = extract(data, params['start'], params['periods'], params['mode'], params['msg_bits'])
        try:
            return jsonify(ok=True, content=msg.decode('utf-8'))
        # return raw hex if not valid text
        except Exception:
            return jsonify(ok=True, content=msg.hex())
    except Exception as e:
        return jsonify(ok=False, error=str(e))
 
@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Ensure user owns the post
    if post.user_id != session['uid']:
        flash('Unauthorized.')
        return redirect(url_for('index'))
    # Remove file
    try:
        os.remove(os.path.join(app.config['POSTS_FOLDER'], post.filename))
    except FileNotFoundError:
        pass
    # Remove db entry
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.')
    return redirect(url_for('index'))
 
@app.route('/posts/<filename>')
def serve_post(filename):
    return send_from_directory(app.config['POSTS_FOLDER'], filename)

# DB
with app.app_context():
    db.create_all()
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)