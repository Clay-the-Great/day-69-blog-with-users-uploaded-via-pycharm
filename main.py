from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, DeletionForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

owners = [1]
login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    time = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="comments")
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_blog = relationship("BlogPost", back_populates="comments")


# db.create_all()
logged_in = False
current_user_id = 0


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user_id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403, "You are not authorized to view this page, sucker hahaha.")
    return wrapper_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=logged_in,
                           current_user_id=current_user_id,
                           owners=owners)


@app.route('/register', methods=["POST", "GET"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = User()
        new_user.email = request.form["email"]
        new_user.name = request.form["name"]
        user_in_db = User.query.filter_by(email=new_user.email).first()
        if user_in_db:
            error = "You already have signed up with that email, log in instead."
            login_form = LoginForm()
            return render_template("login.html", form=login_form, error=error)
        new_user.password = generate_password_hash(
            password=request.form["password"],
            method="pbkdf2:sha256",
            salt_length=8
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        global logged_in, current_user_id
        logged_in = True
        current_user_id = new_user.id
        return redirect(url_for("get_all_posts", logged_in=logged_in))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    error = None
    if login_form.validate_on_submit():
        email_entered = request.form["email"]
        password_entered = request.form["password"]
        user_in_db = User.query.filter_by(email=email_entered).first()
        if user_in_db:
            password_in_db = user_in_db.password
            if check_password_hash(pwhash=password_in_db, password=password_entered):
                login_user(user_in_db)
                global logged_in, current_user_id
                logged_in = True
                current_user_id = user_in_db.id
                return redirect(url_for("get_all_posts"))
            else:
                error = "Invalid Password"
        else:
            error = "No user with that email exists."
    return render_template("login.html", form=login_form, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    global logged_in, current_user_id
    logged_in = False
    current_user_id = 0
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    comments = requested_post.comments
    if comment_form.validate_on_submit():
        # if current_user.is_authenticated:
        if logged_in:
            new_comment = Comment(
                text=request.form["comment"],
                time=datetime.now().strftime("%B %d, %Y, %H:%M:%S"),
                author_id=current_user.id,
                author=current_user,
                blog_id=post_id,
                parent_blog=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            error = "You need to login or register to comment."
            login_form = LoginForm()
            return render_template("login.html", form=login_form, error=error)
    return render_template("post.html", post=requested_post, logged_in=logged_in,
                           current_user_id=current_user_id, comments=comments,
                           owners=owners, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=logged_in)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=logged_in)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=datetime.now().strftime("%B %d, %Y, %H:%M:%S")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author.name = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, logged_in=logged_in)


@app.route("/delete/<int:post_id>", methods=["POST", "GET"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    form = DeletionForm()
    if form.validate_on_submit():
        if form.cancel.data:
            return redirect(url_for("get_all_posts"))
        elif form.delete.data:
            db.session.delete(post_to_delete)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
    return render_template("deletion_confirmation.html", form=form, post_to_delete=post_to_delete)


@app.route("/delete_comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = Comment.query.filter_by(id=comment_id).first()
    if current_user_id == 1 or current_user_id == comment_to_delete.author_id:
        db.session.delete(comment_to_delete)
        db.session.commit()
        return redirect(url_for("show_post", post_id=comment_to_delete.blog_id))
    else:
        return abort(403, "You don't have the authority to delete this comment.")


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


if __name__ == "__main__":
    app.run(debug=True)
