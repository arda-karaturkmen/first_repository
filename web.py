from flask import Flask,render_template,flash,redirect,url_for,session,logging,request
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, FileField
from passlib.hash import sha256_crypt
from functools import wraps
import mysql.connector
from mysql.connector import Error
from werkzeug.utils import secure_filename
import os
import time

# Flask uygulamasını oluştur
app = Flask(__name__)
app.secret_key = "arda2001"

# Dosya yükleme ayarları
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dosya uzantısı kontrolü
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# MySQL bağlantı fonksiyonu
def get_mysql_connection():
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='',
            database='webdb',
            unix_socket='/Applications/XAMPP/xamppfiles/var/mysql/mysql.sock'
        )
        return connection
    except Error as e:
        print(f"MySQL Bağlantı Hatası: {e}")
        return None

# Kullanıcı Giriş Decorator'ı
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            flash("Bu sayfayı görüntülemek için lütfen giriş yapın.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Admin kontrolü için decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            flash("Bu sayfayı görüntülemek için giriş yapın.", "danger")
            return redirect(url_for("login"))
            
        # Admin kontrolü
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT is_admin FROM users WHERE username = %s", (session["username"],))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user or not user["is_admin"]:
                flash("Bu sayfaya erişim yetkiniz yok.", "danger")
                return redirect(url_for("index"))
                
        except Exception as e:
            print(f"Admin kontrol hatası: {e}")
            return redirect(url_for("index"))
            
        return f(*args, **kwargs)
    return decorated_function

# Form Sınıfları
class RegisterForm(Form):
    name = StringField("İsim Soyisim",validators=[validators.Length(min = 4,max = 25)])
    username = StringField("Kullanıcı Adı",validators=[validators.Length(min = 5,max = 35)])
    email = StringField("Email Adresi",validators=[validators.Email(message = "Lütfen Geçerli Bir Email Adresi Girin...")])
    password = PasswordField("Parola:",validators=[
        validators.DataRequired(message = "Lütfen bir parola belirleyin"),
        validators.EqualTo(fieldname = "confirm",message="Parolanız Uyuşmuyor...")
    ])
    confirm = PasswordField("Parola Doğrula")

class LoginForm(Form):
    username = StringField("Kullanıcı Adı")
    password = PasswordField("Parola")

class EventForm(Form):
    title = StringField("Etkinlik Başlığı", validators=[validators.Length(min=5, max=200)])
    content = TextAreaField("Etkinlik Detayı", validators=[validators.Length(min=10)])
    event_date = StringField("Etkinlik Tarihi", validators=[validators.DataRequired()])
    location = StringField("Etkinlik Yeri", validators=[validators.Length(min=5, max=200)])
    image = FileField("Etkinlik Görseli")

class ProfileForm(Form):
    name = StringField("İsim Soyisim", validators=[validators.Length(min=4, max=25)])
    email = StringField("Email Adresi", validators=[validators.Email(message="Lütfen Geçerli Bir Email Adresi Girin...")])
    profile_image = FileField("Profil Fotoğrafı")

class MessageForm(Form):
    message = TextAreaField("Mesajınız", validators=[validators.DataRequired()])

# Bağlantıyı test et
@app.route("/test_connection")
def test_connection():
    try:
        conn = get_mysql_connection()
        if conn.is_connected():
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            cursor.close()
            conn.close()
            return f"MySQL Bağlantısı Başarılı! Versiyon: {version}"
        else:
            return "Bağlantı kurulamadı!"
    except Exception as e:
        return f"Bağlantı Hatası: {str(e)}"

# Register route'u güncellendi
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)

            # Kullanıcı adı kontrolü
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash("Bu kullanıcı adı zaten alınmış...", "danger")
                return redirect(url_for("register"))

            # Yeni kullanıcı ekleme
            cursor.execute("INSERT INTO users(name,username,mail,password) VALUES(%s,%s,%s,%s)",
                         (name, username, email, password))
            conn.commit()
            
            flash("Başarıyla Kayıt Oldunuz...", "success")
            return redirect(url_for("login"))
        except Error as e:
            flash(f"Bir hata oluştu: {str(e)}", "danger")
            return redirect(url_for("register"))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()

    return render_template("register.html", form=form, title="Kayıt Ol")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    
    if request.method == "POST":
        try:
            username = form.username.data
            password_entered = form.password.data
            
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            
            sorgu = "SELECT * FROM users WHERE username = %s"
            cursor.execute(sorgu, (username,))
            user = cursor.fetchone()
            
            if user:
                real_password = user["password"]
                if sha256_crypt.verify(password_entered, real_password):
                    flash("Başarıyla giriş yaptınız", "success")
                    
                    session["logged_in"] = True
                    session["username"] = username
                    session["is_admin"] = bool(user["is_admin"])  # Admin durumunu session'a ekle
                    
                    cursor.close()
                    conn.close()
                    return redirect(url_for("index"))
                else:
                    flash("Parolanızı yanlış girdiniz", "danger")
            else:
                flash("Böyle bir kullanıcı bulunmuyor", "danger")
                
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"Login hatası: {e}")
            flash("Giriş yaparken bir hata oluştu", "danger")
            
    return render_template("login.html", form=form)

# Ana Sayfa
@app.route("/")
def index():
    upcoming_events = None
    if "logged_in" in session:
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            # Bugünden sonraki 3 etkinliği getir
            sorgu = """
                SELECT * FROM events 
                WHERE event_date >= CURDATE() 
                AND status = 'active' 
                ORDER BY event_date ASC 
                LIMIT 3
            """
            cursor.execute(sorgu)
            upcoming_events = cursor.fetchall()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Hata: {e}")
    
    return render_template("index.html", upcoming_events=upcoming_events)

# Hakkımızda Sayfası
@app.route("/about")
def about():
    return render_template("about.html")

# Etkinliklerimiz Sayfası
@app.route("/event")
def event():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        sorgu = "SELECT * FROM events WHERE status = 'active' AND approved = TRUE ORDER BY event_date ASC"
        cursor.execute(sorgu)
        events = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template("event.html", events=events)
    except Exception as e:
        print(f"Hata: {e}")
        return render_template("event.html", events=None)

# Logout
@app.route("/logout")
def logout():
    try:
        # Oturum bilgilerini temizle
        session.clear()
        flash("Başarıyla çıkış yaptınız", "success")
    except Exception as e:
        print(f"Çıkış yaparken hata: {e}")
        flash("Çıkış yaparken bir hata oluştu", "danger")
    
    # Login sayfasına yönlendir
    return redirect(url_for("login"))

# Profil Sayfası
@app.route("/profile")
@login_required
def profile():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        sorgu = "SELECT * FROM users WHERE username = %s"
        cursor.execute(sorgu, (session["username"],))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            return render_template("profile.html", user=user)
        else:
            return redirect(url_for("index"))
    except Exception as e:
        print(f"Hata: {e}")
        return redirect(url_for("index"))

# Profil düzenleme sayfası
@app.route("/edit_profile", methods=['GET', 'POST'])
@login_required
def edit_profile():
    try:
        # Veritabanından kullanıcı bilgilerini al
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (session['username'],))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            flash("Kullanıcı bilgileri bulunamadı", "danger")
            return redirect(url_for("dashboard"))

        # Form nesnesi oluştur
        form = ProfileForm(request.form)
        
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            
            # Veritabanı bağlantısı
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            
            update_query = "UPDATE users SET name = %s, email = %s"
            update_params = [name, email]

            # Profil fotoğrafı yükleme
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and file.filename != '':
                    if allowed_file(file.filename):
                        # Profil fotoğrafları için klasör kontrolü
                        profile_images_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_images')
                        if not os.path.exists(profile_images_dir):
                            os.makedirs(profile_images_dir)
                        
                        # Benzersiz dosya adı oluştur
                        filename = secure_filename(file.filename)
                        filename = f"{session['username']}_{int(time.time())}_{filename}"
                        file_path = os.path.join(profile_images_dir, filename)
                        
                        # Dosyayı kaydet
                        file.save(file_path)
                        
                        # SQL sorgusunu güncelle
                        update_query += ", profile_image = %s"
                        update_params.append(filename)
                    else:
                        flash("Geçersiz dosya formatı. Lütfen PNG, JPG, JPEG veya GIF formatında bir dosya yükleyin.", "danger")
                        return redirect(url_for("edit_profile"))

            # WHERE koşulunu ekle
            update_query += " WHERE username = %s"
            update_params.append(session['username'])
            
            # Güncelleme sorgusunu çalıştır
            cursor.execute(update_query, tuple(update_params))
            conn.commit()
            cursor.close()
            conn.close()
            
            flash("Profil başarıyla güncellendi", "success")
            return redirect(url_for("dashboard"))
        
        # GET isteği için form alanlarını doldur
        form.name.data = user.get('name', '')
        form.email.data = user.get('email', '')
        
        return render_template("edit_profile.html", form=form, user=user)
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Profil güncellenirken bir hata oluştu", "danger")
        return redirect(url_for("dashboard"))

# Etkinlikleri Listeleme
@app.route("/events")
def events():
    return redirect(url_for("event"))

# Etkinlik Kontrol Paneli
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Kullanıcı bilgilerini al
        cursor.execute("SELECT * FROM users WHERE username = %s", (session["username"],))
        user = cursor.fetchone()
        
        # Kullanıcının etkinliklerini al
        cursor.execute("SELECT * FROM events WHERE author = %s ORDER BY created_date DESC", (session["username"],))
        events = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template("dashboard.html", user=user, events=events)
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Bilgiler yüklenirken bir hata oluştu", "danger")
        return redirect(url_for("index"))

# Etkinlik Ekleme
@app.route("/addevent", methods=["GET", "POST"])
@login_required
def addevent():
    form = EventForm(request.form)
    
    if request.method == "POST" and form.validate():
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            
            title = form.title.data
            content = form.content.data
            event_date = form.event_date.data
            location = form.location.data
            
            # Görsel yükleme işlemi
            image_url = None
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename = f"{session['username']}_{int(time.time())}_{filename}"
                    if not os.path.exists(app.config['UPLOAD_FOLDER']):
                        os.makedirs(app.config['UPLOAD_FOLDER'])
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_url = f"uploads/{filename}"
            
            # Etkinliği ekle, ancak onay durumu false olacak
            sorgu = "INSERT INTO events(title, content, author, event_date, location, image_url, approved) VALUES(%s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sorgu, (title, content, session["username"], event_date, location, image_url, False))
            conn.commit()
            cursor.close()
            conn.close()
            
            flash("Etkinlik başarıyla eklendi, admin onayı bekleniyor.", "success")
            return redirect(url_for("dashboard"))
            
        except Exception as e:
            print(f"Hata: {e}")
            flash("Etkinlik eklenirken bir hata oluştu", "danger")
            
    return render_template("addevent.html", form=form)

# Etkinlik Düzenleme
@app.route("/edit/<string:id>", methods=["GET", "POST"])
@login_required
def edit(id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Etkinliği getir
        sorgu = "SELECT * FROM events WHERE id = %s AND author = %s"
        cursor.execute(sorgu, (id, session["username"]))
        event = cursor.fetchone()
        
        if not event:
            flash("Bu etkinliği düzenleme yetkiniz yok veya etkinlik bulunamadı", "danger")
            return redirect(url_for("dashboard"))
        
        # Form oluştur ve mevcut verilerle doldur
        form = EventForm(request.form)
        
        if request.method == "GET":
            form.title.data = event["title"]
            form.content.data = event["content"]
            form.event_date.data = event["event_date"]
            form.location.data = event["location"]
        
        elif request.method == "POST" and form.validate():
            title = form.title.data
            content = form.content.data
            event_date = form.event_date.data
            location = form.location.data
            
            sorgu2 = "UPDATE events SET title = %s, content = %s, event_date = %s, location = %s WHERE id = %s"
            cursor.execute(sorgu2, (title, content, event_date, location, id))
            conn.commit()
            
            flash("Etkinlik başarıyla güncellendi", "success")
            return redirect(url_for("dashboard"))

        cursor.close()
        conn.close()
        return render_template("edit.html", form=form)
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Etkinlik düzenlenirken bir hata oluştu", "danger")
        return redirect(url_for("dashboard"))

# Etkinlik Silme
@app.route("/delete/<string:id>")
@login_required
def delete(id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Önce etkinliğin sahibi olduğunu kontrol et
        sorgu = "SELECT * FROM events WHERE id = %s AND author = %s"
        cursor.execute(sorgu, (id, session["username"]))
        event = cursor.fetchone()
        
        if event:
            sorgu2 = "DELETE FROM events WHERE id = %s"
            cursor.execute(sorgu2, (id,))
            conn.commit()
            flash("Etkinlik başarıyla silindi", "success")
        else:
            flash("Bu etkinliği silme yetkiniz yok veya etkinlik bulunamadı", "danger")
        
        cursor.close()
        conn.close()
        return redirect(url_for("dashboard"))
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Etkinlik silinirken bir hata oluştu", "danger")
        return redirect(url_for("dashboard"))

# Etkinlik Detay Sayfası
@app.route("/event/<string:id>")
def event_detail(id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        sorgu = "SELECT * FROM events WHERE id = %s"
        cursor.execute(sorgu, (id,))
        event = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if event:
            return render_template("event_detail.html", event=event)
        else:
            flash("Etkinlik bulunamadı", "danger")
            return redirect(url_for("event"))
            
    except Exception as e:
        print(f"Hata: {e}")
        return redirect(url_for("event"))

# Tüm etkinlikleri yönetmek için admin paneli
@app.route("/admin/events")
@admin_required
def admin_events():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM events ORDER BY created_date DESC")
        events = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template("admin_events.html", events=events)
    except Exception as e:
        print(f"Hata: {e}")
        flash("Etkinlikler listelenirken bir hata oluştu", "danger")
        return redirect(url_for("index"))

# Admin etkinlik düzenleme
@app.route("/admin/edit/<string:id>", methods=["GET", "POST"])
@admin_required
def admin_edit(id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        if request.method == "GET":
            cursor.execute("SELECT * FROM events WHERE id = %s", (id,))
            event = cursor.fetchone()
            
            if not event:
                flash("Etkinlik bulunamadı", "danger")
                return redirect(url_for("admin_events"))
                
            form = EventForm()
            form.title.data = event["title"]
            form.content.data = event["content"]
            form.event_date.data = event["event_date"]
            form.location.data = event["location"]
            
            cursor.close()
            conn.close()
            return render_template("admin_edit.html", form=form, event=event)
            
        elif request.method == "POST":
            form = EventForm(request.form)
            if form.validate():
                title = form.title.data
                content = form.content.data
                event_date = form.event_date.data
                location = form.location.data
                
                # Görsel işleme
                image_url = None
                if 'image' in request.files:
                    file = request.files['image']
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        filename = f"admin_{int(time.time())}_{filename}"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        image_url = f"uploads/{filename}"
                
                if image_url:
                    cursor.execute("UPDATE events SET title = %s, content = %s, event_date = %s, location = %s, image_url = %s WHERE id = %s",
                                 (title, content, event_date, location, image_url, id))
                else:
                    cursor.execute("UPDATE events SET title = %s, content = %s, event_date = %s, location = %s WHERE id = %s",
                                 (title, content, event_date, location, id))
                
                conn.commit()
                flash("Etkinlik başarıyla güncellendi", "success")
                return redirect(url_for("admin_events"))
                
    except Exception as e:
        print(f"Hata: {e}")
        flash("Etkinlik düzenlenirken bir hata oluştu", "danger")
    
    return redirect(url_for("admin_events"))

@app.route("/admin/approve/<string:id>")
@admin_required
def approve_event(id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Etkinliği onayla
        cursor.execute("UPDATE events SET approved = TRUE WHERE id = %s", (id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        flash("Etkinlik başarıyla onaylandı", "success")
        return redirect(url_for("admin_events"))
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Etkinlik onaylanırken bir hata oluştu", "danger")
        return redirect(url_for("admin_events"))

# Mesaj Gönderme Route'u
@app.route("/message/<int:event_id>", methods=["GET", "POST"])
@login_required
def send_message(event_id):
    form = MessageForm(request.form)
    
    if request.method == "POST" and form.validate():
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            
            message = form.message.data
            
            # Mesajı kaydet
            # Alıcı olarak etkinliğin sahibini kullan
            cursor.execute("SELECT author FROM events WHERE id = %s", (event_id,))
            event = cursor.fetchone()
            if event:
                receiver = event['author']
                # Mesajı her iki tarafa da kaydet
                cursor.execute("INSERT INTO messages (sender, receiver, event_id, message) VALUES (%s, %s, %s, %s)",
                               (session["username"], receiver, event_id, message))
                cursor.execute("INSERT INTO messages (sender, receiver, event_id, message) VALUES (%s, %s, %s, %s)",
                               (receiver, session["username"], event_id, message))  # Yanıtı da kaydet
                conn.commit()
                flash("Mesaj başarıyla gönderildi", "success")
            else:
                flash("Etkinlik bulunamadı", "danger")
            
            cursor.close()
            conn.close()
            return redirect(url_for("event_detail", id=event_id))
            
        except Exception as e:
            print(f"Hata: {e}")
            flash("Mesaj gönderilirken bir hata oluştu", "danger")
    
    return render_template("send_message.html", form=form, event_id=event_id)

# Mesajları Görüntüleme Route'u
@app.route("/messages")
@login_required
def view_messages():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Kullanıcının aldığı mesajları al
        cursor.execute("SELECT * FROM messages WHERE receiver = %s ORDER BY created_at DESC", (session["username"],))
        received_messages = cursor.fetchall()
        
        # Kullanıcının gönderdiği mesajları al
        cursor.execute("SELECT * FROM messages WHERE sender = %s ORDER BY created_at DESC", (session["username"],))
        sent_messages = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template("view_messages.html", received_messages=received_messages, sent_messages=sent_messages)
        
    except Exception as e:
        print(f"Hata: {e}")
        flash("Mesajlar yüklenirken bir hata oluştu", "danger")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5001, debug=True)