import os, sqlite3, secrets, hashlib, hmac
from functools import wraps
from flask import Flask, request, jsonify, session, render_template, g
app=Flask(__name__); app.secret_key=os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE","0")=="1",MAX_CONTENT_LENGTH=12*1024*1024)
DB=os.environ.get("DATABASE_PATH","swall.sqlite3"); OWNER="SantasWall2006"; SALT="6d7d1cbba6b02d5d17f453a37fcfcf13"; OWNER_HASH="c5044fe75111bbd4173909249ddf1e3f4959be876b2ca496523cf7e1191b7cd2"
def hashpw(p,s): return hashlib.pbkdf2_hmac("sha256",p.encode(),s.encode(),310000).hex()
def conn():
 if "db" not in g: g.db=sqlite3.connect(DB); g.db.row_factory=sqlite3.Row; g.db.execute("PRAGMA foreign_keys=ON")
 return g.db
@app.teardown_appcontext
def close(e):
 d=g.pop("db",None)
 if d:d.close()
def init():
 d=sqlite3.connect(DB); d.executescript("""
 CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,login TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'reader');
 CREATE TABLE IF NOT EXISTS works(id INTEGER PRIMARY KEY,title TEXT NOT NULL,kind TEXT,genre TEXT,description TEXT,author TEXT);
 CREATE TABLE IF NOT EXISTS chapters(id INTEGER PRIMARY KEY,work_id INTEGER NOT NULL,title TEXT,body TEXT,FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE);
 CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY,work_id INTEGER NOT NULL,author TEXT,body TEXT,FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE);
 """)
 d.execute("INSERT OR IGNORE INTO users(login,password_hash,role) VALUES(?,?,?)",(OWNER,hashpw("Slojenikina2006",SALT),"owner"))
 d.execute("UPDATE users SET role='owner' WHERE login=?",(OWNER,))
 if d.execute("SELECT COUNT(*) FROM works").fetchone()[0]==0:
  d.executemany("INSERT INTO works(title,kind,genre,description,author) VALUES(?,?,?,?,?)",[
  ("Тень в моём сердце","Новелла","Романтика · Драма","Она была светом в его тьме. История о любви, которая родилась между болью и надеждой.","S. 壁"),
  ("Ледяная клятва","Манхва","Фэнтези · Приключения","Клятва, данная среди вечных снегов. Древняя магия пробуждается вместе с наследником забытого престола.","S. 壁"),
  ("Белый лотос","Новелла","Фэнтези · Романтика","Легенда о цветке, который расцветает лишь однажды за тысячу лет.","S. 壁"),
  ("Пепел и звёзды","Манхва","Мистика · Драма","В городе, где звёзды больше не отражаются в воде, кто-то помнит настоящее небо.","S. 壁")])
 d.commit();d.close()
def me():
 if not session.get("uid"):return None
 return conn().execute("SELECT id,login,role FROM users WHERE id=?",(session["uid"],)).fetchone()
def need(role="reader"):
 def deco(fn):
  @wraps(fn)
  def wrap(*a,**k):
   u=me()
   if not u:return jsonify(error="Сначала войдите в аккаунт."),401
   if role=="owner" and u["role"]!="owner":return jsonify(error="Это действие доступно только владельцу."),403
   return fn(*a,**k)
  return wrap
 return deco
@app.get("/")
def index():return render_template("index.html")
@app.get("/health")
def health():return {"ok":True}
@app.get("/api/me")
def who():
 u=me();return jsonify(user={"login":u["login"],"role":u["role"]} if u else None)
@app.post("/api/register")
def register():
 d=request.get_json(force=True); login=str(d.get("login","")).strip(); pw=str(d.get("password",""))
 if len(login)<3 or len(login)>40 or len(pw)<8:return jsonify(error="Логин: 3–40 символов, пароль: минимум 8."),400
 if login.casefold()==OWNER.casefold():return jsonify(error="Этот логин зарезервирован."),400
 try:
  cur=conn().execute("INSERT INTO users(login,password_hash,role) VALUES(?,?,?)",(login,(lambda s:s+"$"+hashpw(pw,s))(secrets.token_hex(16)),"reader"));conn().commit();session.clear();session["uid"]=cur.lastrowid
  return jsonify(ok=True,user={"login":login,"role":"reader"})
 except sqlite3.IntegrityError:return jsonify(error="Такой логин уже занят."),409
@app.post("/api/login")
def login():
 d=request.get_json(force=True); name=str(d.get("login","")).strip(); pw=str(d.get("password",""))
 u=conn().execute("SELECT * FROM users WHERE login=? COLLATE NOCASE",(name,)).fetchone()
 if not u:return jsonify(error="Неверный логин или пароль."),401
 if u["login"]==OWNER: valid=hmac.compare_digest(hashpw(pw,SALT),OWNER_HASH)
 else:
  try:
   salt,expected=u["password_hash"].split("$",1);valid=hmac.compare_digest(hashpw(pw,salt),expected)
  except: valid=False
 if not valid:return jsonify(error="Неверный логин или пароль."),401
 session.clear();session["uid"]=u["id"];return jsonify(ok=True,user={"login":u["login"],"role":u["role"]})
@app.post("/api/logout")
def logout():session.clear();return jsonify(ok=True)
@app.get("/api/works")
def works():
 rows=conn().execute("SELECT w.*,(SELECT COUNT(*) FROM chapters c WHERE c.work_id=w.id) chapter_count FROM works w ORDER BY id DESC").fetchall()
 return jsonify(works=[dict(x) for x in rows])
@app.get("/api/works/<int:i>")
def work(i):
 w=conn().execute("SELECT * FROM works WHERE id=?",(i,)).fetchone()
 if not w:return jsonify(error="Не найдено."),404
 c=conn().execute("SELECT * FROM chapters WHERE work_id=? ORDER BY id",(i,)).fetchall();cm=conn().execute("SELECT * FROM comments WHERE work_id=? ORDER BY id DESC",(i,)).fetchall()
 return jsonify(work=dict(w),chapters=[dict(x) for x in c],comments=[dict(x) for x in cm])
@app.post("/api/works")
@need("owner")
def create():
 d=request.get_json(force=True);t=str(d.get("title","")).strip()
 if not t:return jsonify(error="Нужно название."),400
 cur=conn().execute("INSERT INTO works(title,kind,genre,description,author) VALUES(?,?,?,?,?)",(t,d.get("kind","Новелла"),d.get("genre",""),d.get("description",""),"S. 壁"));conn().commit();return jsonify(ok=True,id=cur.lastrowid)
@app.put("/api/works/<int:i>")
@need("owner")
def update(i):
 d=request.get_json(force=True);c=conn().execute("UPDATE works SET title=?,kind=?,genre=?,description=? WHERE id=?",(d.get("title",""),d.get("kind","Новелла"),d.get("genre",""),d.get("description",""),i));conn().commit()
 return (jsonify(ok=True) if c.rowcount else (jsonify(error="Не найдено."),404))
@app.delete("/api/works/<int:i>")
@need("owner")
def delete(i):conn().execute("DELETE FROM works WHERE id=?",(i,));conn().commit();return jsonify(ok=True)
@app.post("/api/works/<int:i>/chapters")
@need("owner")
def chapter(i):
 d=request.get_json(force=True)
 if not conn().execute("SELECT id FROM works WHERE id=?",(i,)).fetchone():return jsonify(error="Не найдено."),404
 conn().execute("INSERT INTO chapters(work_id,title,body) VALUES(?,?,?)",(i,d.get("title","Глава"),d.get("body","")));conn().commit();return jsonify(ok=True)
@app.delete("/api/chapters/<int:i>")
@need("owner")
def delchapter(i):conn().execute("DELETE FROM chapters WHERE id=?",(i,));conn().commit();return jsonify(ok=True)
@app.post("/api/works/<int:i>/comments")
@need()
def comment(i):
 d=request.get_json(force=True);u=me();b=str(d.get("body","")).strip()
 if not b:return jsonify(error="Пустой комментарий."),400
 conn().execute("INSERT INTO comments(work_id,author,body) VALUES(?,?,?)",(i,u["login"],b));conn().commit();return jsonify(ok=True)
if __name__=="__main__":
 init();app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")))


init()
