import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(

    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# database code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()
cursor.executescript(""" 
CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoverykey TEXT NOT NULL);
""")
cursor.executescript(""" 
CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);
""")
# hashing password


def hashpassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash


# windowssss
window = Tk()
window.title("Mr.Anish Manager")


def resetscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")
    text = Label(window, text="Enter Recovery Key")
    text.config(anchor=CENTER)
    text.pack()
    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    text1 = Label(window)
    text1.config(anchor=CENTER)
    text1.pack()

    def getrecoverykey():
        recoverykeycheck = hashpassword(str(txt.get()).encode('utf-8'))
        cursor.execute(
            'SELECT * FROM masterpassword WHERE id = 1 AND recoverykey = ?', [(recoverykeycheck)])
        return cursor.fetchall()

    def checkRecoverkey():
        checked = getrecoverykey()
        if checked:
            firstscreen()
        else:
            txt.delete(0, 'end')
            text1.config(text='Wrong Key')

    button = Button(window, text="Check Key", command=checkRecoverkey)

    button.pack(pady=10)

# for login screen


def login():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x200")
    text = Label(window, text="Enter your main Password.")
    text.config(anchor=CENTER)
    text.pack(pady=20)
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    text1 = Label(window)
    text1.pack()

    def getmasterpassword():
        checkhashed = hashpassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(
            kdf.derive(txt.get().encode()))
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkhashed)])

        return cursor.fetchall()

    def checkpassword():
        password = getmasterpassword()

        if password:
            Passwordstorage()
        else:
            txt.delete(0, 'end')
            text1.config(text="Wrong Password")

    def resetpassword():
        resetscreen()

    button = Button(window, text="SUBMIT", command=checkpassword)
    button.pack(pady=10)
    button = Button(window, text="Reset Password", command=resetpassword)
    button.pack(pady=5)

# password vault


def Passwordstorage():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        tx1 = "Website"
        tx2 = "Username"
        tx3 = "Password"

        website = encrypt(popup(tx1).encode(), encryptionKey)
        username = encrypt(popup(tx2).encode(), encryptionKey)
        password = encrypt(popup(tx3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?,?,?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        Passwordstorage()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        Passwordstorage()

    window.geometry("700x350")
    window.resizable(height=None, width=None)
    txt1 = Label(window, text="Password storage")
    txt1.grid(column=1)
    butten = Button(window, text="+", command=addEntry)
    butten.grid(column=1, pady=10)

    lbla = Label(window, text="Website")
    lbla.grid(row=2, column=0, padx=80)
    lbla = Label(window, text="Username")
    lbla.grid(row=2, column=1, padx=80)
    lbla = Label(window, text="Password")
    lbla.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()
            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(
                decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i+3)
            lbl1 = Label(window, text=(
                decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=1, row=i+3)
            lbl1 = Label(window, text=(
                decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=2, row=i+3)

            btn = Button(window, text="Delete",
                         command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i+3, pady=10)
            i = i+1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


# for the 1st time starting

def firstscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x250")
    text = Label(window, text="Create your LogIn Password")
    text.config(anchor=CENTER)
    text.pack(pady=25)

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    text1 = Label(window, text="Re-enter the Password")
    text1.pack(pady=30)

    text2 = Entry(window, width=20, show="*")
    text2.pack()
    text2.focus()

    def savePassword():
        if txt.get() == text2.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedpass = hashpassword(txt.get().encode('utf-8'))

            key = str(uuid.uuid4().hex)
            recoverykey = hashpassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoverykey)
        VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedpass), (recoverykey)))
            db.commit()

            recoveryScreen(key)
        else:
            text.config(text="Password doesn't match")

    button = Button(window, text="SAVE", command=savePassword)
    button.pack(pady=10)


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x250")
    text = Label(window, text="Save this key to recover account")
    text.config(anchor=CENTER)
    text.pack()

    text1 = Label(window, text=key)
    text1.config(anchor=CENTER)
    text1.pack()

    def copykey():
        pyperclip.copy(text1.cget("text"))

    button = Button(window, text="Copy Key", command=copykey)
    button.pack(pady=10)

    def done():
        Passwordstorage()
    button = Button(window, text="Done", command=done)

    button.pack(pady=10)

    # create popUp


def popup(text):
    answer = simpledialog.askstring("input crodiancel", text)
    return answer


# firstscreen()
# login()
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login()
else:
    firstscreen()
window.mainloop()
