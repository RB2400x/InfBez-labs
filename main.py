# -*- coding: utf-8 -*-

import ctypes
from ctypes import wintypes
import os
import json
import hashlib
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


# ===========================================================================
# Константы
# ===========================================================================
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.dat")
TEMP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.tmp")

ADMIN_NAME = "ADMIN"
AUTHOR = "Бородкин Всеволод, группа ИДБ-23-12"

RESTRICTION_TEXT = ("Пароль не соответствует установленным требованиям:\n"
                    "  • должен содержать хотя бы одну цифру;\n"
                    "  • должен содержать хотя бы один знак препинания.")


# ===========================================================================
# Константы CryptoAPI
# ===========================================================================
PROV_RSA_FULL = 1
CRYPT_VERIFYCONTEXT = 0xF0000000
CRYPT_NEWKEYSET = 0x00000008
CRYPT_EXPORTABLE = 0x00000001
CRYPT_CREATE_SALT = 0x00000004

CALG_MD2 = 32769
CALG_RC4 = 0x00006801
CALG_RC2 = 0x00006602

KP_MODE = 4
KP_SALT = 8

CRYPT_MODE_CFB = 4

HP_HASHVAL = 0x0002


# ===========================================================================
# Загрузка библиотек CryptoAPI
# ===========================================================================
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

HCRYPTPROV = wintypes.HANDLE
HCRYPTHASH = wintypes.HANDLE
HCRYPTKEY = wintypes.HANDLE
ALG_ID = wintypes.DWORD
BOOL = wintypes.BOOL
DWORD = wintypes.DWORD
LPCWSTR = wintypes.LPCWSTR
BYTE = ctypes.c_ubyte
PBYTE = ctypes.POINTER(BYTE)


# ---- Прототипы функций ----
advapi32.CryptAcquireContextW.argtypes = [
    ctypes.POINTER(HCRYPTPROV), LPCWSTR, LPCWSTR,
    DWORD, DWORD
]
advapi32.CryptAcquireContextW.restype = BOOL

advapi32.CryptReleaseContext.argtypes = [HCRYPTPROV, DWORD]
advapi32.CryptReleaseContext.restype = BOOL

advapi32.CryptCreateHash.argtypes = [
    HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD,
    ctypes.POINTER(HCRYPTHASH)
]
advapi32.CryptCreateHash.restype = BOOL

advapi32.CryptHashData.argtypes = [
    HCRYPTHASH, PBYTE, DWORD, DWORD
]
advapi32.CryptHashData.restype = BOOL

advapi32.CryptDestroyHash.argtypes = [HCRYPTHASH]
advapi32.CryptDestroyHash.restype = BOOL

advapi32.CryptDeriveKey.argtypes = [
    HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD,
    ctypes.POINTER(HCRYPTKEY)
]
advapi32.CryptDeriveKey.restype = BOOL

advapi32.CryptSetKeyParam.argtypes = [
    HCRYPTKEY, DWORD, PBYTE, DWORD
]
advapi32.CryptSetKeyParam.restype = BOOL

advapi32.CryptEncrypt.argtypes = [
    HCRYPTKEY, HCRYPTHASH, BOOL, DWORD,
    PBYTE, ctypes.POINTER(DWORD), DWORD
]
advapi32.CryptEncrypt.restype = BOOL

advapi32.CryptDecrypt.argtypes = [
    HCRYPTKEY, HCRYPTHASH, BOOL, DWORD,
    PBYTE, ctypes.POINTER(DWORD)
]
advapi32.CryptDecrypt.restype = BOOL

advapi32.CryptDestroyKey.argtypes = [HCRYPTKEY]
advapi32.CryptDestroyKey.restype = BOOL

advapi32.CryptGenRandom.argtypes = [
    HCRYPTPROV, DWORD, PBYTE
]
advapi32.CryptGenRandom.restype = BOOL


# ===========================================================================
# Обёртки CryptoAPI
# ===========================================================================
def _raise_last_error(msg: str):
    err = ctypes.get_last_error()
    raise OSError(f"{msg} (код ошибки Windows: {err})")


class CryptoSession:
    """Управляет криптопровайдером и сеансовым ключом."""

    def __init__(self, passphrase: str):
        self.hProv = HCRYPTPROV()
        self.hHash = HCRYPTHASH()
        self.hKey = HCRYPTKEY()
        self._acquire_provider()
        try:
            self._create_hash(passphrase)
            self._derive_key()
            self._set_cfb_mode()
        except Exception:
            self.release()
            raise

    # ---- Провайдер ----
    def _acquire_provider(self):
        if not advapi32.CryptAcquireContextW(
            ctypes.byref(self.hProv), None, None,
            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        ):
            _raise_last_error("CryptAcquireContext не выполнен")

    # ---- Хеш MD2 ----
    def _create_hash(self, passphrase: str):
        if not advapi32.CryptCreateHash(
            self.hProv, CALG_MD2, HCRYPTHASH(0), 0,
            ctypes.byref(self.hHash)
        ):
            _raise_last_error("CryptCreateHash (MD2) не выполнен")

        data = passphrase.encode("utf-8")
        n = len(data)
        buf = (BYTE * n).from_buffer_copy(data)
        if not advapi32.CryptHashData(self.hHash, buf, n, 0):
            _raise_last_error("CryptHashData не выполнен")

    # ---- Сеансовый ключ ----
    def _derive_key(self):
        # RC4 — поточный шифр; для демонстрации блочного режима
        # используем RC2 (блочный шифр) с флагом создания salt.
        flags = CRYPT_EXPORTABLE | CRYPT_CREATE_SALT
        if not advapi32.CryptDeriveKey(
            self.hProv, CALG_RC2, self.hHash, flags,
            ctypes.byref(self.hKey)
        ):
            _raise_last_error("CryptDeriveKey (RC2) не выполнен")

    # ---- Режим CFB ----
    def _set_cfb_mode(self):
        mode = DWORD(CRYPT_MODE_CFB)
        if not advapi32.CryptSetKeyParam(
            self.hKey, KP_MODE,
            ctypes.cast(ctypes.byref(mode), PBYTE), 0
        ):
            _raise_last_error("CryptSetKeyParam (KP_MODE / CFB) не выполнен")

    # ---- Шифрование ----
    def encrypt(self, plaintext: bytes) -> bytes:
        n = len(plaintext)
        buf = (BYTE * (n + 64)).from_buffer_copy(plaintext + b"\x00" * 64)
        buf_len = DWORD(n)
        if not advapi32.CryptEncrypt(
            self.hKey, HCRYPTHASH(0), True, 0,
            buf, ctypes.byref(buf_len), DWORD(n + 64)
        ):
            _raise_last_error("CryptEncrypt не выполнен")
        return bytes(buf[:buf_len.value])

    # ---- Расшифрование ----
    def decrypt(self, ciphertext: bytes) -> bytes:
        n = len(ciphertext)
        buf = (BYTE * n).from_buffer_copy(ciphertext)
        buf_len = DWORD(n)
        if not advapi32.CryptDecrypt(
            self.hKey, HCRYPTHASH(0), True, 0,
            buf, ctypes.byref(buf_len)
        ):
            _raise_last_error("CryptDecrypt не выполнен")
        return bytes(buf[:buf_len.value])

    # ---- Освобождение ----
    def release(self):
        if self.hKey:
            advapi32.CryptDestroyKey(self.hKey)
            self.hKey = HCRYPTKEY()
        if self.hHash:
            advapi32.CryptDestroyHash(self.hHash)
            self.hHash = HCRYPTHASH()
        if self.hProv:
            advapi32.CryptReleaseContext(self.hProv, 0)
            self.hProv = HCRYPTPROV()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.release()


# ===========================================================================
# Работа с зашифрованным файлом учётных данных
# ===========================================================================
def decrypt_users_file(passphrase: str):
    """
    Расшифровывает файл users.dat во временный файл users.tmp.
    Возвращает список пользователей или None, если парольная фраза неверна.
    """
    if not os.path.exists(DATA_FILE):
        # Первый запуск — файла ещё нет, создаём пустую структуру
        return [{
            "name": ADMIN_NAME,
            "password": "",
            "blocked": False,
            "restrict": True
        }]

    with open(DATA_FILE, "rb") as f:
        ciphertext = f.read()

    try:
        with CryptoSession(passphrase) as session:
            plaintext = session.decrypt(ciphertext)
    except OSError:
        return None

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    users = data.get("users", [])
    # Проверка правильности парольной фразы: в файле должна быть
    # учётная запись администратора.
    if not any(u.get("name") == ADMIN_NAME for u in users):
        return None

    # Сохраняем расшифрованные данные во временный файл
    with open(TEMP_FILE, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, ensure_ascii=False, indent=2)

    return users


def encrypt_users_file(passphrase: str, users: list):
    """Шифрует список пользователей и записывает в DATA_FILE."""
    data = json.dumps({"users": users}, ensure_ascii=False, indent=2).encode("utf-8")
    with CryptoSession(passphrase) as session:
        ciphertext = session.encrypt(data)

    with open(DATA_FILE, "wb") as f:
        f.write(ciphertext)

    # «Старое» содержимое стирается: удаляем временный файл
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)


def wipe_temp_file():
    """Удаляет временный файл с расшифрованными данными."""
    if os.path.exists(TEMP_FILE):
        try:
            os.remove(TEMP_FILE)
        except OSError:
            pass


# ===========================================================================
# Вспомогательные функции
# ===========================================================================
def hash_password(pwd: str) -> str:
    """SHA-256 хэш пароля пользователя. Пустой пароль = пустая строка."""
    if pwd == "":
        return ""
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()


def check_password_restrictions(pwd: str) -> bool:
    """Пароль должен содержать цифры и знаки препинания."""
    has_digit = any(c.isdigit() for c in pwd)
    has_punct = any(c in string.punctuation for c in pwd)
    return has_digit and has_punct


# ===========================================================================
# Диалоговые окна
# ===========================================================================
def ask_passphrase(parent, title: str, prompt: str):
    """Окно ввода парольной фразы (символы скрыты)."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.geometry("450x160")
    dlg.resizable(False, False)
    dlg.grab_set()

    tk.Label(dlg, text=prompt, justify="left", wraplength=420).pack(padx=10, pady=10)
    var = tk.StringVar()
    entry = tk.Entry(dlg, textvariable=var, show="*", width=35)
    entry.pack(padx=10, pady=5)
    entry.focus_set()

    result = {"value": None}

    def on_ok():
        result["value"] = var.get()
        dlg.destroy()

    def on_cancel():
        dlg.destroy()

    frame = tk.Frame(dlg)
    frame.pack(pady=10)
    tk.Button(frame, text="OK", width=10, command=on_ok).pack(side="left", padx=5)
    tk.Button(frame, text="Отмена", width=10, command=on_cancel).pack(side="left", padx=5)

    dlg.bind("<Return>", lambda e: on_ok())
    dlg.protocol("WM_DELETE_WINDOW", on_cancel)
    parent.wait_window(dlg)
    return result["value"]


def ask_password(parent, title: str, prompt: str):
    """Окно ввода пароля пользователя (символы скрыты)."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.geometry("420x150")
    dlg.resizable(False, False)
    dlg.grab_set()

    tk.Label(dlg, text=prompt, justify="left").pack(padx=10, pady=10)
    var = tk.StringVar()
    entry = tk.Entry(dlg, textvariable=var, show="*", width=30)
    entry.pack(padx=10, pady=5)
    entry.focus_set()

    result = {"value": None}

    def on_ok():
        result["value"] = var.get()
        dlg.destroy()

    def on_cancel():
        dlg.destroy()

    frame = tk.Frame(dlg)
    frame.pack(pady=10)
    tk.Button(frame, text="OK", width=10, command=on_ok).pack(side="left", padx=5)
    tk.Button(frame, text="Отмена", width=10, command=on_cancel).pack(side="left", padx=5)

    dlg.bind("<Return>", lambda e: on_ok())
    dlg.protocol("WM_DELETE_WINDOW", on_cancel)
    parent.wait_window(dlg)
    return result["value"]


class PasswordDialog(tk.Toplevel):
    """Ввод нового пароля с подтверждением и проверкой ограничений."""

    def __init__(self, parent, title: str, user: dict, first_login: bool = False):
        super().__init__(parent)
        self.user = user
        self.first_login = first_login
        self.result_password = None
        self.cancelled = True

        self.title(title)
        self.geometry("450x200")
        self.resizable(False, False)

        tk.Label(self, text="Новый пароль:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.pwd1 = tk.StringVar()
        e1 = tk.Entry(self, textvariable=self.pwd1, show="*", width=25)
        e1.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self, text="Подтверждение пароля:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.pwd2 = tk.StringVar()
        e2 = tk.Entry(self, textvariable=self.pwd2, show="*", width=25)
        e2.grid(row=1, column=1, padx=10, pady=10)

        frame = tk.Frame(self)
        frame.grid(row=2, column=0, columnspan=2, pady=15)
        tk.Button(frame, text="OK", width=12, command=self.on_ok).pack(side="left", padx=5)
        cancel_label = "Завершить работу" if first_login else "Отмена"
        tk.Button(frame, text=cancel_label, width=15,
                  command=self.on_cancel).pack(side="left", padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        e1.focus_set()
        self.bind("<Return>", lambda e: self.on_ok())
        self.grab_set()

    def on_ok(self):
        p1 = self.pwd1.get()
        p2 = self.pwd2.get()
        if p1 == "":
            messagebox.showerror("Ошибка", "Пароль не может быть пустым.", parent=self)
            return
        if p1 != p2:
            messagebox.showerror("Ошибка", "Введённые пароли не совпадают.", parent=self)
            self.pwd1.set(""); self.pwd2.set("")
            return
        if self.user.get("restrict") and not check_password_restrictions(p1):
            messagebox.showerror("Ошибка", RESTRICTION_TEXT, parent=self)
            self.pwd1.set(""); self.pwd2.set("")
            return
        self.result_password = p1
        self.cancelled = False
        self.destroy()

    def on_cancel(self):
        self.cancelled = True
        self.destroy()


def select_user(parent, title: str, prompt: str, users: list):
    """Диалог выбора пользователя из списка."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.geometry("400x350")
    dlg.transient(parent)
    dlg.grab_set()

    tk.Label(dlg, text=prompt, justify="left", wraplength=380).pack(padx=10, pady=10)
    listbox = tk.Listbox(dlg, width=40, height=12)
    listbox.pack(padx=10, pady=5, fill="both", expand=True)
    for u in users:
        listbox.insert("end", u["name"])
    if users:
        listbox.selection_set(0)

    result = {"user": None}

    def on_ok():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите пользователя.", parent=dlg)
            return
        result["user"] = users[sel[0]]
        dlg.destroy()

    def on_cancel():
        dlg.destroy()

    frame = tk.Frame(dlg)
    frame.pack(pady=10)
    tk.Button(frame, text="OK", width=10, command=on_ok).pack(side="left", padx=5)
    tk.Button(frame, text="Отмена", width=10, command=on_cancel).pack(side="left", padx=5)

    dlg.bind("<Double-Button-1>", lambda e: on_ok())
    dlg.protocol("WM_DELETE_WINDOW", on_cancel)
    parent.wait_window(dlg)
    return result["user"]


# ===========================================================================
# Окно входа в систему (парольная аутентификация пользователя)
# ===========================================================================
class LoginDialog(tk.Toplevel):
    def __init__(self, parent, users: list):
        super().__init__(parent)
        self.users = users
        self.result = None
        self.attempts = 0

        self.title("Вход в систему")
        self.geometry("430x200")
        self.resizable(False, False)

        tk.Label(self, text="Имя пользователя:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.name_var = tk.StringVar()
        self.name_entry = tk.Entry(self, textvariable=self.name_var, width=25)
        self.name_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self, text="Пароль:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.pwd_var = tk.StringVar()
        self.pwd_entry = tk.Entry(self, textvariable=self.pwd_var, show="*", width=25)
        self.pwd_entry.grid(row=1, column=1, padx=10, pady=10)

        frame = tk.Frame(self)
        frame.grid(row=2, column=0, columnspan=2, pady=15)
        tk.Button(frame, text="Войти", width=12, command=self.on_login).pack(side="left", padx=5)
        tk.Button(frame, text="Выход", width=12, command=self.on_cancel).pack(side="left", padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.name_entry.focus_set()
        self.bind("<Return>", lambda e: self.on_login())
        self.grab_set()

    def find(self, name):
        for u in self.users:
            if u["name"] == name:
                return u
        return None

    def on_cancel(self):
        self.result = None
        self.destroy()

    def on_login(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Ошибка", "Введите имя пользователя.", parent=self)
            return

        user = self.find(name)
        if user is None:
            messagebox.showerror("Ошибка",
                                 f"Пользователь «{name}» не зарегистрирован.\n"
                                 "Введите другое имя или закройте окно.",
                                 parent=self)
            self.name_var.set(""); self.pwd_var.set("")
            self.name_entry.focus_set()
            return

        if user.get("blocked"):
            messagebox.showerror("Ошибка",
                                 f"Учётная запись «{name}» заблокирована.\n"
                                 "Обратитесь к администратору.",
                                 parent=self)
            return

        # Первый вход — установка пароля
        if user.get("password", "") == "":
            self.grab_release(); self.withdraw()
            dlg = PasswordDialog(self.master, "Установка пароля", user, first_login=True)
            self.master.wait_window(dlg)
            if dlg.cancelled:
                self.result = None; self.destroy(); return
            user["password"] = hash_password(dlg.result_password)
            messagebox.showinfo("Информация", "Пароль установлен.", parent=self.master)
            self.result = user
            self.destroy()
            return

        # Проверка пароля
        if hash_password(self.pwd_var.get()) != user["password"]:
            self.attempts += 1
            if self.attempts >= 3:
                messagebox.showerror("Ошибка",
                                     "Три неверных попытки.\nПрограмма будет завершена.",
                                     parent=self)
                self.result = None; self.destroy(); return
            messagebox.showerror("Ошибка",
                                 f"Неверный пароль.\nПопытка {self.attempts} из 3.",
                                 parent=self)
            self.pwd_var.set("")
            self.pwd_entry.focus_set()
            return

        self.result = user
        self.destroy()


# ===========================================================================
# Главное приложение
# ===========================================================================
class Application:
    def __init__(self, root: tk.Tk, passphrase: str, users: list):
        self.root = root
        self.passphrase = passphrase
        self.users = users
        self.current_user = None

        self.root.withdraw()
        self.root.title("Разграничение полномочий (CryptoAPI)")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)

        self.login()

    # ------- завершение -------
    def exit_app(self):
        """Шифрует изменения, стирает временный файл и завершает работу."""
        try:
            encrypt_users_file(self.passphrase, self.users)
        except OSError as e:
            messagebox.showerror("Ошибка",
                                 f"Не удалось сохранить изменения:\n{e}")
        finally:
            wipe_temp_file()
            self.root.destroy()

    # ------- вход -------
    def login(self):
        dlg = LoginDialog(self.root, self.users)
        self.root.wait_window(dlg)
        if dlg.result is None:
            self.exit_app()
            return
        self.current_user = dlg.result
        self.build_ui()

    # ------- интерфейс -------
    def build_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        user = self.current_user
        is_admin = (user["name"] == ADMIN_NAME)
        role = "Администратор" if is_admin else "Пользователь"

        self.root.title(f"CryptoAPI — {user['name']} ({role})")
        self.root.geometry("720x520")

        menubar = tk.Menu(self.root)

        # Меню «Пароль»
        pwd_menu = tk.Menu(menubar, tearoff=0)
        pwd_menu.add_command(label="Сменить пароль", command=self.change_own_password)
        menubar.add_cascade(label="Пароль", menu=pwd_menu)

        # Меню «Пользователи» — только администратор
        if is_admin:
            users_menu = tk.Menu(menubar, tearoff=0)
            users_menu.add_command(label="Показать всех пользователей",
                                   command=self.show_all_users)
            users_menu.add_command(label="Просмотр по одному",
                                   command=self.show_users_one_by_one)
            users_menu.add_separator()
            users_menu.add_command(label="Добавить пользователя",
                                   command=self.add_user)
            users_menu.add_separator()
            users_menu.add_command(label="Блокировать пользователя",
                                   command=self.block_user)
            users_menu.add_command(label="Разблокировать пользователя",
                                   command=self.unblock_user)
            users_menu.add_separator()
            users_menu.add_command(label="Включить/отключить ограничения паролей",
                                   command=self.toggle_restrictions)
            menubar.add_cascade(label="Пользователи", menu=users_menu)

        # Меню «Справка»
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        # Меню «Выход»
        exit_menu = tk.Menu(menubar, tearoff=0)
        exit_menu.add_command(label="Завершить работу", command=self.exit_app)
        menubar.add_cascade(label="Выход", menu=exit_menu)

        self.root.config(menu=menubar)

        # Содержимое
        content = tk.Frame(self.root)
        content.pack(fill="both", expand=True, padx=25, pady=25)

        tk.Label(content, text=f"Добро пожаловать, {user['name']}!",
                 font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 15))

        if is_admin:
            info = ("Вы вошли как АДМИНИСТРАТОР.\n\n"
                    "Доступные действия:\n"
                    "  • управление списком пользователей;\n"
                    "  • блокировка / разблокировка учётных записей;\n"
                    "  • включение / отключение ограничений паролей;\n"
                    "  • добавление новых пользователей;\n"
                    "  • смена собственного пароля.")
        else:
            info = ("Вы вошли как ОБЫЧНЫЙ ПОЛЬЗОВАТЕЛЬ.\n\n"
                    "Доступные действия:\n"
                    "  • смена собственного пароля.\n\n"
                    "Остальные функции доступны только администратору.")

        tk.Label(content, text=info, justify="left", font=("Arial", 11)).pack(anchor="w")

        # Строка состояния
        tk.Label(self.root,
                 text=f"  Пользователь: {user['name']}   |   Роль: {role}"
                      f"   |   Файл данных защищён CryptoAPI (RC2/CFB/MD2)",
                 bd=1, relief=tk.SUNKEN, anchor="w").pack(side="bottom", fill="x")

        self.root.deiconify()

    # ------- общие действия -------
    def change_own_password(self):
        user = self.current_user
        old = ask_password(self.root, "Смена пароля", "Введите текущий пароль:")
        if old is None:
            return
        if hash_password(old) != user.get("password", ""):
            messagebox.showerror("Ошибка", "Неверный текущий пароль.", parent=self.root)
            return
        dlg = PasswordDialog(self.root, "Новый пароль", user, first_login=False)
        self.root.wait_window(dlg)
        if dlg.cancelled:
            return
        user["password"] = hash_password(dlg.result_password)
        messagebox.showinfo("Готово", "Пароль изменён.", parent=self.root)

    def about(self):
        messagebox.showinfo(
            "О программе",
            "Лабораторная работа №3.\n"
            "Защита файла учётных данных средствами CryptoAPI Windows.\n\n"
            f"Автор: {AUTHOR}\n\n"
            "Используемые примитивы:\n"
            "  • тип шифрования — блочный (RC2);\n"
            "  • режим — обратная связь по шифротексту (CFB);\n"
            "  • добавление salt — да (CRYPT_CREATE_SALT);\n"
            "  • хеширование — MD2 (CALG_MD2).",
            parent=self.root)

    # ------- действия администратора -------
    def _require_admin(self) -> bool:
        if self.current_user["name"] != ADMIN_NAME:
            messagebox.showerror("Доступ запрещён",
                                 "Действие доступно только администратору.",
                                 parent=self.root)
            return False
        return True

    def show_all_users(self):
        if not self._require_admin():
            return
        win = tk.Toplevel(self.root)
        win.title("Список зарегистрированных пользователей")
        win.geometry("640x380")
        win.transient(self.root)

        cols = ("name", "password", "blocked", "restrict")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("name", text="Имя пользователя")
        tree.heading("password", text="Пароль")
        tree.heading("blocked", text="Заблокирован")
        tree.heading("restrict", text="Ограничения паролей")
        tree.column("name", width=150, anchor="w")
        tree.column("password", width=130, anchor="center")
        tree.column("blocked", width=130, anchor="center")
        tree.column("restrict", width=180, anchor="center")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        for u in self.users:
            pwd = "(не задан)" if u.get("password", "") == "" else "********"
            tree.insert("", "end", values=(
                u["name"], pwd,
                "Да" if u.get("blocked") else "Нет",
                "Включены" if u.get("restrict") else "Отключены"
            ))

        tk.Button(win, text="Закрыть", width=15, command=win.destroy).pack(pady=8)

    def show_users_one_by_one(self):
        if not self._require_admin():
            return
        if not self.users:
            messagebox.showinfo("Информация", "Список пуст.", parent=self.root)
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Просмотр пользователей")
        dlg.geometry("480x300")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        idx = [0]
        name_var = tk.StringVar()
        pwd_var = tk.StringVar()
        blocked_var = tk.StringVar()
        restrict_var = tk.StringVar()
        pos_var = tk.StringVar()

        rows = [("Имя:", name_var), ("Пароль:", pwd_var),
                ("Заблокирован:", blocked_var), ("Ограничения:", restrict_var)]
        for i, (label, var) in enumerate(rows):
            tk.Label(dlg, text=label, anchor="e", width=20).grid(
                row=i, column=0, padx=10, pady=5, sticky="e")
            tk.Label(dlg, textvariable=var, anchor="w", width=25,
                     relief="sunken", bd=1).grid(
                row=i, column=1, padx=10, pady=5, sticky="w")

        tk.Label(dlg, textvariable=pos_var,
                 font=("Arial", 10, "italic")).grid(
            row=4, column=0, columnspan=2, pady=5)

        def update():
            u = self.users[idx[0]]
            name_var.set(u["name"])
            pwd_var.set("(не задан)" if u.get("password", "") == "" else "********")
            blocked_var.set("Да" if u.get("blocked") else "Нет")
            restrict_var.set("Включены" if u.get("restrict") else "Отключены")
            pos_var.set(f"Запись {idx[0] + 1} из {len(self.users)}")

        def go_first(): idx[0] = 0; update()
        def go_prev():
            if idx[0] > 0: idx[0] -= 1; update()
        def go_next():
            if idx[0] < len(self.users) - 1: idx[0] += 1; update()
        def go_last(): idx[0] = len(self.users) - 1; update()

        frame = tk.Frame(dlg)
        frame.grid(row=5, column=0, columnspan=2, pady=15)
        tk.Button(frame, text="В начало", width=10, command=go_first).pack(side="left", padx=3)
        tk.Button(frame, text="Назад", width=10, command=go_prev).pack(side="left", padx=3)
        tk.Button(frame, text="Вперёд", width=10, command=go_next).pack(side="left", padx=3)
        tk.Button(frame, text="В конец", width=10, command=go_last).pack(side="left", padx=3)
        tk.Button(frame, text="Закрыть", width=10, command=dlg.destroy).pack(side="left", padx=3)

        update()

    def add_user(self):
        if not self._require_admin():
            return
        name = simpledialog.askstring("Добавление пользователя",
                                      "Введите уникальное имя нового пользователя:",
                                      parent=self.root)
        if name is None:
            return
        name = name.strip()
        if not name:
            messagebox.showerror("Ошибка", "Имя не может быть пустым.", parent=self.root)
            return
        for u in self.users:
            if u["name"] == name:
                messagebox.showerror("Ошибка",
                                     f"Пользователь «{name}» уже существует.",
                                     parent=self.root)
                return
        self.users.append({
            "name": name,
            "password": "",
            "blocked": False,
            "restrict": True
        })
        messagebox.showinfo("Готово",
                            f"Пользователь «{name}» добавлен с пустым паролем.",
                            parent=self.root)

    def block_user(self):
        if not self._require_admin():
            return
        candidates = [u for u in self.users
                      if not u.get("blocked") and u["name"] != ADMIN_NAME]
        if not candidates:
            messagebox.showinfo("Информация", "Нет пользователей для блокировки.",
                                parent=self.root)
            return
        u = select_user(self.root, "Блокировка",
                        "Выберите пользователя для блокировки:", candidates)
        if u is None:
            return
        u["blocked"] = True
        messagebox.showinfo("Готово", f"«{u['name']}» заблокирован.", parent=self.root)

    def unblock_user(self):
        if not self._require_admin():
            return
        candidates = [u for u in self.users if u.get("blocked")]
        if not candidates:
            messagebox.showinfo("Информация", "Нет заблокированных пользователей.",
                                parent=self.root)
            return
        u = select_user(self.root, "Разблокировка",
                        "Выберите пользователя для разблокировки:", candidates)
        if u is None:
            return
        u["blocked"] = False
        messagebox.showinfo("Готово", f"«{u['name']}» разблокирован.", parent=self.root)

    def toggle_restrictions(self):
        if not self._require_admin():
            return
        if not self.users:
            return
        u = select_user(self.root, "Ограничения паролей",
                        "Выберите пользователя:", self.users)
        if u is None:
            return
        u["restrict"] = not u.get("restrict", False)
        state = "включены" if u["restrict"] else "отключены"
        messagebox.showinfo("Готово",
                            f"Ограничения для «{u['name']}» {state}.",
                            parent=self.root)


# ===========================================================================
# Точка входа
# ===========================================================================
def main():
    root = tk.Tk()
    root.withdraw()

    # --- Запрос парольной фразы при запуске ---
    passphrase = ask_passphrase(
        root, "Защита файла учётных данных",
        "Введите парольную фразу для расшифрования файла учётных данных.\n"
        "При первом запуске эта фраза будет использована для создания файла."
    )
    if not passphrase:
        messagebox.showerror("Ошибка",
                             "Парольная фраза не введена.\nПрограмма будет завершена.")
        root.destroy()
        return

    # --- Расшифрование файла ---
    users = decrypt_users_file(passphrase)
    if users is None:
        messagebox.showerror("Ошибка",
                             "Неверная парольная фраза\n"
                             "или файл учётных данных повреждён.\n\n"
                             "Программа будет завершена.")
        root.destroy()
        return

    # --- Запуск приложения ---
    app = Application(root, passphrase, users)
    root.mainloop()

    # --- Гарантированная очистка временного файла ---
    wipe_temp_file()


if __name__ == "__main__":
    main()
