import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import json
import os
import hashlib
import string


# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")
ADMIN_NAME = "ADMIN"
AUTHOR = "Бородкин Всеволод, группа ИДБ-23-12"

RESTRICTION_TEXT = ("Пароль не соответствует установленным требованиям:\n"
                    "  • должен содержать хотя бы одну цифру;\n"
                    "  • должен содержать хотя бы один знак препинания.")


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def hash_password(pwd: str) -> str:
    """Возвращает SHA-256 хэш пароля. Пустой пароль остаётся пустым."""
    if pwd == "":
        return ""
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()


def check_password_restrictions(pwd: str) -> bool:
    """Проверяет, что пароль содержит и цифры, и знаки препинания."""
    has_digit = any(c.isdigit() for c in pwd)
    has_punct = any(c in string.punctuation for c in pwd)
    return has_digit and has_punct


# ---------------------------------------------------------------------------
# Хранилище пользователей
# ---------------------------------------------------------------------------
class UserStore:
    def __init__(self, filename: str):
        self.filename = filename
        self.users = []
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("users"), list):
                    self.users = data["users"]
            except (json.JSONDecodeError, OSError):
                self.users = []

        if not self.users:
            # Первый запуск: только администратор с пустым паролем
            self.users = [{
                "name": ADMIN_NAME,
                "password": "",
                "blocked": False,
                "restrict": True
            }]
            self.save()

    def save(self):
        try:
            with open(self.filename, "w", encoding="utf-8") as f:
                json.dump({"users": self.users}, f, ensure_ascii=False, indent=2)
        except OSError as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл данных:\n{e}")

    def find(self, name: str):
        for u in self.users:
            if u["name"] == name:
                return u
        return None


# ---------------------------------------------------------------------------
# Вспомогательные диалоговые окна
# ---------------------------------------------------------------------------
def ask_password(parent, title: str, prompt: str):
    """Окно ввода пароля (символы скрыты). Возвращает строку или None."""
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
    """Диалог ввода нового пароля с подтверждением и проверкой ограничений."""

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
            self.pwd1.set("")
            self.pwd2.set("")
            return
        if self.user.get("restrict") and not check_password_restrictions(p1):
            messagebox.showerror("Ошибка", RESTRICTION_TEXT, parent=self)
            self.pwd1.set("")
            self.pwd2.set("")
            return

        self.result_password = p1
        self.cancelled = False
        self.destroy()

    def on_cancel(self):
        self.cancelled = True
        self.destroy()


def select_user(parent, title: str, prompt: str, users: list):
    """Диалог выбора пользователя из списка. Возвращает dict или None."""
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


# ---------------------------------------------------------------------------
# Окно входа
# ---------------------------------------------------------------------------
class LoginDialog(tk.Toplevel):
    def __init__(self, parent, store: UserStore):
        super().__init__(parent)
        self.store = store
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

    def on_cancel(self):
        self.result = None
        self.destroy()

    def on_login(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Ошибка", "Введите имя пользователя.", parent=self)
            return

        user = self.store.find(name)
        if user is None:
            messagebox.showerror("Ошибка",
                                 f"Пользователь с именем «{name}» не зарегистрирован.\n"
                                 "Введите другое имя или закройте окно.",
                                 parent=self)
            self.name_var.set("")
            self.pwd_var.set("")
            self.name_entry.focus_set()
            return

        if user.get("blocked"):
            messagebox.showerror("Ошибка",
                                 f"Учётная запись «{name}» заблокирована администратором.\n"
                                 "Обратитесь к администратору.",
                                 parent=self)
            return

        # Первый вход — устанавливаем пароль
        if user.get("password", "") == "":
            self.grab_release()
            self.withdraw()
            dlg = PasswordDialog(self.master, "Установка пароля", user, first_login=True)
            self.master.wait_window(dlg)
            if dlg.cancelled:
                self.result = None
                self.destroy()
                return
            user["password"] = hash_password(dlg.result_password)
            self.store.save()
            messagebox.showinfo("Информация", "Пароль успешно установлен.", parent=self.master)
            self.result = user
            self.destroy()
            return

        # Проверка пароля
        if hash_password(self.pwd_var.get()) != user["password"]:
            self.attempts += 1
            if self.attempts >= 3:
                messagebox.showerror("Ошибка",
                                     "Три неверных попытки ввода пароля.\n"
                                     "Программа будет завершена.",
                                     parent=self)
                self.result = None
                self.destroy()
                return
            messagebox.showerror("Ошибка",
                                 f"Неверный пароль.\nПопытка {self.attempts} из 3.",
                                 parent=self)
            self.pwd_var.set("")
            self.pwd_entry.focus_set()
            return

        # Успешный вход
        self.result = user
        self.destroy()


# ---------------------------------------------------------------------------
# Главный класс приложения
# ---------------------------------------------------------------------------
class Application:
    def __init__(self, root: tk.Tk, store: UserStore):
        self.root = root
        self.store = store
        self.current_user = None

        self.root.withdraw()
        self.root.title("Система разграничения полномочий")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)

        self.login()

    # ------- выход -------
    def exit_app(self):
        self.root.destroy()

    # ------- вход -------
    def login(self):
        dlg = LoginDialog(self.root, self.store)
        self.root.wait_window(dlg)
        if dlg.result is None:
            self.exit_app()
            return
        self.current_user = dlg.result
        self.build_ui()

    # ------- построение интерфейса -------
    def build_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        user = self.current_user
        is_admin = (user["name"] == ADMIN_NAME)
        role = "Администратор" if is_admin else "Пользователь"

        self.root.title(f"Разграничение полномочий — {user['name']} ({role})")
        self.root.geometry("720x500")

        menubar = tk.Menu(self.root)

        # Меню "Пароль"
        pwd_menu = tk.Menu(menubar, tearoff=0)
        pwd_menu.add_command(label="Сменить пароль", command=self.change_own_password)
        menubar.add_cascade(label="Пароль", menu=pwd_menu)

        # Меню "Пользователи" — только для администратора
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

        # Меню "Справка"
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        # Меню "Выход"
        exit_menu = tk.Menu(menubar, tearoff=0)
        exit_menu.add_command(label="Завершить работу", command=self.exit_app)
        menubar.add_cascade(label="Выход", menu=exit_menu)

        self.root.config(menu=menubar)

        # Содержимое окна
        content = tk.Frame(self.root)
        content.pack(fill="both", expand=True, padx=25, pady=25)

        tk.Label(content, text=f"Добро пожаловать, {user['name']}!",
                 font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 15))

        if is_admin:
            info = ("Вы вошли как АДМИНИСТРАТОР.\n\n"
                    "Доступные действия:\n"
                    "  • управление списком пользователей (меню «Пользователи»);\n"
                    "  • блокировка / разблокировка учётных записей;\n"
                    "  • включение / отключение ограничений на пароли;\n"
                    "  • добавление новых пользователей;\n"
                    "  • смена собственного пароля (меню «Пароль»).")
        else:
            info = ("Вы вошли как ОБЫЧНЫЙ ПОЛЬЗОВАТЕЛЬ.\n\n"
                    "Доступные действия:\n"
                    "  • смена собственного пароля (меню «Пароль»).\n\n"
                    "Остальные функции доступны только администратору.")

        tk.Label(content, text=info, justify="left", font=("Arial", 11)).pack(anchor="w")

        # Строка состояния
        status = tk.Label(self.root,
                          text=f"  Пользователь: {user['name']}   |   Роль: {role}",
                          bd=1, relief=tk.SUNKEN, anchor="w")
        status.pack(side="bottom", fill="x")

        self.root.deiconify()

    # ------- общие действия -------
    def change_own_password(self):
        user = self.current_user
        # Запрос старого пароля
        old = ask_password(self.root, "Смена пароля",
                           "Введите текущий пароль:")
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
        self.store.save()
        messagebox.showinfo("Готово", "Пароль успешно изменён.", parent=self.root)

    def about(self):
        messagebox.showinfo(
            "О программе",
            "Программа разграничения полномочий пользователей\n"
            "на основе парольной аутентификации.\n\n"
            f"Автор: {AUTHOR}\n\n"
            "Вариант индивидуального задания:\n"
            "ограничение на выбираемые пароли —\n"
            "наличие цифр и знаков препинания.",
            parent=self.root)

    # ------- действия администратора -------
    def _require_admin(self) -> bool:
        if self.current_user["name"] != ADMIN_NAME:
            messagebox.showerror("Доступ запрещён",
                                 "Данное действие доступно только администратору.",
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

        for u in self.store.users:
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
        if not self.store.users:
            messagebox.showinfo("Информация", "Список пользователей пуст.", parent=self.root)
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Просмотр пользователей по одному")
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
                ("Заблокирован:", blocked_var), ("Ограничения паролей:", restrict_var)]
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
            u = self.store.users[idx[0]]
            name_var.set(u["name"])
            pwd_var.set("(не задан)" if u.get("password", "") == "" else "********")
            blocked_var.set("Да" if u.get("blocked") else "Нет")
            restrict_var.set("Включены" if u.get("restrict") else "Отключены")
            pos_var.set(f"Запись {idx[0] + 1} из {len(self.store.users)}")

        def go_first(): idx[0] = 0; update()
        def go_prev():
            if idx[0] > 0:
                idx[0] -= 1; update()
        def go_next():
            if idx[0] < len(self.store.users) - 1:
                idx[0] += 1; update()
        def go_last(): idx[0] = len(self.store.users) - 1; update()

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
        if self.store.find(name) is not None:
            messagebox.showerror("Ошибка",
                                 f"Пользователь с именем «{name}» уже существует.",
                                 parent=self.root)
            return

        self.store.users.append({
            "name": name,
            "password": "",       # пустой пароль
            "blocked": False,
            "restrict": True      # по умолчанию ограничения включены
        })
        self.store.save()
        messagebox.showinfo("Готово",
                            f"Пользователь «{name}» добавлен с пустым паролем.\n"
                            "При первом входе он должен будет задать пароль.",
                            parent=self.root)

    def block_user(self):
        if not self._require_admin():
            return
        candidates = [u for u in self.store.users
                      if not u.get("blocked") and u["name"] != ADMIN_NAME]
        if not candidates:
            messagebox.showinfo("Информация",
                                "Нет пользователей, доступных для блокировки.",
                                parent=self.root)
            return

        u = select_user(self.root, "Блокировка пользователя",
                        "Выберите пользователя для блокировки:", candidates)
        if u is None:
            return
        u["blocked"] = True
        self.store.save()
        messagebox.showinfo("Готово",
                            f"Учётная запись «{u['name']}» заблокирована.",
                            parent=self.root)

    def unblock_user(self):
        if not self._require_admin():
            return
        candidates = [u for u in self.store.users if u.get("blocked")]
        if not candidates:
            messagebox.showinfo("Информация",
                                "Нет заблокированных пользователей.",
                                parent=self.root)
            return

        u = select_user(self.root, "Разблокировка пользователя",
                        "Выберите пользователя для разблокировки:", candidates)
        if u is None:
            return
        u["blocked"] = False
        self.store.save()
        messagebox.showinfo("Готово",
                            f"Учётная запись «{u['name']}» разблокирована.",
                            parent=self.root)

    def toggle_restrictions(self):
        if not self._require_admin():
            return
        if not self.store.users:
            return
        u = select_user(self.root, "Ограничения паролей",
                        "Выберите пользователя, для которого нужно\n"
                        "включить или отключить ограничения на пароли:",
                        self.store.users)
        if u is None:
            return
        u["restrict"] = not u.get("restrict", False)
        self.store.save()
        state = "включены" if u["restrict"] else "отключены"
        messagebox.showinfo("Готово",
                            f"Ограничения на пароли для «{u['name']}» {state}.",
                            parent=self.root)


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------
def main():
    store = UserStore(DATA_FILE)
    root = tk.Tk()
    Application(root, store)
    root.mainloop()


if __name__ == "__main__":
    main()


