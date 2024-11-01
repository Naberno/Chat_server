import configparser
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import ttkthemes
import logging
import json
import os

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        if isinstance(root, ttkthemes.ThemedTk):
            self.root.set_theme("arc")
        self.root.title("Чат-клиент")
        self.root.geometry("800x600")
        self.history_file = "client_chat_history.txt"
        self.config_path = 'config.ini'
        self.init_config()  # Инициализируем конфиг при запуске
        self.conn = None
        self.nickname = None
        self.current_frame = None
        self.receive_thread = None
        self.stop_thread = threading.Event()
        self.chat_area = None

        self.create_menubar()
        self.create_main_frame()
        self.load_login_frame()
        self.root.protocol("WM_DELETE_WINDOW", self.confirm_exit)

    def create_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = ttk.Frame(self.main_frame)
        self.current_frame.pack(fill=tk.BOTH, expand=True)

    def load_login_frame(self, check_saved_credentials=True):
        self.clear_frame()
        if check_saved_credentials:
            email, saved_password = self.load_user_config()
            if email and saved_password:
                self.perform_login(email, saved_password)
                return

        ttk.Label(self.current_frame, text="Добро пожаловать в чат", font=('Arial', 16)).pack(pady=20)
        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Войти", command=self.show_login_fields).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Регистрация", command=self.show_register_fields).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Выход", command=self.root.quit).pack(side=tk.LEFT, padx=10)

    def show_login_fields(self):
        self.clear_frame()
        ttk.Label(self.current_frame, text="Вход", font=('Arial', 16)).pack(pady=20)

        email_frame = ttk.Frame(self.current_frame)
        email_frame.pack(fill=tk.X, pady=5)
        ttk.Label(email_frame, text="Email:").pack(side=tk.LEFT)
        email_entry = ttk.Entry(email_frame)
        email_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        pass_frame = ttk.Frame(self.current_frame)
        pass_frame.pack(fill=tk.X, pady=5)
        ttk.Label(pass_frame, text="Пароль:").pack(side=tk.LEFT)
        pass_entry = ttk.Entry(pass_frame, show="*")
        pass_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        remember_var = tk.BooleanVar()
        ttk.Checkbutton(self.current_frame, text="Запомнить меня", variable=remember_var).pack(pady=5)

        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Войти",
                  command=lambda: self.perform_login(email_entry.get(), pass_entry.get(), remember_var.get())
                  ).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Назад", command=self.load_login_frame).pack(side=tk.LEFT, padx=10)

    def show_register_fields(self):
        self.clear_frame()
        ttk.Label(self.current_frame, text="Регистрация", font=('Arial', 16)).pack(pady=20)

        email_frame = ttk.Frame(self.current_frame)
        email_frame.pack(fill=tk.X, pady=5)
        ttk.Label(email_frame, text="Email:").pack(side=tk.LEFT)
        email_entry = ttk.Entry(email_frame)
        email_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        pass_frame = ttk.Frame(self.current_frame)
        pass_frame.pack(fill=tk.X, pady=5)
        ttk.Label(pass_frame, text="Пароль:").pack(side=tk.LEFT)
        pass_entry = ttk.Entry(pass_frame, show="*")
        pass_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        nick_frame = ttk.Frame(self.current_frame)
        nick_frame.pack(fill=tk.X, pady=5)
        ttk.Label(nick_frame, text="Никнейм:").pack(side=tk.LEFT)
        nick_entry = ttk.Entry(nick_frame)
        nick_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Зарегистрироваться",
                  command=lambda: self.perform_registration(email_entry.get(), pass_entry.get(), nick_entry.get())
                  ).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Назад", command=self.load_login_frame).pack(side=tk.LEFT, padx=10)

    def connect_to_server(self):
        try:
            config = configparser.ConfigParser()
            config.read(self.config_path)
            if 'mysql' not in config:
                messagebox.showerror("Ошибка", "Отсутствуют настройки сервера в config.ini")
                return False

            server_ip = config['mysql']['ip']
            server_port = int(config['mysql']['port'])

            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((server_ip, server_port))
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")
            return False

    def perform_login(self, email, password, remember=False):
        if not email or not password:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return

        if not self.connect_to_server():
            return

        try:
            login_data = {
                "action": "LOGIN",
                "email": email,
                "password": password
            }

            login_request = json.dumps(login_data)

            print(f"Отправка запроса: {login_request}")  # Отладка
            self.conn.send(login_request.encode('utf-8'))

            response = self.conn.recv(1024).decode('utf-8')
            print(f"Получен ответ (сырые данные): {response}")  # Отладка

            # Декодируем JSON-ответ
            response_data = json.loads(response)

            # Декодируем сообщение из Unicode
            decoded_message = response_data["message"].encode('latin1').decode('utf-8')
            print(f"Декодированное сообщение: {decoded_message}")  # Отладка

            if response_data["status"] == "success":
                try:
                    self.nickname = response_data.get("nickname", "")
                    if remember:
                        self.save_user_config(email, password, True)
                    self.show_main_menu()
                except KeyError:
                    messagebox.showerror("Ошибка", "Некорректный ответ от сервера")
            else:
                messagebox.showerror("Ошибка входа", decoded_message)
                self.conn.close()
                self.conn = None

        except json.JSONDecodeError:
            messagebox.showerror("Ошибка", "Получен некорректный ответ от сервера")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при входе: {e}")
            if self.conn:
                self.conn.close()
                self.conn = None

    def logout(self):
        if messagebox.askyesno("Выход", "Вы действительно хотите выйти из аккаунта?"):
            self.stop_thread.set()
            if self.conn:
                try:
                    self.conn.send("LOGOUT".encode('utf-8'))
                    self.conn.close()
                except:
                    pass
            self.conn = None
            self.nickname = None
            self.token = None

            # Удаляем сохраненные учетные данные
            config = configparser.ConfigParser()
            config.read(self.config_path)
            if 'credentials' in config:
                config.remove_section('credentials')
            with open(self.config_path, 'w') as configfile:
                config.write(configfile)

            # Возвращаемся к окну входа
            self.load_login_frame()

    def clear_user_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_path)

        if 'credentials' in config:
            config.remove_section('credentials')  # Удаляем секцию с учетными данными

        with open(self.config_path, 'w') as f:
            config.write(f)

    def view_channels(self):
        if not self.conn:
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return

        try:
            # Отправляем запрос на получение списка каналов
            request = json.dumps({
                "action": "get_channels",
                "token": self.token
            })
            self.conn.send(request.encode('utf-8'))

            # Получаем ответ
            response = self.conn.recv(1024).decode('utf-8')
            response_data = json.loads(response)

            if response_data["status"] == "success":
                channels = response_data.get("channels", [])

                # Очищаем текущий фрейм
                self.clear_frame()

                # Создаем новый фрейм для списка каналов
                channels_frame = ttk.Frame(self.current_frame)
                channels_frame.pack(fill=tk.BOTH, expand=True)

                # Создаем скроллбар
                scrollbar = ttk.Scrollbar(channels_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

                # Создаем список каналов
                channels_listbox = tk.Listbox(channels_frame, yscrollcommand=scrollbar.set)
                channels_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

                # Привязываем скроллбар к списку
                scrollbar.config(command=channels_listbox.yview)

                # Добавляем каналы в список
                for channel in channels:
                    channels_listbox.insert(tk.END, channel)

                # Добавляем кнопку для присоединения к выбранному каналу
                def join_selected_channel():
                    selection = channels_listbox.curselection()
                    if selection:
                        channel = channels_listbox.get(selection[0])
                        self.join_channel(channel)

                join_button = ttk.Button(self.current_frame, text="Присоединиться к каналу", command=join_selected_channel)
                join_button.pack(pady=10)

                # Добавляем кнопку "Назад"
                back_button = ttk.Button(self.current_frame, text="Назад", command=self.show_main_menu)
                back_button.pack(pady=10)

            else:
                messagebox.showerror("Ошибка", response_data.get("message", "Неизвестная ошибка"))

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось получить список каналов: {e}")

    def join_channel(self, channel_name):
        if not self.conn:
            messagebox.showerror("Ошибка", "Нет подключения к серверу")
            return

        try:
            # Отправляем запрос на присоединение к каналу
            request = json.dumps({
                "action": "join_channel",
                "channel": channel_name,
                "token": self.token
            })
            self.conn.send(request.encode('utf-8'))

            # Получаем ответ
            response = self.conn.recv(1024).decode('utf-8')
            response_data = json.loads(response)

            if response_data["status"] == "success":
                messagebox.showinfo("Успех", f"Вы присоединились к каналу {channel_name}")
                self.current_channel = channel_name
                self.show_chat_interface()
            else:
                messagebox.showerror("Ошибка", response_data.get("message", "Неизвестная ошибка"))

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось присоединиться к каналу: {e}")

    def show_chat_interface(self):
        self.clear_frame()

        # Создаем область чата
        self.chat_area = tk.Text(self.current_frame, state=tk.DISABLED)
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        # Создаем поле ввода сообщения
        self.message_entry = ttk.Entry(self.current_frame)
        self.message_entry.pack(fill=tk.X, pady=5)

        # Создаем кнопку отправки сообщения
        send_button = ttk.Button(self.current_frame, text="Отправить", command=self.send_message)
        send_button.pack()

        # Создаем кнопку выхода из канала
        leave_button = ttk.Button(self.current_frame, text="Покинуть канал", command=self.leave_chat)
        leave_button.pack(pady=10)

        # Запускаем поток для приема сообщений
        self.stop_thread = threading.Event()
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def show_main_menu(self):
        self.clear_frame()

        # Обновляем меню
        self.menubar.delete(0, tk.END)

        # Добавляем меню настроек аккаунта
        account_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Настройки аккаунта", menu=account_menu)
        account_menu.add_command(label="Изменить никнейм", command=self.change_nickname_dialog)
        account_menu.add_command(label="Изменить пароль", command=self.change_password_dialog)
        account_menu.add_separator()
        account_menu.add_command(label="Выйти из аккаунта", command=self.logout)

        # Добавляем меню каналов
        channels_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Каналы", menu=channels_menu)
        channels_menu.add_command(label="Список каналов", command=self.view_channels)
        channels_menu.add_command(label="Создать канал", command=self.create_channel_dialog)

        # Добавляем кнопку выхода
        self.menubar.add_command(label=" " * 150, state="disabled")
        self.menubar.add_command(label="Выйти", command=self.confirm_exit)

        # Основной контент
        welcome_label = ttk.Label(
            self.current_frame,
            text=f"Добро пожаловать, {self.nickname}!",
            font=('Arial', 16)
        )
        welcome_label.pack(pady=20)

        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)

        ttk.Button(
            btn_frame,
            text="Просмотр каналов",
            command=self.view_channels
        ).pack(side=tk.LEFT, padx=10)

        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Зарегистрироваться",
                  command=lambda: self.perform_registration(email_entry.get(), pass_entry.get(), nick_entry.get())
                  ).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Назад", command=self.load_login_frame).pack(side=tk.LEFT, padx=10)

    def create_channel_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Создать канал")
        dialog.geometry("300x150")

        ttk.Label(dialog, text="Введите имя канала:").pack(pady=10)
        channel_name_entry = ttk.Entry(dialog)
        channel_name_entry.pack(pady=5)

        def create_channel():
            channel_name = channel_name_entry.get().strip()
            if not channel_name:
                messagebox.showerror("Ошибка", "Имя канала не может быть пустым")
                return

            try:
                # Отправляем запрос на создание канала
                request = json.dumps({
                    "action": "create_channel",
                    "channel": channel_name,
                    "token": self.token  # Используем токен для аутентификации
                })
                self.conn.send(request.encode('utf-8'))

                # Получаем ответ от сервера
                response = self.conn.recv(1024).decode('utf-8')
                response_data = json.loads(response)

                if response_data["status"] == "success":
                    messagebox.showinfo("Успех", f"Канал '{channel_name}' успешно создан!")
                    dialog.destroy()
                    self.view_channels()  # Обновляем список каналов
                else:
                    messagebox.showerror("Ошибка", response_data.get("message", "Неизвестная ошибка"))

            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать канал: {e}")

        ttk.Button(dialog, text="Создать", command=create_channel).pack(pady=10)
        ttk.Button(dialog, text="Отмена", command=dialog.destroy).pack(pady=5)

    def connect_to_server(self):
        try:
            config = configparser.ConfigParser()
            config.read(self.config_path)

            # Проверяем наличие настроек сервера
            server_ip = config.get('server', 'ip', fallback='localhost')  # значение по умолчанию
            server_port = config.getint('server', 'port', fallback=5000)  # значение по умолчанию

            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((server_ip, server_port))
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу: {e}")
            return False

    def perform_login(self, email, password, remember=False):
        if not email or not password:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return

        if not self.connect_to_server():
            return

        try:
            login_data = {
                "action": "LOGIN",
                "email": email,
                "password": password
            }

            login_request = json.dumps(login_data)
            print(f"Отправка запроса: {login_request}")  # Отладка
            self.conn.send(login_request.encode('utf-8'))

            response = self.conn.recv(1024).decode('utf-8')
            print(f"Получен ответ (сырые данные): {response}")  # Отладка

            # Декодируем JSON-ответ
            response_data = json.loads(response)

            if response_data["status"] == "error":
                messagebox.showerror("Ошибка входа", response_data["message"])
                self.conn.close()
                self.conn = None
                return

            if response_data["status"] == "success":
                self.nickname = response_data.get("nickname", "")
                self.token = response_data.get("token")  # Сохраняем токен
                if remember:
                    self.save_user_config(email, password, True)
                self.show_main_menu()
            else:
                messagebox.showerror("Ошибка входа", response_data["message"])
                self.conn.close()
                self.conn = None

        except json.JSONDecodeError:
            messagebox.showerror("Ошибка", "Получен некорректный ответ от сервера")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при входе: {str(e)}")
            if self.conn:
                self.conn.close()
                self.conn = None

    def perform_registration(self, email, password, nickname):
        if not email or not password or not nickname:
            messagebox.showerror("Ошибка", "Заполните все поля")
            return

        if not self.connect_to_server():
            return

        try:
            # Создаем словарь с данными для регистрации
            register_data = {
                "action": "REGISTER",
                "email": email,
                "password": password,
                "nickname": nickname
            }

            # Преобразуем словарь в JSON-строку
            register_request = json.dumps(register_data)

            print(f"Отправка запроса регистрации: {register_request}")  # Отладка
            self.conn.send(register_request.encode('utf-8'))

            # Получаем и декодируем ответ
            response = self.conn.recv(1024).decode('utf-8')
            print(f"Получен ответ (сырые данные): {response}")  # Отладка

            # Парсим JSON-ответ
            response_data = json.loads(response)

            # Используем сообщение напрямую, без дополнительного декодирования
            decoded_message = response_data["message"]
            print(f"Декодированное сообщение: {decoded_message}")  # Отладка

            if response_data["status"] == "verification_needed":
                self.show_verification_code_dialog(email)  # Показать окно для ввода кода
            elif response_data["status"] == "success":
                messagebox.showinfo("Успех", decoded_message)
                self.show_login_fields()
            else:
                messagebox.showerror("Ошибка", decoded_message)

        except json.JSONDecodeError as e:
            print(f"Ошибка декодирования JSON: {e}")  # Отладка
            messagebox.showerror("Ошибка", "Получен некорректный ответ от сервера")
        except Exception as e:
            print(f"Общая ошибка: {e}")  # Отладка
            messagebox.showerror("Ошибка", f"Ошибка при регистрации: {e}")
        finally:
            if self.conn:
                self.conn.close()
                self.conn = None

    def show_verification_code_dialog(self, email):
        dialog = tk.Toplevel(self.root)
        dialog.title("Введите код подтверждения")
        dialog.geometry("300x150")

        ttk.Label(dialog, text="Введите код подтверждения, отправленный на ваш email:").pack(pady=10)
        code_entry = ttk.Entry(dialog)
        code_entry.pack(pady=5)

        def verify_code():
            verification_code = code_entry.get().strip()
            if not verification_code:
                messagebox.showerror("Ошибка", "Введите код подтверждения")
                return

            try:
                # Проверяем, есть ли соединение
                if not self.conn:
                    if not self.connect_to_server():
                        messagebox.showerror("Ошибка", "Не удалось подключиться к серверу")
                        return

                verification_data = {
                    "action": "VERIFY_REGISTRATION",
                    "email": email,
                    "verification_code": verification_code
                }

                verification_request = json.dumps(verification_data)
                self.conn.send(verification_request.encode('utf-8'))

                response = self.conn.recv(1024).decode('utf-8')
                response_data = json.loads(response)

                if response_data["status"] == "success":
                    messagebox.showinfo("Успех", "Регистрация успешно завершена!")
                    dialog.destroy()
                    self.show_login_fields()  # Переход к экрану входа
                else:
                    messagebox.showerror("Ошибка", response_data["message"])

            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при проверке кода: {e}")

        ttk.Button(dialog, text="Подтвердить", command=verify_code).pack(pady=10)
        ttk.Button(dialog, text="Отмена", command=dialog.destroy).pack(pady=5)

    def show_main_menu(self):
        self.clear_frame()

        # Обновляем меню
        self.menubar.delete(0, tk.END)

        # Добавляем меню настроек аккаунта
        account_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Настройки аккаунта", menu=account_menu)
        account_menu.add_command(label="Изменить никнейм", command=self.change_nickname_dialog)
        account_menu.add_command(label="Изменить пароль", command=self.change_password_dialog)
        account_menu.add_separator()
        account_menu.add_command(label="Выйти из аккаунта", command=self.logout)

        # Добавляем меню каналов
        channels_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Каналы", menu=channels_menu)
        channels_menu.add_command(label="Список каналов", command=self.view_channels)
        channels_menu.add_command(label="Создать канал", command=self.create_channel_dialog)

        # Добавляем кнопку выхода
        self.menubar.add_command(label=" " * 150, state="disabled")
        self.menubar.add_command(label="Выйти", command=self.confirm_exit)

        # Основной контент
        welcome_label = ttk.Label(
            self.current_frame,
            text=f"Добро пожаловать, {self.nickname}!",
            font=('Arial', 16)
        )
        welcome_label.pack(pady=20)

        btn_frame = ttk.Frame(self.current_frame)
        btn_frame.pack(pady=20)

        ttk.Button(
            btn_frame,
            text="Просмотр каналов",
            command=self.view_channels
        ).pack(side=tk.LEFT, padx=10)

    def send_message(self):
        if not self.message_entry:
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            # Создаем структурированное сообщение с токеном
            message_data = {
                "action": "send_message",
                "channel": self.current_channel,
                "message": message,
                "token": self.token  # Добавляем сохраненный токен
            }

            # Преобразуем словарь в JSON и отправляем
            formatted_message = json.dumps(message_data)
            self.conn.send(formatted_message.encode('utf-8'))

            # Очищаем поле ввода
            self.message_entry.delete(0, tk.END)

            # Получаем ответ от сервера
            response = self.conn.recv(1024).decode('utf-8')
            response_data = json.loads(response)

            # Обрабатываем ответ
            if response_data["status"] == "error":
                if "token" in response_data["message"].lower():
                    # Если проблема с токеном, можно попробовать переподключиться
                    messagebox.showerror("Ошибка", "Сессия истекла. Необходимо повторно войти в систему")
                    self.show_login_fields()  # Показываем окно входа
                else:
                    messagebox.showerror("Ошибка", response_data["message"])

        except json.JSONDecodeError:
            messagebox.showerror("Ошибка", "Получен некорректный ответ от сервера")
            self.reconnect()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение: {e}")
            self.reconnect()

    def receive_messages(self):
        while not self.stop_thread.is_set():
            try:
                if not self.conn:
                    break

                message = self.conn.recv(1024).decode('utf-8')
                if not message:
                    continue

                print(f"Получено сообщение: {message}")  # Отладка

                if message.startswith("MESSAGE"):
                    _, sender, content = message.split(" ", 2)
                    self.add_message_to_chat(f"{sender}: {content}")
                elif message.startswith("SYSTEM"):
                    _, content = message.split(" ", 1)
                    self.add_message_to_chat(f"[Система] {content}")
                elif message == "PING":
                    self.conn.send("PONG".encode('utf-8'))

            except Exception as e:
                print(f"Ошибка при получении сообщения: {e}")
                if not self.stop_thread.is_set():
                    self.reconnect()
                break

    def add_message_to_chat(self, message):
        if not self.chat_area:
            return

        self.chat_area.configure(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.see(tk.END)
        self.chat_area.configure(state=tk.DISABLED)

        # Сохраняем сообщение в истории
        with open(self.history_file, 'a', encoding='utf-8') as f:
            f.write(f"{message}\n")

    def leave_chat(self):
        try:
            self.conn.send(f"LEAVE_CHANNEL {self.current_channel}".encode('utf-8'))
            self.stop_thread.set()
            if self.receive_thread:
                self.receive_thread.join()
            self.show_main_menu()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при выходе из канала: {e}")

    def reconnect(self):
        """Попытка переподключения к серверу"""
        try:
            if self.conn:
                self.conn.close()

            if self.connect_to_server():
                # Повторная авторизация
                config = configparser.ConfigParser()
                config.read(self.config_path)
                if 'credentials' in config:
                    email = config['credentials']['email']
                    password = config['credentials']['password']
                    self.perform_login(email, password)
            else:
                messagebox.showerror("Ошибка", "Не удалось переподключиться к серверу")
                self.load_login_frame()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при переподключении: {e}")
            self.load_login_frame()

    def change_nickname_dialog(self):
        new_nickname = simpledialog.askstring("Изменить никнейм", "Введите новый никнейм:")
        if new_nickname:
            try:
                self.conn.send(f"CHANGE_NICKNAME {new_nickname}".encode('utf-8'))
                response = self.conn.recv(1024).decode('utf-8')

                if "SUCCESS" in response:
                    self.nickname = new_nickname
                    messagebox.showinfo("Успех", "Никнейм успешно изменен")
                else:
                    messagebox.showerror("Ошибка", response)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось изменить никнейм: {e}")

    def change_password_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Изменить пароль")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="Текущий пароль:").pack(pady=5)
        current_pass = ttk.Entry(dialog, show="*")
        current_pass.pack(pady=5)

        ttk.Label(dialog, text="Новый пароль:").pack(pady=5)
        new_pass = ttk.Entry(dialog, show="*")
        new_pass.pack(pady=5)

        ttk.Label(dialog, text="Подтвердите новый пароль:").pack(pady=5)
        confirm_pass = ttk.Entry(dialog, show="*")
        confirm_pass.pack(pady=5)

        def change_password():
            if new_pass.get() != confirm_pass.get():
                messagebox.showerror("Ошибка", "Пароли не совпадают")
                return

            try:
                self.conn.send(f"CHANGE_PASSWORD {current_pass.get()} {new_pass.get()}".encode('utf-8'))
                response = self.conn.recv(1024).decode('utf-8')

                if "SUCCESS" in response:
                    messagebox.showinfo("Успех", "Пароль успешно изменен")
                    dialog.destroy()
                else:
                    messagebox.showerror("Ошибка", response)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось изменить пароль: {e}")

        ttk.Button(dialog, text="Изменить", command=change_password).pack(pady=10)
        ttk.Button(dialog, text="Отмена", command=dialog.destroy).pack(pady=5)

    def create_menubar(self):
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)

    def confirm_exit(self):
        if messagebox.askyesno("Выход", "Вы действительно хотите выйти?"):
            self.stop_thread.set()
            if self.conn:
                try:
                    self.conn.send("LOGOUT".encode('utf-8'))
                    self.conn.close()
                except:
                    pass
            self.root.quit()

    def logout(self):
        if messagebox.askyesno("Выход", "Вы действительно хотите выйти из аккаунта?"):
            self.stop_thread.set()
            if self.conn:
                try:
                    self.conn.send("LOGOUT".encode('utf-8'))
                    self.conn.close()
                except:
                    pass

            # Очищаем данные сессии
            self.conn = None
            self.nickname = None
            self.token = None

            # Очищаем сохраненные учетные данные
            config = configparser.ConfigParser()
            config.read(self.config_path)

            # Сохраняем настройки сервера и другие параметры
            server_ip = config.get('server', 'ip', fallback='localhost')
            server_port = config.get('server', 'port', fallback='5000')
            remember = config.get('credentials', 'remember', fallback='False')

            # Создаем новый конфиг
            config = configparser.ConfigParser()

            # Восстанавливаем настройки сервера
            config['server'] = {
                'ip': server_ip,
                'port': server_port
            }

            # Восстанавливаем секцию credentials с пустыми значениями
            config['credentials'] = {
                'email': '',
                'password': '',
                'remember': remember
            }

            # Сохраняем обновленный конфиг
            with open(self.config_path, 'w') as f:
                config.write(f)

            # Возвращаемся к начальному экрану
            self.load_login_frame()

    def save_user_config(self, email, password, remember=False):
        config = configparser.ConfigParser()
        config.read(self.config_path)

        if 'credentials' not in config:
            config.add_section('credentials')

        config['credentials']['remember'] = str(remember)

        if remember:
            config['credentials']['email'] = email
            config['credentials']['password'] = password
        else:
            config['credentials']['email'] = ''
            config['credentials']['password'] = ''

        # Добавляем настройки сервера, если их нет
        if 'server' not in config:
            config.add_section('server')
            config['server']['ip'] = 'localhost'
            config['server']['port'] = '5000'

        with open(self.config_path, 'w') as f:
            config.write(f)

    def load_user_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_path)
        if 'credentials' in config:
            remember = config.getboolean('credentials', 'remember', fallback=False)
            if remember:
                return config['credentials'].get('email'), config['credentials'].get('password')
        return None, None

    def init_config(self):
        """Инициализация конфигурационного файла с настройками по умолчанию"""
        config = configparser.ConfigParser()

        if not os.path.exists(self.config_path):
            config['server'] = {
                'ip': 'localhost',
                'port': '5000'
            }
            config['credentials'] = {
                'email': '',
                'password': '',
                'remember': 'False'  # Добавляем параметр remember
            }

            with open(self.config_path, 'w') as f:
                config.write(f)

    def run(self):
        self.root.mainloop()

class ConfigManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self):
        self.config.read(self.config_path)

    def save_config(self):
        with open(self.config_path, 'w') as config_file:
            self.config.write(config_file)

    def get_value(self, section, key, default=None):
        try:
            return self.config[section][key]
        except KeyError:
            return default

    def set_value(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = str(value)
        self.save_config()

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, message, level="INFO"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"

        print(log_message.strip())  # Вывод в консоль

        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_message)

class EncryptionManager:
    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key.ljust(32)[:32]))

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

class ThemeManager:
    def __init__(self, root):
        self.root = root
        self.style = ttk.Style()

    def set_theme(self, theme_name):
        if theme_name == "light":
            self.style.theme_use('default')
            self.root.configure(bg='white')
            self.style.configure("TLabel", background="white", foreground="black")
            self.style.configure("TButton", background="lightgray", foreground="black")
            self.style.configure("TEntry", fieldbackground="white", foreground="black")
        elif theme_name == "dark":
            self.style.theme_use('alt')
            self.root.configure(bg='#2E2E2E')
            self.style.configure("TLabel", background="#2E2E2E", foreground="white")
            self.style.configure("TButton", background="#3E3E3E", foreground="white")
            self.style.configure("TEntry", fieldbackground="#3E3E3E", foreground="white")

def create_tooltip(widget, text):
    def enter(event):
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{event.x_root}+{event.y_root + 20}")
        label = tk.Label(tooltip, text=text, background="#FFFFDD", relief="solid", borderwidth=1)
        label.pack()
        widget.tooltip = tooltip

    def leave(event):
        if hasattr(widget, 'tooltip'):
            widget.tooltip.destroy()

    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)

# Дополнительные утилиты

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_password(password):
    # Пароль должен содержать минимум 8 символов, включая буквы и цифры
    return len(password) >= 8 and re.search(r"\d", password) and re.search(r"[a-zA-Z]", password)

def generate_verification_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

class CustomNotification:
    """Класс для создания пользовательских уведомлений"""
    def __init__(self, parent, message, duration=3000):
        self.parent = parent

        # Создаем окно уведомления
        self.window = tk.Toplevel(parent)
        self.window.overrideredirect(True)
        self.window.attributes('-topmost', True)

        # Настраиваем внешний вид
        frame = ttk.Frame(self.window, style='Notification.TFrame')
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=message,
            style='Notification.TLabel'
        ).pack(padx=10, pady=5)

        # Позиционируем окно в правом нижнем углу
        self.position_window()

        # Автоматически закрываем через заданное время
        self.window.after(duration, self.close)

    def position_window(self):
        screen_width = self.parent.winfo_screenwidth()
        screen_height = self.parent.winfo_screenheight()
        window_width = 300
        window_height = 50

        x = screen_width - window_width - 20
        y = screen_height - window_height - 40

        self.window.geometry(f'{window_width}x{window_height}+{x}+{y}')

    def close(self):
        self.window.destroy()

class FileTransferManager:
    """Класс для управления передачей файлов"""
    def __init__(self, socket, max_size=10485760):  # 10MB по умолчанию
        self.socket = socket
        self.max_size = max_size

    def send_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError("Файл не найден")

        filesize = os.path.getsize(filepath)
        if filesize > self.max_size:
            raise ValueError("Файл слишком большой")

        filename = os.path.basename(filepath)

        # Отправляем информацию о файле
        header = f"FILE_TRANSFER {filename} {filesize}"
        self.socket.send(header.encode('utf-8'))

        # Получаем подтверждение
        response = self.socket.recv(1024).decode('utf-8')
        if response != "READY":
            raise Exception("Сервер не готов к приему файла")

        # Отправляем файл
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                self.socket.send(data)

    def receive_file(self, save_path):
        # Получаем информацию о файле
        header = self.socket.recv(1024).decode('utf-8')
        _, filename, filesize = header.split()
        filesize = int(filesize)

        # Отправляем подтверждение
        self.socket.send("READY".encode('utf-8'))

        # Принимаем файл
        filepath = os.path.join(save_path, filename)
        received = 0

        with open(filepath, 'wb') as f:
            while received < filesize:
                data = self.socket.recv(1024)
                f.write(data)
                received += len(data)

        return filepath

class EmojiPicker:
    """Класс для работы с эмодзи"""
    def __init__(self, parent, callback):
        self.parent = parent
        self.callback = callback
        self.emojis = ['😊', '😂', '❤️', '👍', '😎', '🎉', '🌟', '💪', '🤔', '👋']

    def show_picker(self, event=None):
        picker = tk.Toplevel(self.parent)
        picker.overrideredirect(True)

        frame = ttk.Frame(picker)
        frame.pack(padx=2, pady=2)

        for i, emoji in enumerate(self.emojis):
            btn = ttk.Button(
                frame,
                text=emoji,
                width=3,
                command=lambda e=emoji: self.select_emoji(e, picker)
            )
            btn.grid(row=i//5, column=i%5, padx=1, pady=1)

        # Позиционируем около курсора
        x = event.x_root if event else 0
        y = event.y_root if event else 0
        picker.geometry(f"+{x}+{y}")

    def select_emoji(self, emoji, picker):
        self.callback(emoji)
        picker.destroy()

def create_rounded_button(parent, text, command, **kwargs):
    """Создание кнопки с закругленными углами"""
    style = ttk.Style()
    style.configure(
        'Rounded.TButton',
        borderwidth=0,
        relief="flat",
        background="#4CAF50",
        foreground="white",
        padding=10
    )

    button = ttk.Button(
        parent,
        text=text,
        command=command,
        style='Rounded.TButton',
        **kwargs
    )
    return button

# Константы приложения
APP_NAME = "Chat Application"
APP_VERSION = "1.0.0"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000
MAX_RECONNECT_ATTEMPTS = 3
RECONNECT_DELAY = 5  # секунд

# Настройки логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chat_client.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        root = tk.Tk()  # Создаем корневое окно
        app = ChatClientGUI(root)  # Передаем корневое окно в конструктор
        app.run()
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        messagebox.showerror(
            "Критическая ошибка",
            f"Произошла непредвиденная ошибка: {e}\n"
            "Пожалуйста, проверьте лог-файл для получения дополнительной информации."
        )