import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import string
import random
from .storage import PasswordStorage
from password_generator.security import SecurityManager

class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.security = SecurityManager()
        self.root.withdraw()  # Oculta la ventana principal
        self.blocked = False
        self.blocked_until = None
        self.block_window = None

        # Pedir clave pública al inicio
        self.public_key_value = None
        if not self.ask_public_key():
            root.destroy()
            return

        # Inicializa el almacenamiento usando la clave pública como clave maestra
        self.storage = PasswordStorage()
        self.storage.initialize(self.public_key_value)

        self.root.deiconify()  # Muestra la ventana principal
        self.root.title("Gestor de Contraseñas")
        self.root.geometry("600x700")
        self.root.configure(bg='#f0f0f0')
        
        self._create_widgets()
        
    def ask_public_key(self):
        for _ in range(3):  # Permite 3 intentos
            key = simpledialog.askstring(
                "Clave Pública",
                "Introduce la clave pública:",
                show="*",
                parent=self.root
            )
            if key is None:
                return False  # Usuario canceló
            if self.security.validate_public_key(key):
                self.public_key_value = key  # Guarda la clave pública para inicializar el storage
                return True
            else:
                messagebox.showerror("Error", "Clave pública incorrecta.")
        return False  # Demasiados intentos

    def _create_widgets(self):
        label = ttk.Label(self.root, text="¡Bienvenido al Gestor de Contraseñas!", font=("Arial", 16))
        label.pack(pady=20)
        # Password Generation Section
        self.length_frame = ttk.LabelFrame(self.root, text="Longitud de la Contraseña", padding=10)
        self.length_frame.pack(fill="x", padx=10, pady=5)
        
        self.length_var = tk.StringVar(value="15")
        self.length_entry = ttk.Entry(self.length_frame, textvariable=self.length_var)
        self.length_entry.pack(fill="x", pady=5)

        # Special Characters Section
        self.special_frame = ttk.LabelFrame(self.root, text="Caracteres Especiales", padding=10)
        self.special_frame.pack(fill="x", padx=10, pady=5)
        
        self.special_chars = {
            '!': tk.BooleanVar(value=True),
            '@': tk.BooleanVar(value=False),
            '.': tk.BooleanVar(value=False)
        }
        
        for char, var in self.special_chars.items():
            ttk.Checkbutton(self.special_frame, text=char, variable=var).pack(anchor="w", pady=2)

        # Generated Password Section
        self.generate_frame = ttk.LabelFrame(self.root, text="Contraseña Generada", padding=10)
        self.generate_frame.pack(fill="x", padx=10, pady=5)
        
        self.password_text = tk.Text(self.generate_frame, height=3, wrap="word")
        self.password_text.pack(fill="x", pady=5)
        
        self.generate_button = ttk.Button(self.root, text="Generar Contraseña", 
                                        command=self.generate_password)
        self.generate_button.pack(pady=10)

        # Password Storage Section
        self.storage_frame = ttk.LabelFrame(self.root, text="Almacenamiento de Contraseñas", padding=10)
        self.storage_frame.pack(fill="x", padx=10, pady=5)
        
        # Platform input
        self.platform_var = tk.StringVar()
        ttk.Label(self.storage_frame, text="Plataforma:").pack(anchor="w")
        ttk.Entry(self.storage_frame, textvariable=self.platform_var).pack(fill="x", pady=2)

        # Username input
        self.username_var = tk.StringVar()
        ttk.Label(self.storage_frame, text="Usuario:").pack(anchor="w")
        ttk.Entry(self.storage_frame, textvariable=self.username_var).pack(fill="x", pady=2)

        # Save button
        self.save_button = ttk.Button(self.storage_frame, text="Guardar Contraseña", 
                                    command=self.save_password)
        self.save_button.pack(pady=5)

        # Password list
        self.password_list = ttk.Treeview(self.storage_frame, 
                                        columns=("Platform", "Username", "Date"),
                                        show="headings")
        self.password_list.heading("Platform", text="Plataforma")
        self.password_list.heading("Username", text="Usuario")
        self.password_list.heading("Date", text="Fecha")
        self.password_list.pack(fill="x", pady=5)

        # Search section
        self.search_frame = ttk.Frame(self.storage_frame)
        self.search_frame.pack(fill="x", pady=5)
        
        self.search_var = tk.StringVar()
        ttk.Label(self.search_frame, text="Buscar:").pack(side="left")
        ttk.Entry(self.search_frame, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(self.search_frame, text="Buscar", command=self.search_passwords).pack(side="right")

        # Llenar la lista con datos de ejemplo o reales
        self.update_password_list()

        # Binding de doble click
        self.password_list.bind("<Double-1>", self.on_password_double_click)

        # Botón de configuración
        config_btn = ttk.Button(self.root, text="Configuración", command=self.open_config_window)
        config_btn.pack(pady=10)

    def get_special_chars(self):
        return ''.join(char for char, var in self.special_chars.items() if var.get())

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 4:
                self.password_text.delete(1.0, tk.END)
                self.password_text.insert(tk.END, "La longitud mínima recomendada es 4.")
                return
        except ValueError:
            self.password_text.delete(1.0, tk.END)
            self.password_text.insert(tk.END, "Por favor, ingrese un número válido.")
            return

        self.password_text.delete(1.0, tk.END)
        characters = string.ascii_letters + string.digits + self.get_special_chars()
        password = ''.join(random.choice(characters) for _ in range(length))
        
        def animate_password():
            self.password_text.delete(1.0, tk.END)
            for char in password:
                self.password_text.insert(tk.END, char)
                self.root.update()
                time.sleep(0.1)
        
        threading.Thread(target=animate_password, daemon=True).start()

    def save_password(self):
        # Verifica que el almacenamiento esté inicializado
        if not self.storage.encryption:
            messagebox.showerror("Error", "El almacenamiento no está inicializado correctamente.")
            return
        try:
            platform = self.platform_var.get()
            username = self.username_var.get()
            password = self.password_text.get(1.0, tk.END).strip()
            
            if not all([platform, username, password]):
                messagebox.showerror("Error", "Todos los campos son requeridos")
                return
                
            self.storage.add_password(platform, username, password)
            self.update_password_list()
            messagebox.showinfo("Éxito", "Contraseña guardada correctamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar la contraseña: {str(e)}")

    def update_password_list(self):
        # Clear existing items
        for item in self.password_list.get_children():
            self.password_list.delete(item)
            
        # Add new items
        for entry in self.storage.get_passwords():
            self.password_list.insert("", "end", values=(
                entry.platform,
                entry.username,
                entry.date_created.strftime("%Y-%m-%d %H:%M")
            ))

    def search_passwords(self):
        query = self.search_var.get()
        if not query:
            self.update_password_list()
            return
            
        # Clear existing items
        for item in self.password_list.get_children():
            self.password_list.delete(item)
            
        # Add filtered items
        for entry in self.storage.search_passwords(query):
            self.password_list.insert("", "end", values=(
                entry.platform,
                entry.username,
                entry.date_created.strftime("%Y-%m-%d %H:%M")
            ))

    def on_password_double_click(self, event):
        if self.blocked:
            self.show_block_window()
            return
        selected_item = self.password_list.focus()
        if not selected_item:
            return
        values = self.password_list.item(selected_item, 'values')
        if not values:
            return
        platform, username, date = values
        
        # Pedir clave privada con 3 intentos
        for intento in range(3):  # Permite 3 intentos
            key = simpledialog.askstring(
                "Clave Privada",
                "Introduce la clave privada para ver los detalles:",
                show="*",
                parent=self.root
            )
            if key is None:
                return  # Usuario canceló
            if self.security.validate_private_key(key):
                # Buscar la entrada completa
                entry = next((e for e in self.storage.get_passwords() if e.platform == platform and e.username == username and e.date_created.strftime("%Y-%m-%d %H:%M") == date), None)
                if not entry:
                    messagebox.showerror("Error", "No se encontró la entrada seleccionada.")
                    return
                # Mostrar toda la info
                info = f"Plataforma: {entry.platform}\nUsuario: {entry.username}\nContraseña: {entry.password}\nFecha de creación: {entry.date_created.strftime('%Y-%m-%d %H:%M')}\nÚltima modificación: {entry.last_modified.strftime('%Y-%m-%d %H:%M') if entry.last_modified else '-'}"
                messagebox.showinfo("Detalles de la contraseña", info)
                return
            else:
                intentos_restantes = 2 - intento
                if intentos_restantes > 0:
                    messagebox.showerror("Error", f"Clave privada incorrecta. Te quedan {intentos_restantes} intentos.")
                else:
                    messagebox.showerror("Error", "Clave privada incorrecta. Último intento.")
        
        # Si llegamos aquí, es porque se agotaron los intentos
        self.block_app()

    def open_config_window(self):
        if self.blocked:
            self.show_block_window()
            return
        config_win = tk.Toplevel(self.root)
        config_win.title("Configuración")
        config_win.geometry("350x220")
        config_win.grab_set()

        ttk.Label(config_win, text="Opciones de configuración", font=("Arial", 14)).pack(pady=10)
        
        def close_config():
            config_win.destroy()

        def add_entry_with_eye(parent, label_text):
            frame = ttk.Frame(parent)
            frame.pack(pady=5)
            ttk.Label(frame, text=label_text).pack(side="left")
            entry = ttk.Entry(frame, show="*")
            entry.pack(side="left", padx=5)
            show = tk.BooleanVar(value=False)
            def toggle():
                if show.get():
                    entry.config(show="*")
                    eye_btn.config(text="👁️")
                    show.set(False)
                else:
                    entry.config(show="")
                    eye_btn.config(text="🙈")
                    show.set(True)
            eye_btn = ttk.Button(frame, text="👁️", width=2, command=toggle)
            eye_btn.pack(side="left")
            return entry

        def start_change_keys():
            for widget in config_win.winfo_children():
                widget.destroy()
            # Paso 1: Clave pública actual
            attempts_pub = [0]
            ttk.Label(config_win, text="Paso 1: Ingrese la clave pública actual", font=("Arial", 12)).pack(pady=10)
            pub_entry = add_entry_with_eye(config_win, "Clave pública:")
            def next_pub():
                pub = pub_entry.get()
                if not self.security.validate_public_key(pub):
                    attempts_pub[0] += 1
                    if attempts_pub[0] >= 3:
                        messagebox.showerror("Error", "3 intentos fallidos. Bloqueando la app.")
                        config_win.destroy()
                        self.block_app()
                        return
                    else:
                        messagebox.showerror("Error", f"Clave pública incorrecta. Intento {attempts_pub[0]}/3")
                        return
                # Paso 2: Clave privada actual
                for widget in config_win.winfo_children():
                    widget.destroy()
                attempts_priv = [0]
                ttk.Label(config_win, text="Paso 2: Ingrese la clave privada actual", font=("Arial", 12)).pack(pady=10)
                priv_entry = add_entry_with_eye(config_win, "Clave privada:")
                def next_priv():
                    priv = priv_entry.get()
                    if not self.security.validate_private_key(priv):
                        attempts_priv[0] += 1
                        if attempts_priv[0] >= 3:
                            messagebox.showerror("Error", "3 intentos fallidos. Bloqueando la app.")
                            config_win.destroy()
                            self.block_app()
                            return
                        else:
                            messagebox.showerror("Error", f"Clave privada incorrecta. Intento {attempts_priv[0]}/3")
                            return
                    # Paso 3: Nueva clave pública
                    for widget in config_win.winfo_children():
                        widget.destroy()
                    attempts_new_pub = [0]
                    ttk.Label(config_win, text="Paso 3: Nueva clave pública", font=("Arial", 12)).pack(pady=10)
                    new_pub_entry = add_entry_with_eye(config_win, "Nueva pública:")
                    def next_new_pub():
                        new_pub = new_pub_entry.get()
                        if not new_pub:
                            attempts_new_pub[0] += 1
                            if attempts_new_pub[0] >= 3:
                                messagebox.showerror("Error", "3 intentos fallidos. Bloqueando la app.")
                                config_win.destroy()
                                self.block_app()
                                return
                            else:
                                messagebox.showerror("Error", f"La nueva clave pública no puede estar vacía. Intento {attempts_new_pub[0]}/3")
                                return
                        # Paso 4: Nueva clave privada
                        for widget in config_win.winfo_children():
                            widget.destroy()
                        attempts_new_priv = [0]
                        ttk.Label(config_win, text="Paso 4: Nueva clave privada", font=("Arial", 12)).pack(pady=10)
                        new_priv_entry = add_entry_with_eye(config_win, "Nueva privada:")
                        def finish_change():
                            new_priv = new_priv_entry.get()
                            if not new_priv:
                                attempts_new_priv[0] += 1
                                if attempts_new_priv[0] >= 3:
                                    messagebox.showerror("Error", "3 intentos fallidos. Bloqueando la app.")
                                    config_win.destroy()
                                    self.block_app()
                                    return
                                else:
                                    messagebox.showerror("Error", f"La nueva clave privada no puede estar vacía. Intento {attempts_new_priv[0]}/3")
                                    return
                            ok, msg = self.security.change_keys(pub, priv, new_pub, new_priv)
                            if ok:
                                messagebox.showinfo("Éxito", msg)
                                config_win.destroy()
                            else:
                                messagebox.showerror("Error", msg)
                                config_win.destroy()
                                self.block_app()
                        ttk.Button(config_win, text="Finalizar", command=finish_change).pack(pady=10)
                    ttk.Button(config_win, text="Siguiente", command=next_new_pub).pack(pady=10)
                ttk.Button(config_win, text="Siguiente", command=next_priv).pack(pady=10)
            ttk.Button(config_win, text="Siguiente", command=next_pub).pack(pady=10)
        
        ttk.Button(config_win, text="Cambiar claves", command=start_change_keys).pack(pady=10)
        ttk.Button(config_win, text="Salir", command=close_config).pack(pady=10)

    def block_app(self):
        self.blocked = True
        self.blocked_until = time.time() + 15 * 60  # 15 minutos
        self.show_block_window()
        threading.Thread(target=self._block_timer_thread, daemon=True).start()

    def show_block_window(self):
        if self.block_window and tk.Toplevel.winfo_exists(self.block_window):
            return
        self.block_window = tk.Toplevel(self.root)
        self.block_window.title("Bloqueado")
        self.block_window.geometry("350x150")
        self.block_window.grab_set()
        self.block_window.protocol("WM_DELETE_WINDOW", lambda: None)  # No cerrar
        label = ttk.Label(self.block_window, text="Demasiados intentos fallidos.\nEl programa está bloqueado.", font=("Arial", 12))
        label.pack(pady=10)
        self.timer_label = ttk.Label(self.block_window, text="", font=("Arial", 16))
        self.timer_label.pack(pady=10)
        self.update_block_timer()

    def update_block_timer(self):
        if not self.blocked_until:
            return
        remaining = int(self.blocked_until - time.time())
        if remaining < 0:
            remaining = 0
        mins, secs = divmod(remaining, 60)
        self.timer_label.config(text=f"Tiempo restante: {mins:02d}:{secs:02d}")
        if remaining > 0:
            self.root.after(1000, self.update_block_timer)
        else:
            self.unblock_app()

    def _block_timer_thread(self):
        while time.time() < self.blocked_until:
            time.sleep(1)
        self.root.after(0, self.unblock_app)

    def unblock_app(self):
        self.blocked = False
        self.blocked_until = None
        if self.block_window:
            self.block_window.destroy()
            self.block_window = None 