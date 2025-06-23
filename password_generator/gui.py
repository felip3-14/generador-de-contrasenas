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
        
        # Variables para el generador de contraseñas
        self.length_var = tk.StringVar(value="15")
        self.special_chars = {
            '!': tk.BooleanVar(value=True),
            '@': tk.BooleanVar(value=False),
            '.': tk.BooleanVar(value=False)
        }
        self.password_text = None
        
        # Variables para el almacenamiento
        self.platform_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_list = None
        self.search_var = tk.StringVar()
        
        # Mostrar menú principal
        self.show_main_menu()
        
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

    def clear_window(self):
        """Limpia todos los widgets de la ventana principal"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def create_back_button(self, parent, command):
        """Crea un botón de volver en la esquina superior izquierda"""
        back_btn = ttk.Button(parent, text="← Volver", command=command)
        back_btn.place(relx=0.05, rely=0.02, anchor="nw")
        return back_btn

    def show_main_menu(self):
        """Muestra el menú principal con las 4 opciones"""
        self.clear_window()
        
        # Título principal
        title_label = ttk.Label(self.root, text="Gestor de Contraseñas", font=("Arial", 20, "bold"))
        title_label.pack(pady=30)
        
        subtitle_label = ttk.Label(self.root, text="Selecciona una opción:", font=("Arial", 14))
        subtitle_label.pack(pady=10)
        
        # Frame para los botones
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=30)
        
        # Botones del menú principal
        buttons = [
            ("🔍 Revisión de Claves", self.show_password_review),
            ("🔐 Generador de Claves", self.show_password_generator),
            ("⚙️ Ajustes", self.show_settings),
            ("❌ Cerrar", self.root.destroy)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(button_frame, text=text, command=command, width=25)
            btn.pack(pady=10)

    def show_password_review(self):
        """Muestra la pantalla de revisión de contraseñas almacenadas"""
        # Verificar autenticación antes de mostrar la pantalla
        if not self.authenticate_for_review():
            return
            
        self.clear_window()
        
        # Botón volver
        self.create_back_button(self.root, self.show_main_menu)
        
        # Título
        title_label = ttk.Label(self.root, text="Revisión de Contraseñas", font=("Arial", 18, "bold"))
        title_label.pack(pady=20)
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Sección de búsqueda
        search_frame = ttk.LabelFrame(main_frame, text="Buscar Contraseñas", padding=10)
        search_frame.pack(fill="x", pady=10)
        
        search_input_frame = ttk.Frame(search_frame)
        search_input_frame.pack(fill="x")
        
        ttk.Label(search_input_frame, text="Buscar:").pack(side="left")
        ttk.Entry(search_input_frame, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(search_input_frame, text="Buscar", command=self.search_passwords).pack(side="right")
        
        # Lista de contraseñas
        list_frame = ttk.LabelFrame(main_frame, text="Contraseñas Almacenadas", padding=10)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        # Crear Treeview para la lista
        columns = ("Platform", "Username", "Date")
        self.password_list = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        self.password_list.heading("Platform", text="Plataforma")
        self.password_list.heading("Username", text="Usuario")
        self.password_list.heading("Date", text="Fecha")
        
        # Configurar columnas
        self.password_list.column("Platform", width=150)
        self.password_list.column("Username", width=150)
        self.password_list.column("Date", width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.password_list.yview)
        self.password_list.configure(yscrollcommand=scrollbar.set)
        
        self.password_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Binding de doble click
        self.password_list.bind("<Double-1>", self.on_password_double_click)
        
        # Actualizar lista
        self.update_password_list()

    def authenticate_for_review(self):
        """Autentica al usuario con clave pública y privada para acceder a la revisión"""
        if self.blocked:
            self.show_block_window()
            return False
            
        # Pedir clave pública
        for intento_pub in range(3):
            pub_key = simpledialog.askstring(
                "Autenticación - Clave Pública",
                "Introduce la clave pública para acceder a la revisión:",
                show="*",
                parent=self.root
            )
            if pub_key is None:
                return False  # Usuario canceló
            if self.security.validate_public_key(pub_key):
                break
            else:
                intentos_restantes = 2 - intento_pub
                if intentos_restantes > 0:
                    messagebox.showerror("Error", f"Clave pública incorrecta. Te quedan {intentos_restantes} intentos.")
                else:
                    messagebox.showerror("Error", "Clave pública incorrecta. Último intento.")
        else:
            # Si llegamos aquí, se agotaron los intentos de clave pública
            self.block_app()
            return False
            
        # Pedir clave privada
        for intento_priv in range(3):
            priv_key = simpledialog.askstring(
                "Autenticación - Clave Privada",
                "Introduce la clave privada para acceder a la revisión:",
                show="*",
                parent=self.root
            )
            if priv_key is None:
                return False  # Usuario canceló
            if self.security.validate_private_key(priv_key):
                messagebox.showinfo("Éxito", "Autenticación exitosa. Acceso concedido a la revisión de contraseñas.")
                return True
            else:
                intentos_restantes = 2 - intento_priv
                if intentos_restantes > 0:
                    messagebox.showerror("Error", f"Clave privada incorrecta. Te quedan {intentos_restantes} intentos.")
                else:
                    messagebox.showerror("Error", "Clave privada incorrecta. Último intento.")
        else:
            # Si llegamos aquí, se agotaron los intentos de clave privada
            self.block_app()
            return False

    def show_password_generator(self):
        """Muestra la pantalla del generador de contraseñas"""
        self.clear_window()
        
        # Botón volver
        self.create_back_button(self.root, self.show_main_menu)
        
        # Título
        title_label = ttk.Label(self.root, text="Generador de Contraseñas", font=("Arial", 18, "bold"))
        title_label.pack(pady=20)
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Sección de longitud
        length_frame = ttk.LabelFrame(main_frame, text="Longitud de la Contraseña", padding=10)
        length_frame.pack(fill="x", pady=10)
        
        ttk.Entry(length_frame, textvariable=self.length_var).pack(fill="x", pady=5)

        # Sección de caracteres especiales
        special_frame = ttk.LabelFrame(main_frame, text="Caracteres Especiales", padding=10)
        special_frame.pack(fill="x", pady=10)
        
        for char, var in self.special_chars.items():
            ttk.Checkbutton(special_frame, text=char, variable=var).pack(anchor="w", pady=2)

        # Sección de contraseña generada
        generate_frame = ttk.LabelFrame(main_frame, text="Contraseña Generada", padding=10)
        generate_frame.pack(fill="x", pady=10)
        
        self.password_text = tk.Text(generate_frame, height=3, wrap="word")
        self.password_text.pack(fill="x", pady=5)
        
        # Botón generar
        generate_button = ttk.Button(main_frame, text="Generar Contraseña", 
                                    command=self.generate_password)
        generate_button.pack(pady=10)

        # Sección de almacenamiento
        storage_frame = ttk.LabelFrame(main_frame, text="Guardar Contraseña", padding=10)
        storage_frame.pack(fill="x", pady=10)
        
        # Campos de entrada
        ttk.Label(storage_frame, text="Plataforma:").pack(anchor="w")
        ttk.Entry(storage_frame, textvariable=self.platform_var).pack(fill="x", pady=2)

        ttk.Label(storage_frame, text="Usuario:").pack(anchor="w")
        ttk.Entry(storage_frame, textvariable=self.username_var).pack(fill="x", pady=2)

        # Botón guardar
        save_button = ttk.Button(storage_frame, text="Guardar Contraseña", 
                                command=self.save_password)
        save_button.pack(pady=5)

    def show_settings(self):
        """Muestra la pantalla de ajustes"""
        self.clear_window()
        
        # Botón volver
        self.create_back_button(self.root, self.show_main_menu)
        
        # Título
        title_label = ttk.Label(self.root, text="Ajustes", font=("Arial", 18, "bold"))
        title_label.pack(pady=20)
        
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Opciones de configuración
        config_frame = ttk.LabelFrame(main_frame, text="Opciones de Configuración", padding=20)
        config_frame.pack(fill="x", pady=10)
        
        # Botones de configuración
        buttons = [
            ("🔑 Cambiar Clave Pública", self.change_public_key),
            ("🔒 Cambiar Clave Privada", self.change_private_key),
            ("🔄 Cambiar Ambas Claves", self.change_both_keys),
            ("🔄 Restaurar Claves por Defecto", self.restore_default_keys)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(config_frame, text=text, command=command, width=25)
            btn.pack(pady=10)

    def change_public_key(self):
        """Cambia solo la clave pública"""
        if self.blocked:
            self.show_block_window()
            return
            
        # Implementar lógica para cambiar solo clave pública
        messagebox.showinfo("Info", "Función para cambiar solo clave pública")

    def change_private_key(self):
        """Cambia solo la clave privada"""
        if self.blocked:
            self.show_block_window()
            return
            
        # Implementar lógica para cambiar solo clave privada
        messagebox.showinfo("Info", "Función para cambiar solo clave privada")

    def change_both_keys(self):
        """Cambia ambas claves"""
        if self.blocked:
            self.show_block_window()
            return
            
        # Usar la lógica existente de cambio de claves
        self.open_config_window()

    def restore_default_keys(self):
        """Restaura las claves por defecto"""
        if self.blocked:
            self.show_block_window()
            return
            
        result = messagebox.askyesno("Confirmar", 
                                   "¿Estás seguro de que quieres restaurar las claves por defecto?\n"
                                   "Esto eliminará todas las contraseñas almacenadas.")
        if result:
            # Implementar lógica para restaurar claves por defecto
            messagebox.showinfo("Info", "Claves restauradas por defecto")

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
            messagebox.showinfo("Éxito", "Contraseña guardada correctamente")
            
            # Limpiar campos
            self.platform_var.set("")
            self.username_var.set("")
            self.password_text.delete(1.0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar la contraseña: {str(e)}")

    def update_password_list(self):
        # Clear existing items
        for item in self.password_list.get_children():
            self.password_list.delete(item)
            
        # Add new items con usuarios censurados
        for entry in self.storage.get_passwords():
            # Censurar el nombre de usuario (mostrar solo primera y última letra)
            username = entry.username
            if len(username) > 2:
                censored_username = username[0] + "*" * (len(username) - 2) + username[-1]
            else:
                censored_username = "*" * len(username)
                
            self.password_list.insert("", "end", values=(
                entry.platform,
                censored_username,
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
            
        # Add filtered items con usuarios censurados
        for entry in self.storage.search_passwords(query):
            # Censurar el nombre de usuario (mostrar solo primera y última letra)
            username = entry.username
            if len(username) > 2:
                censored_username = username[0] + "*" * (len(username) - 2) + username[-1]
            else:
                censored_username = "*" * len(username)
                
            self.password_list.insert("", "end", values=(
                entry.platform,
                censored_username,
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
        platform, censored_username, date = values
        
        # Buscar la entrada completa usando la plataforma y fecha
        # Como el username está censurado, necesitamos buscar por otros criterios
        matching_entries = []
        for entry in self.storage.get_passwords():
            if (entry.platform == platform and 
                entry.date_created.strftime("%Y-%m-%d %H:%M") == date):
                matching_entries.append(entry)
        
        if not matching_entries:
            messagebox.showerror("Error", "No se encontró la entrada seleccionada.")
            return
        elif len(matching_entries) > 1:
            # Si hay múltiples entradas con la misma plataforma y fecha, mostrar un selector
            self.show_entry_selector(matching_entries)
            return
        else:
            entry = matching_entries[0]
            self.show_password_details(entry)

    def show_entry_selector(self, entries):
        """Muestra un selector cuando hay múltiples entradas con la misma plataforma y fecha"""
        selector_window = tk.Toplevel(self.root)
        selector_window.title("Seleccionar Entrada")
        selector_window.geometry("400x300")
        selector_window.grab_set()
        
        ttk.Label(selector_window, text="Múltiples entradas encontradas.\nSelecciona la correcta:", 
                 font=("Arial", 12)).pack(pady=10)
        
        # Crear lista de selección
        listbox = tk.Listbox(selector_window, height=10)
        listbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Agregar entradas a la lista
        for entry in entries:
            censored_username = entry.username[0] + "*" * (len(entry.username) - 2) + entry.username[-1] if len(entry.username) > 2 else "*" * len(entry.username)
            listbox.insert(tk.END, f"{entry.platform} - {censored_username}")
        
        def select_entry():
            selection = listbox.curselection()
            if selection:
                selected_entry = entries[selection[0]]
                selector_window.destroy()
                self.show_password_details(selected_entry)
        
        ttk.Button(selector_window, text="Seleccionar", command=select_entry).pack(pady=10)

    def show_password_details(self, entry):
        """Muestra los detalles de la contraseña seleccionada"""
        # Crear ventana personalizada para mostrar la información
        info_window = tk.Toplevel(self.root)
        info_window.title("Detalles de la contraseña")
        info_window.geometry("400x300")
        info_window.grab_set()
        
        # Mostrar la información
        info_text = f"Plataforma: {entry.platform}\nUsuario: {entry.username}\nContraseña: {entry.password}\nFecha de creación: {entry.date_created.strftime('%Y-%m-%d %H:%M')}\nÚltima modificación: {entry.last_modified.strftime('%Y-%m-%d %H:%M') if entry.last_modified else '-'}"
        info_label = ttk.Label(info_window, text=info_text, justify="left", padding=10)
        info_label.pack(pady=10)
        
        # Frame para los botones
        button_frame = ttk.Frame(info_window)
        button_frame.pack(pady=10)
        
        def copy_to_clipboard():
            # Pedir clave pública para copiar
            for intento in range(3):
                pub_key = simpledialog.askstring(
                    "Clave Pública",
                    "Introduce la clave pública para copiar la contraseña:",
                    show="*",
                    parent=info_window
                )
                if pub_key is None:
                    return  # Usuario canceló
                if self.security.validate_public_key(pub_key):
                    # Copiar al portapapeles
                    self.root.clipboard_clear()
                    self.root.clipboard_append(entry.password)
                    messagebox.showinfo("Éxito", "Contraseña copiada al portapapeles", parent=info_window)
                    return
                else:
                    intentos_restantes = 2 - intento
                    if intentos_restantes > 0:
                        messagebox.showerror("Error", f"Clave pública incorrecta. Te quedan {intentos_restantes} intentos.", parent=info_window)
                    else:
                        messagebox.showerror("Error", "Clave pública incorrecta. Último intento.", parent=info_window)
            # Si llegamos aquí, es porque se agotaron los intentos
            self.block_app()
        
        # Botones
        ttk.Button(button_frame, text="Copiar Contraseña", command=copy_to_clipboard).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cerrar", command=info_window.destroy).pack(side="left", padx=5)

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