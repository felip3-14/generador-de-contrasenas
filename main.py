import random
import string
import time
import sys
import tkinter as tk
from tkinter import ttk
import threading

class PasswordGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Contraseñas")
        self.root.geometry("400x500")
        self.root.configure(bg='#f0f0f0')

        # Sección 1: Longitud de la contraseña
        self.length_frame = ttk.LabelFrame(root, text="Longitud de la Contraseña", padding=10)
        self.length_frame.pack(fill="x", padx=10, pady=5)
        
        self.length_var = tk.StringVar(value="15")
        self.length_entry = ttk.Entry(self.length_frame, textvariable=self.length_var)
        self.length_entry.pack(fill="x", pady=5)

        # Sección 2: Caracteres especiales
        self.special_frame = ttk.LabelFrame(root, text="Caracteres Especiales", padding=10)
        self.special_frame.pack(fill="x", padx=10, pady=5)
        
        self.special_chars = {
            '!': tk.BooleanVar(value=True),
            '@': tk.BooleanVar(value=False),
            '.': tk.BooleanVar(value=False)
        }
        
        for char, var in self.special_chars.items():
            ttk.Checkbutton(self.special_frame, text=char, variable=var).pack(anchor="w", pady=2)

        # Sección 3: Generar y mostrar contraseña
        self.generate_frame = ttk.LabelFrame(root, text="Contraseña Generada", padding=10)
        self.generate_frame.pack(fill="x", padx=10, pady=5)
        
        self.password_text = tk.Text(self.generate_frame, height=3, wrap="word")
        self.password_text.pack(fill="x", pady=5)
        
        self.generate_button = ttk.Button(root, text="Generar Contraseña", command=self.generate_password)
        self.generate_button.pack(pady=10)

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

        # Limpiar el texto anterior
        self.password_text.delete(1.0, tk.END)
        
        # Generar la contraseña
        characters = string.ascii_letters + string.digits + self.get_special_chars()
        password = ''.join(random.choice(characters) for _ in range(length))
        
        # Mostrar la contraseña con animación
        def animate_password():
            self.password_text.delete(1.0, tk.END)
            for char in password:
                self.password_text.insert(tk.END, char)
                self.root.update()
                time.sleep(0.1)
        
        # Ejecutar la animación en un hilo separado
        threading.Thread(target=animate_password, daemon=True).start()

def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()


