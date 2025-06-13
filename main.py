import tkinter as tk
from password_generator.gui import PasswordGeneratorGUI

def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()


