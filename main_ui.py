import tkinter as tk
from gui import AntivirusGUI

def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()