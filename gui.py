import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import os
from scanner import SimpleAntivirus
from typing import Optional
import json
from logger import AntivirusLogger


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Python Antivirus")
        self.root.geometry("800x600")

        # Initialize logger
        self.logger = AntivirusLogger()
        self.logger.log_info("Starting Antivirus GUI")

        # Initialize scanner
        self.scanner = SimpleAntivirus()

        # Create main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create and configure the tree view
        self.setup_tree_view()

        # Create buttons frame
        self.setup_buttons()

        # Create output text area
        self.setup_output_area()

        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

        # Start with the current directory
        self.logger.log_info("GUI initialization complete")

    def setup_tree_view(self):
        """Set up the directory tree view."""
        # Create frame for tree view with scrollbars
        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # Create tree view
        self.tree = ttk.Treeview(tree_frame, selectmode="extended")
        self.tree.heading("#0", text="Directory Structure", anchor=tk.W)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Bind events
        self.tree.bind("<<TreeviewOpen>>", self.item_opened)
        self.tree.bind("<Double-1>", self.item_double_clicked)

    def setup_buttons(self):
        """Set up the control buttons."""
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)

        ttk.Button(btn_frame, text="Select Folder", command=self.select_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Scan Selected", command=self.scan_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_tree).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Output", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="View Logs", command=self.view_logs).pack(side=tk.LEFT, padx=5)

    def setup_output_area(self):
        """Set up the output text area."""
        output_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding="5")
        output_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        self.output_text = tk.Text(output_frame, height=10, wrap=tk.WORD)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.output_text.configure(yscrollcommand=scrollbar.set)

        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

    def populate_tree(self, path: str, parent: str = ""):
        """Populate the tree view with directory contents."""
        # Clear existing items if populating root
        if not parent:
            for item in self.tree.get_children():
                self.tree.delete(item)

        try:
            # List directory contents
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                item_id = item_path

                try:
                    # Check if it's a directory
                    is_dir = os.path.isdir(item_path)

                    # Create item in tree
                    self.tree.insert(parent, tk.END, item_id, text=item,
                                     values=(item_path,),
                                     tags=('directory' if is_dir else 'file'))

                    # If it's a directory, add a dummy item if it has contents
                    if is_dir and os.listdir(item_path):
                        self.tree.insert(item_id, tk.END, f"{item_id}_dummy", text="Loading...")
                except PermissionError:
                    self.logger.log_error(f"Permission denied for {item_path}")
                    continue

        except PermissionError:
            self.logger.log_error(f"Permission denied for {path}")
            self.log_output(f"Permission denied: {path}")

    def view_logs(self):
        """Open a new window to view logs."""
        log_window = tk.Toplevel(self.root)
        log_window.title("Antivirus Logs")
        log_window.geometry("800x600")

        # Create text widget for logs
        log_text = tk.Text(log_window, wrap=tk.WORD)
        log_text.pack(expand=True, fill=tk.BOTH)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(log_text, orient=tk.VERTICAL, command=log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        log_text.configure(yscrollcommand=scrollbar.set)

        # Load and display logs
        try:
            log_files = sorted([f for f in os.listdir("logs") if f.endswith(".log")], reverse=True)
            if log_files:
                with open(os.path.join("logs", log_files[0]), 'r') as f:
                    log_text.insert(tk.END, f.read())
            else:
                log_text.insert(tk.END, "No logs found.")
        except Exception as e:
            log_text.insert(tk.END, f"Error loading logs: {str(e)}")

        log_text.configure(state=tk.DISABLED)  # Make text read-only

    def item_opened(self, event):
        """Handle directory expansion."""
        item_id = self.tree.focus()

        # Clear dummy item if it exists
        children = self.tree.get_children(item_id)
        if children and self.tree.item(children[0])['text'] == "Loading...":
            self.tree.delete(children[0])

        # Populate the actual contents
        path = self.tree.item(item_id)['values'][0]
        self.populate_tree(path, item_id)

    def item_double_clicked(self, event):
        """Handle double-click on an item."""
        item_id = self.tree.focus()
        path = self.tree.item(item_id)['values'][0]
        self.scan_path(path)

    def scan_selected(self):
        """Scan all selected items."""
        selected_items = self.tree.selection()
        for item_id in selected_items:
            path = self.tree.item(item_id)['values'][0]
            self.scan_path(path)

    def scan_path(self, path: str):
        """Scan a file or directory."""
        self.logger.log_info(f"GUI initiated scan for: {path}")
        if os.path.isfile(path):
            self.redirect_output(lambda: self.scanner.scan_file(path))
        else:
            self.redirect_output(lambda: self.scanner.scan_directory(path))

    def refresh_tree(self):
        """Refresh the directory tree."""
        self.logger.log_info("Refreshing directory tree")
        current_selection = self.tree.selection()
        if current_selection:
            path = os.path.dirname(self.tree.item(current_selection[0])['values'][0])
        else:
            path = "/home"
        self.populate_tree(path)

    def clear_output(self):
        """Clear the output text area."""
        self.output_text.delete(1.0, tk.END)
        self.logger.log_info("Cleared output display")

    def log_output(self, message: str):
        """Add message to output text area."""
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)

    def redirect_output(self, func):
        """Redirect print output to the GUI."""
        import sys
        from io import StringIO

        # Create string buffer to capture output
        output = StringIO()
        sys.stdout = output

        # Run the function
        func()

        # Restore stdout and get output
        sys.stdout = sys.__stdout__
        self.log_output(output.getvalue())
        output.close()

    def select_folder(self):
        """Open a dialog to select a folder."""
        folder = filedialog.askdirectory()
        if folder:
            self.logger.log_info(f"Selected folder: {folder}")
            self.populate_tree(folder)
