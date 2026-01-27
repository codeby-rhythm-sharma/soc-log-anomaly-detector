import tkinter as tk
from tkinter import ttk, messagebox
import json
import os

#Configuration file path
CONFIG_FILE = "rules.json"

class ConfigGUI:
    """GUI for configuring SOC Log Anomaly Detector rules."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SOC Detector Configuration")
        self.root.geometry("800x650")
        
        # Dark Mode Colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#37373d"
        self.input_bg = "#2d2d2d"
        self.input_fg = "#cccccc"
        self.btn_bg = "#0e639c"

        #Apply background color to root window 
        self.root.configure(bg=self.bg_color)

        #Load existing configuration
        self.rules = self.load_config()

        #Setup UI styles and layout
        self.setup_styles()
        self.setup_ui()
        self.refresh_listbox()

    def setup_styles(self):
        """Configure ttk styles for dark theme UI."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabelframe", background=self.bg_color, foreground=self.fg_color)
        style.configure("TLabelframe.Label", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10, "bold"))
        
        # Label
        style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 9))
        
        # Entry
        style.configure("TEntry", fieldbackground=self.input_bg, foreground=self.fg_color, bordercolor=self.accent_color)
        
        # Button
        style.configure("TButton", background=self.btn_bg, foreground=self.fg_color, borderwidth=0)
        style.map("TButton", background=[('active', '#1177bb')])
        
        # Combobox
        style.configure("TCombobox", fieldbackground=self.input_bg, background=self.accent_color, foreground=self.fg_color)
        
        # Spinbox
        style.configure("TSpinbox", fieldbackground=self.input_bg, foreground=self.fg_color)

    def load_config(self):
        """Load rules from JSON file or return defaults."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                pass
        
        #Default configuration     
        return {"severity_levels": {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}, "suspicious_patterns": {}}

    def save_config(self):
        """Save current rules to json file."""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.rules, f, indent=4)
            messagebox.showinfo("Success", "Configuration saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")

    def setup_ui(self):
        """Create and arrange all UI components."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(main_frame, text="SOC LOG ANOMALY DETECTOR - CONFIGURATION", font=("Segoe UI", 14, "bold"))
        header.pack(pady=(0, 20))

        # Horizontal layout for list and editor
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # List of rules
        list_frame = ttk.LabelFrame(content_frame, text="Detection Rules", padding="5")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        #Listbox showing rule patterns
        self.rules_listbox = tk.Listbox(
            list_frame, 
            bg=self.input_bg, 
            fg=self.fg_color, 
            selectbackground=self.btn_bg, 
            selectforeground=self.fg_color,
            borderwidth=0,
            highlightthickness=1,
            highlightcolor=self.accent_color,
            font=("Segoe UI", 10)
        )
        self.rules_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.rules_listbox.bind('<<ListboxSelect>>', self.on_rule_select)

        #Scrollbar for listbox
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rules_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rules_listbox.config(yscrollcommand=scrollbar.set)

        # Buttons for list area
        list_btn_frame = ttk.Frame(list_frame)
        list_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(list_btn_frame, text="+ New Rule", command=self.clear_form).pack(fill=tk.X)

        # Editor frame
        edit_frame = ttk.LabelFrame(content_frame, text="Edit Rule", padding="15")
        edit_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))

        # Pattern input
        ttk.Label(edit_frame, text="Pattern (Keyword):").grid(row=0, column=0, sticky=tk.W, pady=(0, 2))
        self.pattern_var = tk.StringVar()
        self.pattern_entry = ttk.Entry(edit_frame, textvariable=self.pattern_var, width=35)
        self.pattern_entry.grid(row=1, column=0, pady=(0, 10), sticky=tk.W)

        #Message input 
        ttk.Label(edit_frame, text="Alert Message:").grid(row=2, column=0, sticky=tk.W, pady=(0, 2))
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(edit_frame, textvariable=self.message_var, width=35)
        self.message_entry.grid(row=3, column=0, pady=(0, 10), sticky=tk.W)

        #Severity selector 
        ttk.Label(edit_frame, text="Severity:").grid(row=4, column=0, sticky=tk.W, pady=(0, 2))
        self.severity_var = tk.StringVar(value="LOW")
        self.severity_combo = ttk.Combobox(edit_frame, textvariable=self.severity_var, values=list(self.rules["severity_levels"].keys()), width=32)
        self.severity_combo.grid(row=5, column=0, pady=(0, 10), sticky=tk.W)

        #Threshold input
        ttk.Label(edit_frame, text="Threshold (Matches):").grid(row=6, column=0, sticky=tk.W, pady=(0, 2))
        self.threshold_var = tk.IntVar(value=1)
        self.threshold_spin = ttk.Spinbox(edit_frame, from_=1, to=100, textvariable=self.threshold_var, width=33)
        self.threshold_spin.grid(row=7, column=0, pady=(0, 10), sticky=tk.W)

        ttk.Label(edit_frame, text="Threshold Severity:").grid(row=8, column=0, sticky=tk.W, pady=(0, 2))
        self.t_severity_var = tk.StringVar(value="LOW")
        self.t_severity_combo = ttk.Combobox(edit_frame, textvariable=self.t_severity_var, values=list(self.rules["severity_levels"].keys()), width=32)
        self.t_severity_combo.grid(row=9, column=0, pady=(0, 10), sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(edit_frame)
        btn_frame.grid(row=10, column=0, pady=(20, 0))

        ttk.Button(btn_frame, text="Add/Update", command=self.save_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        
        # Save all button at bottom
        ttk.Button(main_frame, text="SAVE ALL TO RULES.JSON", command=self.save_config).pack(side=tk.BOTTOM, pady=20, fill=tk.X)

    def refresh_listbox(self):
        """Refresh rule list display."""
        self.rules_listbox.delete(0, tk.END)
        for pattern in sorted(self.rules["suspicious_patterns"].keys()):
            self.rules_listbox.insert(tk.END, pattern)

    def clear_form(self):
        """Clear form inputs for adding a new rule."""
        self.rules_listbox.selection_clear(0, tk.END)
        self.pattern_var.set("")
        self.message_var.set("")
        self.severity_var.set("LOW")
        self.threshold_var.set(1)
        self.t_severity_var.set("LOW")
        self.pattern_entry.focus_set()

    def on_rule_select(self, event):
        """Load selected rule data into the editor"""
        selection = self.rules_listbox.curselection()
        if selection:
            pattern = self.rules_listbox.get(selection[0])
            config = self.rules["suspicious_patterns"][pattern]
            self.pattern_var.set(pattern)
            self.message_var.set(config.get("message", ""))
            self.severity_var.set(config.get("severity", "LOW"))
            self.threshold_var.set(config.get("threshold", 1))
            self.t_severity_var.set(config.get("threshold_severity", config.get("severity", "LOW")))
       
    def save_rule(self):
        """Add or update a rule in memory """
        pattern = self.pattern_var.get().strip()
        if not pattern:
            messagebox.showwarning("Warning", "Pattern cannot be empty")
            return
        
        self.rules["suspicious_patterns"][pattern] = {
            "message": self.message_var.get(),
            "severity": self.severity_var.get(),
            "threshold": self.threshold_var.get(),
            }
        self.refresh_listbox()
        messagebox.showinfo("Success", f"Rule for '{pattern}' updated locally. Don't forget to 'Save All to File'.")

    def delete_rule(self):
        """Delete selected rule."""
        selection = self.rules_listbox.curselection()
        if not selection:
            return
        
        pattern = self.rules_listbox.get(selection[0])
        if messagebox.askyesno("Confirm", f"Delete rule for '{pattern}'?"):
            del self.rules["suspicious_patterns"][pattern]
            self.refresh_listbox()
            self.pattern_var.set("")
            self.message_var.set("")

if __name__ == "__main__":
    #Application entry point
    root = tk.Tk()
    app = ConfigGUI(root)
    root.mainloop()
