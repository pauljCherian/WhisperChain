import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext

class MessagingApp(tk.Tk):
    def enable_main_buttons(self):
        self.send_btn.config(state="normal")
        self.retrieve_btn.config(state="normal")
        self.flag_btn.config(state="normal")
        self.exit_btn.config(state="normal")
        
    def __init__(self):
        super().__init__()
        self.title("Messaging Client")
        self.geometry("500x400")
        self.create_widgets()
        self.current_user = None
        self.show_login_dialog()

    def create_widgets(self):
        # Main action buttons
        self.btn_frame = tk.Frame(self)
        self.btn_frame.pack(pady=10)

        self.send_btn = tk.Button(self.btn_frame, text="Send Message", width=20, command=self.send_message_dialog, state="disabled")
        self.send_btn.pack(pady=5)
        self.retrieve_btn = tk.Button(self.btn_frame, text="Retrieve Messages", width=20, command=self.retrieve_messages_dialog, state="disabled")
        self.retrieve_btn.pack(pady=5)
        self.flag_btn = tk.Button(self.btn_frame, text="Flag Message", width=20, command=self.flag_message_dialog, state="disabled")
        self.flag_btn.pack(pady=5)
        self.exit_btn = tk.Button(self.btn_frame, text="Exit", width=20, command=self.quit, state="disabled")
        self.exit_btn.pack(pady=5)

        # Output area
        self.output_area = scrolledtext.ScrolledText(self, height=15, width=60, state='disabled')
        self.output_area.pack(pady=10)

    def send_message_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Send Message")
        tk.Label(dialog, text="Recipient:").pack()
        recipient_entry = tk.Entry(dialog)
        recipient_entry.pack()
        tk.Label(dialog, text="Message:").pack()
        message_entry = tk.Entry(dialog)
        message_entry.pack()
        def send():
            recipient = recipient_entry.get()
            message = message_entry.get()
            # TODO: Call send_message(recipient, message)
            self.display_output(f"[Send] To: {recipient}, Message: {message}")
            dialog.destroy()
        tk.Button(dialog, text="Send", command=send).pack(pady=5)

    def retrieve_messages_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Retrieve Messages")
        tk.Label(dialog, text="Round Number (leave blank for current):").pack()
        round_entry = tk.Entry(dialog)
        round_entry.pack()
        def retrieve():
            round_number = round_entry.get()
            # TODO: Call read_messages(round_number)
            self.display_output(f"[Retrieve] Round: {round_number or 'current'}")
            dialog.destroy()
        tk.Button(dialog, text="Retrieve", command=retrieve).pack(pady=5)

    def flag_message_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Flag Message")
        tk.Label(dialog, text="Message ID:").pack()
        msgid_entry = tk.Entry(dialog)
        msgid_entry.pack()
        tk.Label(dialog, text="Reason:").pack()
        reason_entry = tk.Entry(dialog)
        reason_entry.pack()
        def flag():
            msgid = msgid_entry.get()
            reason = reason_entry.get()
            # TODO: Call flag_message(msgid, reason)
            self.display_output(f"[Flag] ID: {msgid}, Reason: {reason}")
            dialog.destroy()
        tk.Button(dialog, text="Flag", command=flag).pack(pady=5)

    def display_output(self, text):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, text + '\n')
        self.output_area.config(state='disabled')
        self.output_area.see(tk.END)

    def show_login_dialog(self):
        login_dialog = tk.Toplevel(self)
        login_dialog.title("Login")
        login_dialog.grab_set()  # Make dialog modal

        tk.Label(login_dialog, text="Username:").pack()
        username_entry = tk.Entry(login_dialog)
        username_entry.pack()
        tk.Label(login_dialog, text="Password:").pack()
        password_entry = tk.Entry(login_dialog, show="*")
        password_entry.pack()

        def attempt_login():
            username = username_entry.get()
            password = password_entry.get()
            # TODO: Call your login(username, password) function here
            # For now, just accept any input as successful
            if username and password:
                self.current_user = username  # Store for later use
                self.display_output(f"Logged in as {username}")
                login_dialog.destroy()
                self.enable_main_buttons()
            else:
                messagebox.showerror("Login Failed", "Please enter both username and password.")

        tk.Button(login_dialog, text="Login", command=attempt_login).pack(pady=5)
        login_dialog.protocol("WM_DELETE_WINDOW", self.quit)  # Exit if login window is closed


if __name__ == "__main__":
    app = MessagingApp()
    app.mainloop()