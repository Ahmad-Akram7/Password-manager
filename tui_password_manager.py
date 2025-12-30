from textual.app import App, ComposeResult
from textual.screen import Screen, ModalScreen
from textual.widgets import Header, Footer, Button, Static, Input, DataTable, Label
from textual.containers import Grid, VerticalScroll
from textual.binding import Binding
import password as pm

class Notification(Static):
    """A notification widget."""

    def on_mount(self) -> None:
        self.set_timer(3, self.remove)

class AddPasswordScreen(ModalScreen):
    """Screen for adding a new password."""

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Add New Password", id="title"),
            Label("Username:"),
            Input(placeholder="e.g., my_username", id="username"),
            Label("Password:"),
            Input(placeholder="e.g., ********", id="password", password=True),
            Label("Master Password:"),
            Input(placeholder="Your master password", id="master_password", password=True),
            Button("Add", variant="primary", id="add"),
            Button("Cancel", variant="default", id="cancel"),
            id="add_password_grid",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add":
            username = self.query_one("#username", Input).value
            password = self.query_one("#password", Input).value
            master_password = self.query_one("#master_password", Input).value
            if not all([username, password, master_password]):
                self.app.mount(Notification("All fields are required!", classes="error"))
                return
            conn, c = pm.init_db()
            try:
                salt, encrypted_pass = pm.encrypt_password(password, master_password)
                c.execute('''INSERT INTO passwords (username, salt, encrypted_password)
                             VALUES (?, ?, ?)''', (username, salt, encrypted_pass))
                conn.commit()
                self.dismiss(("Password added successfully!", "success"))
            except Exception as e:
                self.dismiss((f"Error: {e}", "error"))
            finally:
                conn.close()
        else:
            self.dismiss(None)

class RetrievePasswordsScreen(ModalScreen):
    """Screen for retrieving passwords."""

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Retrieve Passwords", id="title"),
            Label("Master Password:"),
            Input(placeholder="Your master password", id="master_password", password=True),
            Button("Retrieve", variant="primary", id="retrieve"),
            Button("Cancel", variant="default", id="cancel"),
            id="retrieve_password_grid",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "retrieve":
            master_password = self.query_one("#master_password", Input).value
            if not master_password:
                self.app.mount(Notification("Master password is required!", classes="error"))
                return
            conn, c = pm.init_db()
            c.execute('''SELECT username, salt, encrypted_password FROM passwords''')
            results = c.fetchall()
            conn.close()

            passwords = []
            for result in results:
                username, salt, encrypted_password = result
                decrypted_password = pm.decrypt_password(encrypted_password, salt, master_password)
                if decrypted_password:
                    passwords.append((username, decrypted_password))
            self.dismiss(passwords)
        else:
            self.dismiss([])

class UpdatePasswordScreen(ModalScreen):
    """Screen for updating a password."""

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Update Password", id="title"),
            Label("Username:"),
            Input(placeholder="Username to update", id="username"),
            Label("New Password:"),
            Input(placeholder="New password", id="new_password", password=True),
            Label("Master Password:"),
            Input(placeholder="Your master password", id="master_password", password=True),
            Button("Update", variant="primary", id="update"),
            Button("Cancel", variant="default", id="cancel"),
            id="update_password_grid",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "update":
            username = self.query_one("#username", Input).value
            new_password = self.query_one("#new_password", Input).value
            master_password = self.query_one("#master_password", Input).value
            if not all([username, new_password, master_password]):
                self.app.mount(Notification("All fields are required!", classes="error"))
                return
            conn, c = pm.init_db()
            try:
                salt, encrypted_pass = pm.encrypt_password(new_password, master_password)
                c.execute('''UPDATE passwords SET salt=?, encrypted_password=?
                             WHERE username=?''', (salt, encrypted_pass, username))
                conn.commit()
                self.dismiss(("Password updated successfully!", "success"))
            except Exception as e:
                self.dismiss((f"Error: {e}", "error"))
            finally:
                conn.close()
        else:
            self.dismiss(None)

class DeletePasswordScreen(ModalScreen):
    """Screen for deleting a password."""

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Delete Password", id="title"),
            Label("Username:"),
            Input(placeholder="Username to delete", id="username"),
            Button("Delete", variant="error", id="delete"),
            Button("Cancel", variant="default", id="cancel"),
            id="delete_password_grid",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "delete":
            username = self.query_one("#username", Input).value
            if not username:
                self.app.mount(Notification("Username is required!", classes="error"))
                return
            conn, c = pm.init_db()
            try:
                c.execute('''DELETE FROM passwords WHERE username=?''', (username,))
                conn.commit()
                self.dismiss(("Password deleted successfully!", "success"))
            except Exception as e:
                self.dismiss((f"Error: {e}", "error"))
            finally:
                conn.close()
        else:
            self.dismiss(None)


class PasswordManagerTUI(App):
    """A Textual interface for the password manager."""

    CSS_PATH = "tui.css"
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        yield VerticalScroll(
            Static("🔑 PassSafe", id="logo"),
            Static("Your friendly neighborhood password manager", id="subtitle"),
            Button("Add Password", id="add_password", variant="primary"),
            Button("Retrieve Passwords", id="retrieve_passwords", variant="success"),
            Button("Update Password", id="update_password", variant="warning"),
            Button("Delete Password", id="delete_password", variant="error"),
            DataTable(id="password_table"),
            id="main_container"
        )

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Username", "Password")
        table.visible = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add_password":
            def callback(result):
                if result:
                    message, status = result
                    self.mount(Notification(message, classes=status))
            self.push_screen(AddPasswordScreen(), callback)
        elif event.button.id == "retrieve_passwords":
            def show_passwords(passwords: list):
                table = self.query_one(DataTable)
                table.clear()
                if passwords:
                    for username, password in passwords:
                        table.add_row(username, password)
                    table.visible = True
                    self.mount(Notification("Passwords retrieved!", classes="success"))
                else:
                    table.visible = False
                    self.mount(Notification("No passwords found or master password incorrect.", classes="error"))
            self.push_screen(RetrievePasswordsScreen(), show_passwords)
        elif event.button.id == "update_password":
            def callback(result):
                if result:
                    message, status = result
                    self.mount(Notification(message, classes=status))
            self.push_screen(UpdatePasswordScreen(), callback)
        elif event.button.id == "delete_password":
            def callback(result):
                if result:
                    message, status = result
                    self.mount(Notification(message, classes=status))
            self.push_screen(DeletePasswordScreen(), callback)

if __name__ == "__main__":
    app = PasswordManagerTUI()
    app.run()