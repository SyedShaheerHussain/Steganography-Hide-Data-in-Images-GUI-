import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import hashlib, base64, threading

DELIMITER = "#####"
PREVIEW_W = 520
PREVIEW_H = 520

# ================= ENCRYPTION =================
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_text(text, password):
    return Fernet(generate_key(password)).encrypt(text.encode()).decode()

def decrypt_text(text, password):
    try:
        return Fernet(generate_key(password)).decrypt(text.encode()).decode()
    except:
        return None

# ================= APP =================
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Tool")
        self.root.geometry("1200x750")
        self.root.configure(bg="#121212")

        self.encode_image = None
        self.decode_image = None

        self.setup_style()
        self.build_ui()

    # ================= STYLE =================
    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#121212")
        style.configure("TNotebook.Tab", background="#1f1f1f", foreground="white", padding=12)
        style.map("TNotebook.Tab", background=[("selected", "#333")])
        style.configure("TButton", background="#333", foreground="white", padding=10)
        style.configure("TLabel", background="#121212", foreground="white")

    # ================= UI =================
    def build_ui(self):
        ttk.Label(self.root, text="🔐 Image Steganography Tool (LSB + AES-256)",
                  font=("Segoe UI", 20, "bold")).pack(pady=10)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tab_encode = tk.Frame(notebook, bg="#121212")
        self.tab_decode = tk.Frame(notebook, bg="#121212")
        notebook.add(self.tab_encode, text="Hide Message")
        notebook.add(self.tab_decode, text="Extract Message")

        self.build_encode_tab()
        self.build_decode_tab()

    # ================= ENCODE TAB =================
    def build_encode_tab(self):
        left = tk.Frame(self.tab_encode, bg="#121212")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        right = tk.Frame(self.tab_encode, bg="#121212")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.encode_canvas = tk.Canvas(left, width=PREVIEW_W, height=PREVIEW_H, bg="#1f1f1f")
        self.encode_canvas.pack()

        ttk.Button(right, text="Select Image", command=self.select_encode_image).pack(pady=5, fill=tk.X)
        ttk.Label(right, text="Secret Message").pack(anchor="w", padx=5, pady=(10,0))
        self.secret_text = tk.Text(right, height=8, bg="#2b2b2b", fg="white")
        self.secret_text.pack(fill=tk.X, padx=5)
        ttk.Label(right, text="Password").pack(anchor="w", padx=5, pady=(10,0))
        self.encode_password = tk.Entry(right, show="*", bg="#2b2b2b", fg="white")
        self.encode_password.pack(fill=tk.X, padx=5)
        ttk.Button(right, text="Hide Message", command=lambda: threading.Thread(target=self.encode_message).start()).pack(pady=15, fill=tk.X)
        self.encode_progress = ttk.Progressbar(right)
        self.encode_progress.pack(fill=tk.X, padx=5, pady=10)

    # ================= DECODE TAB =================
    def build_decode_tab(self):
        left = tk.Frame(self.tab_decode, bg="#121212")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        right = tk.Frame(self.tab_decode, bg="#121212")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.decode_canvas = tk.Canvas(left, width=PREVIEW_W, height=PREVIEW_H, bg="#1f1f1f")
        self.decode_canvas.pack()

        ttk.Button(right, text="Select Encoded Image", command=self.select_decode_image).pack(pady=5, fill=tk.X)
        ttk.Label(right, text="Password").pack(anchor="w", padx=5, pady=(10,0))
        self.decode_password = tk.Entry(right, show="*", bg="#2b2b2b", fg="white")
        self.decode_password.pack(fill=tk.X, padx=5)
        ttk.Button(right, text="Extract Message", command=lambda: threading.Thread(target=self.decode_message).start()).pack(pady=15, fill=tk.X)
        ttk.Label(right, text="Extracted Message").pack(anchor="w", padx=5, pady=(10,0))
        self.output_text = tk.Text(right, height=8, bg="#2b2b2b", fg="white", state=tk.DISABLED)
        self.output_text.pack(fill=tk.X, padx=5)

    # ================= IMAGE PREVIEW =================
    def resize_for_preview(self, image):
        img_ratio = image.width / image.height
        box_ratio = PREVIEW_W / PREVIEW_H
        if img_ratio > box_ratio:
            new_w = PREVIEW_W
            new_h = int(PREVIEW_W / img_ratio)
        else:
            new_h = PREVIEW_H
            new_w = int(PREVIEW_H * img_ratio)
        return image.resize((new_w, new_h), Image.LANCZOS)

    def show_image_on_canvas(self, image, canvas):
        resized = self.resize_for_preview(image)
        canvas_image = Image.new("RGB", (PREVIEW_W, PREVIEW_H), "#1f1f1f")
        x = (PREVIEW_W - resized.width)//2
        y = (PREVIEW_H - resized.height)//2
        canvas_image.paste(resized, (x, y))
        self.tkimg = ImageTk.PhotoImage(canvas_image)
        canvas.create_image(0,0, anchor="nw", image=self.tkimg)

    # ================= SELECT IMAGES =================
    def select_encode_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images","*.png *.jpg *.jpeg")])
        if path:
            self.encode_image = Image.open(path).convert("RGB")
            self.show_image_on_canvas(self.encode_image, self.encode_canvas)

    def select_decode_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images","*.png *.jpg *.jpeg")])
        if path:
            self.decode_image = Image.open(path).convert("RGB")
            self.show_image_on_canvas(self.decode_image, self.decode_canvas)

    # ================= ENCODE =================
    def encode_message(self):
        if not self.encode_image:
            messagebox.showerror("Error", "Select image first")
            return
        message = self.secret_text.get("1.0", tk.END).strip()
        password = self.encode_password.get().strip()
        if not message or not password:
            messagebox.showerror("Error", "Message and password required")
            return

        encrypted = encrypt_text(message, password) + DELIMITER
        binary = ''.join(format(ord(c), '08b') for c in encrypted)

        pixels = list(self.encode_image.getdata())
        flat_pixels = []
        for r,g,b in pixels:
            flat_pixels.extend([r,g,b])

        if len(binary) > len(flat_pixels):
            messagebox.showerror("Error", "Message too large for image")
            return

        # Encode
        for i in range(len(binary)):
            flat_pixels[i] = (flat_pixels[i] & ~1) | int(binary[i])
            self.encode_progress["value"] = (i/len(binary))*100

        # Repack as RGB tuples
        new_pixels = list(zip(*(iter(flat_pixels),)*3))
        encoded_image = Image.new("RGB", self.encode_image.size)
        encoded_image.putdata(new_pixels)

        save = filedialog.asksaveasfilename(defaultextension=".png")
        if save:
            encoded_image.save(save)
            messagebox.showinfo("Success", "Message hidden successfully")
        self.encode_progress["value"] = 0

    # ================= DECODE =================
    def decode_message(self):
        if not self.decode_image:
            messagebox.showerror("Error", "Select encoded image")
            return
        password = self.decode_password.get().strip()
        if not password:
            messagebox.showerror("Error", "Password required")
            return

        pixels = list(self.decode_image.getdata())
        flat_pixels = []
        for r,g,b in pixels:
            flat_pixels.extend([r,g,b])

        binary = "".join(str(val & 1) for val in flat_pixels)

        data = ""
        for i in range(0, len(binary), 8):
            char = chr(int(binary[i:i+8],2))
            data += char
            if data.endswith(DELIMITER):
                data = data.replace(DELIMITER,"")
                break

        decrypted = decrypt_text(data, password)
        if decrypted is None:
            messagebox.showerror("Error","Wrong password or no message found")
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted)
        self.output_text.config(state=tk.DISABLED)

# ================= RUN =================
if __name__=="__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
