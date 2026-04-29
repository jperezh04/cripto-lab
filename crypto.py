"""
CriptoLab — One Time Pad & OTP XOR & Rejillas Criptográficas
Interfaz gráfica con tkinter, estilo terminal dark
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import base64
import math

# ──────────────────────────────────────────────
#  ALFABETO (27 letras con Ñ)
# ──────────────────────────────────────────────
ALFABETO = (
    list("ABCDEFGHIJKLMN") +
    ["Ñ"] +
    list("OPQRSTUVWXYZ")
)

N = len(ALFABETO)
CHAR_TO_IDX = {c: i for i, c in enumerate(ALFABETO)}

SUSTITUCIONES = {
    "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U", "Ü": "U",
    "á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u", "ü": "u",
}

# ──────────────────────────────────────────────
#  PREPROCESAMIENTO
# ──────────────────────────────────────────────
def preprocesar(texto: str) -> str:
    resultado = []
    for c in texto:
        if c == " ":
            continue
        c = SUSTITUCIONES.get(c, c).upper()
        if c not in CHAR_TO_IDX:
            raise ValueError(f"Carácter no permitido: '{c}'")
        resultado.append(c)
    return "".join(resultado)

# ──────────────────────────────────────────────
#  OTP CLÁSICO
# ──────────────────────────────────────────────
def otp_encriptar(mensaje: str, clave: str) -> str:
    m = preprocesar(mensaje)
    k = preprocesar(clave)
    if len(k) < len(m):
        raise ValueError(
            f"La clave debe tener al menos {len(m)} caracteres "
            f"(tiene {len(k)}, mensaje tiene {len(m)})."
        )
    return "".join(
        ALFABETO[(CHAR_TO_IDX[m[i]] + CHAR_TO_IDX[k[i]]) % N]
        for i in range(len(m))
    )

def otp_desencriptar(cifrado: str, clave: str) -> str:
    c = preprocesar(cifrado)
    k = preprocesar(clave)
    if len(k) < len(c):
        raise ValueError(
            f"La clave debe tener al menos {len(c)} caracteres "
            f"(tiene {len(k)}, cifrado tiene {len(c)})."
        )
    return "".join(
        ALFABETO[(CHAR_TO_IDX[c[i]] - CHAR_TO_IDX[k[i]]) % N]
        for i in range(len(c))
    )

# ──────────────────────────────────────────────
#  OTP XOR
# ──────────────────────────────────────────────
def encrypt_otp_xor(message: str, key: str) -> str:
    if len(message) != len(key):
        raise ValueError("El mensaje y la clave deben tener la misma longitud")

    # Convertir a bytes
    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')

    # XOR byte a byte
    result = bytes([m ^ k for m, k in zip(message_bytes, key_bytes)])

    # Codificar en Base64 (para hacerlo legible)
    return base64.b64encode(result).decode('utf-8')

# ──────────────────────────────────────────────
#  REJILLAS CRIPTOGRÁFICAS
# ──────────────────────────────────────────────
def rejilla_parse_posiciones(texto_pos: str, total_celdas: int) -> list[int]:
    """
    Parsea la lista de posiciones de la rejilla (1-based, separadas por comas o espacios).
    Devuelve lista de índices 0-based validados.
    """
    posiciones = []
    partes = texto_pos.replace(",", " ").split()
    if not partes:
        raise ValueError("No se indicaron posiciones para la rejilla.")
    for p in partes:
        try:
            idx = int(p) - 1  # convertir a 0-based
        except ValueError:
            raise ValueError(f"Posición inválida: '{p}'. Solo se permiten números enteros.")
        if idx < 0 or idx >= total_celdas:
            raise ValueError(
                f"Posición {p} fuera de rango. La cuadrícula tiene {total_celdas} celdas (1–{total_celdas})."
            )
        if idx in posiciones:
            raise ValueError(f"Posición {p} duplicada en la rejilla.")
        posiciones.append(idx)
    return posiciones


def rejilla_desencriptar(texto_cifrado: str, filas: int, cols: int,
                          posiciones: list[int]) -> tuple[str, list[list[str]]]:
    """
    Desencripta un texto usando rejilla criptográfica.
    
    Parámetros:
        texto_cifrado  — texto completo que llena la cuadrícula (filas×cols chars, sin espacios)
        filas, cols    — dimensiones de la cuadrícula
        posiciones     — índices 0-based de las celdas visibles por la rejilla
    
    Devuelve:
        (mensaje_extraído, matriz)  donde matriz[r][c] es el carácter en esa celda.
    """
    total = filas * cols
    # Eliminar espacios y saltos del texto cifrado
    chars = [c for c in texto_cifrado if c.strip()]

    if len(chars) < total:
        raise ValueError(
            f"El texto cifrado tiene solo {len(chars)} caracteres útiles "
            f"pero la cuadrícula {filas}×{cols} necesita {total}."
        )
    if len(chars) > total:
        chars = chars[:total]  # recortar al tamaño exacto

    # Construir matriz
    matriz = []
    for r in range(filas):
        fila = []
        for c in range(cols):
            fila.append(chars[r * cols + c])
        matriz.append(fila)

    # Extraer mensaje por las posiciones de la rejilla
    mensaje = "".join(chars[p] for p in posiciones)

    return mensaje, matriz


def rejilla_encriptar(mensaje: str, filas: int, cols: int,
                       posiciones: list[int], relleno: str = "") -> tuple[str, list[list[str]]]:
    """
    Encripta un mensaje usando rejilla criptográfica.
    Coloca las letras del mensaje en las posiciones de la rejilla
    y rellena el resto con el texto de relleno (o letras aleatorias si está vacío).
    
    Devuelve:
        (texto_completo_plano, matriz)
    """
    import random
    import string

    total = filas * cols
    msg_chars = [c for c in mensaje if c.strip()]

    if len(msg_chars) > len(posiciones):
        raise ValueError(
            f"El mensaje tiene {len(msg_chars)} caracteres pero la rejilla "
            f"solo tiene {len(posiciones)} posiciones abiertas."
        )

    # Rellenar posiciones no usadas del mensaje con espacios si el mensaje es más corto
    while len(msg_chars) < len(posiciones):
        msg_chars.append(" ")

    # Construir cuadrícula vacía
    celdas = [""] * total

    # Colocar mensaje en posiciones de rejilla
    for i, pos in enumerate(posiciones):
        celdas[pos] = msg_chars[i]

    # Rellenar el resto
    relleno_chars = [c for c in relleno if c.strip()]
    relleno_idx = 0
    for i in range(total):
        if celdas[i] == "":
            if relleno_idx < len(relleno_chars):
                celdas[i] = relleno_chars[relleno_idx]
                relleno_idx += 1
            else:
                celdas[i] = random.choice(string.ascii_uppercase)

    # Construir matriz
    matriz = []
    for r in range(filas):
        fila = []
        for c in range(cols):
            fila.append(celdas[r * cols + c])
        matriz.append(fila)

    texto_completo = "".join(celdas)
    return texto_completo, matriz


# ──────────────────────────────────────────────
#  COLORES Y FUENTES
# ──────────────────────────────────────────────
C = {
    "bg":       "#0D0D0D",
    "surface":  "#141414",
    "surface2": "#1C1C1C",
    "border":   "#2A2A2A",
    "accent":   "#C8FF00",   # verde lima
    "accent2":  "#FF6B35",   # naranja
    "accent3":  "#00CFFF",   # cian (para rejillas)
    "text":     "#F0F0F0",
    "muted":    "#888888",
    "error":    "#FF4444",
    "success":  "#44FF88",
    "highlight":"#FFD700",   # dorado para celdas activas
}

FM = ("Courier New", 11)
FL = ("Courier New", 10, "bold")
FT = ("Courier New", 18, "bold")
FS = ("Courier New",  9)

# ══════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════
class CriptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CriptoLab — OTP & XOR & Rejillas")
        self.configure(bg=C["bg"])
        self.geometry("920x780")
        self.resizable(True, True)
        self._build_ui()

    # ── cabecera ──────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self, bg=C["bg"], pady=18)
        hdr.pack(fill="x", padx=32)

        tk.Label(hdr, text="◈ CRIPTOLAB",
                 font=FT, fg=C["accent"], bg=C["bg"]).pack(side="left")
        tk.Label(hdr, text="  One Time Pad · OTP XOR · Rejillas",
                 font=("Courier New", 11), fg=C["muted"],
                 bg=C["bg"]).pack(side="left", padx=12, pady=4)

        tk.Frame(self, bg=C["accent"], height=1).pack(fill="x", padx=32)

        # ── notebook ──────────────────────────
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",
                        background=C["bg"],
                        borderwidth=0,
                        tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=C["surface2"],
                        foreground=C["muted"],
                        font=("Courier New", 11, "bold"),
                        padding=[20, 8],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", C["surface"])],
                  foreground=[("selected", C["accent"])])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=32, pady=16)

        tab_otp   = tk.Frame(nb, bg=C["bg"])
        tab_xor   = tk.Frame(nb, bg=C["bg"])
        tab_rej   = tk.Frame(nb, bg=C["bg"])
        tab_alfa  = tk.Frame(nb, bg=C["bg"])

        nb.add(tab_otp,  text=" OTP — Encriptar / Desencriptar ")
        nb.add(tab_xor,  text=" OTP XOR ")
        nb.add(tab_rej,  text=" Rejillas Criptográficas ")
        nb.add(tab_alfa, text=" Alfabeto ")

        self._build_otp_tab(tab_otp)
        self._build_xor_tab(tab_xor)
        self._build_rejilla_tab(tab_rej)
        self._build_alfa_tab(tab_alfa)

    # ── helpers ───────────────────────────────
    def _label(self, parent, text, color=None):
        return tk.Label(parent, text=text, font=FL,
                        fg=color or C["muted"], bg=C["bg"], anchor="w")

    def _text(self, parent, h=3):
        return scrolledtext.ScrolledText(
            parent, height=h, font=FM,
            bg=C["surface2"], fg=C["text"],
            insertbackground=C["accent"],
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=C["border"],
            highlightcolor=C["accent"],
            wrap="word"
        )

    def _btn(self, parent, text, cmd, color=None):
        c = color or C["accent"]
        return tk.Button(
            parent, text=text, command=cmd,
            font=FL, fg=C["bg"], bg=c,
            activebackground=C["text"],
            activeforeground=C["bg"],
            relief="flat", bd=0,
            padx=18, pady=8,
            cursor="hand2"
        )

    def _result_box(self, parent):
        frame = tk.Frame(parent, bg=C["surface"],
                         highlightthickness=1,
                         highlightbackground=C["accent"])
        frame.pack(fill="x", pady=(4, 0))
        lbl = tk.Label(frame, text="", font=FM,
                       fg=C["success"], bg=C["surface"],
                       wraplength=800, justify="left",
                       padx=12, pady=10, anchor="w")
        lbl.pack(fill="x")
        return lbl

    def _set_result(self, lbl, text, error=False):
        lbl.config(text=text, fg=C["error"] if error else C["success"])

    def _section(self, parent, title, accent_color=None):
        color = accent_color or C["accent"]
        f = tk.LabelFrame(parent, text=f"  {title}  ", font=FL,
                          fg=color, bg=C["bg"], bd=0,
                          highlightthickness=1,
                          highlightbackground=C["border"],
                          pady=10, padx=16)
        return f

    # ══════════════════════════════════════════
    #  TAB OTP CLÁSICO
    # ══════════════════════════════════════════
    def _build_otp_tab(self, parent):
        pad = dict(padx=4, pady=6)

        # ── Encriptar ─────────────────────────
        enc = self._section(parent, "ENCRIPTAR")
        enc.pack(fill="x", pady=(8, 0))

        self._label(enc, "Mensaje en claro:").pack(anchor="w", **pad)
        self.otp_msg = self._text(enc, h=3)
        self.otp_msg.pack(fill="x", **pad)

        self._label(enc, "Clave (≥ longitud del mensaje):").pack(anchor="w", **pad)
        self.otp_key_enc = self._text(enc, h=3)
        self.otp_key_enc.pack(fill="x", **pad)

        row = tk.Frame(enc, bg=C["bg"])
        row.pack(fill="x", **pad)
        self._btn(row, "◈  ENCRIPTAR", self._otp_encrypt).pack(side="left")
        self._btn(row, "⟳  Limpiar", self._clear_otp_enc,
                  color=C["surface2"]).pack(side="left", padx=8)

        self._label(enc, "Resultado cifrado:").pack(anchor="w", **pad)
        self.otp_enc_result = self._result_box(enc)

        # ── Desencriptar ──────────────────────
        dec = self._section(parent, "DESENCRIPTAR", accent_color=C["accent2"])
        dec.pack(fill="x", pady=(14, 0))

        self._label(dec, "Texto cifrado:").pack(anchor="w", **pad)
        self.otp_cipher = self._text(dec, h=3)
        self.otp_cipher.pack(fill="x", **pad)

        self._label(dec, "Clave:").pack(anchor="w", **pad)
        self.otp_key_dec = self._text(dec, h=3)
        self.otp_key_dec.pack(fill="x", **pad)

        row2 = tk.Frame(dec, bg=C["bg"])
        row2.pack(fill="x", **pad)
        self._btn(row2, "◈  DESENCRIPTAR", self._otp_decrypt,
                  color=C["accent2"]).pack(side="left")
        self._btn(row2, "⟳  Limpiar", self._clear_otp_dec,
                  color=C["surface2"]).pack(side="left", padx=8)

        self._label(dec, "Resultado:").pack(anchor="w", **pad)
        self.otp_dec_result = self._result_box(dec)

    def _otp_encrypt(self):
        try:
            res = otp_encriptar(self.otp_msg.get("1.0", "end-1c"),
                                self.otp_key_enc.get("1.0", "end-1c"))
            self._set_result(self.otp_enc_result, res)
        except Exception as e:
            self._set_result(self.otp_enc_result, f"ERROR: {e}", error=True)

    def _otp_decrypt(self):
        try:
            res = otp_desencriptar(self.otp_cipher.get("1.0", "end-1c"),
                                   self.otp_key_dec.get("1.0", "end-1c"))
            self._set_result(self.otp_dec_result, res)
        except Exception as e:
            self._set_result(self.otp_dec_result, f"ERROR: {e}", error=True)

    def _clear_otp_enc(self):
        self.otp_msg.delete("1.0", "end")
        self.otp_key_enc.delete("1.0", "end")
        self._set_result(self.otp_enc_result, "")

    def _clear_otp_dec(self):
        self.otp_cipher.delete("1.0", "end")
        self.otp_key_dec.delete("1.0", "end")
        self._set_result(self.otp_dec_result, "")

    # ══════════════════════════════════════════
    #  TAB OTP XOR
    # ══════════════════════════════════════════
    def _build_xor_tab(self, parent):
        pad = dict(padx=4, pady=6)

        info = tk.Label(parent,
                        text="Cifrado XOR byte a byte. El resultado se entrega en Base64.\n"
                             "Mensaje y clave deben tener exactamente la misma longitud.",
                        font=FS, fg=C["muted"], bg=C["bg"],
                        justify="left", anchor="w")
        info.pack(anchor="w", padx=4, pady=(10, 4))

        sec = self._section(parent, "OTP XOR — ENCRIPTAR", accent_color=C["accent2"])
        sec.pack(fill="x", pady=(4, 0))

        self._label(sec, "Mensaje:").pack(anchor="w", **pad)
        self.xor_msg = self._text(sec, h=4)
        self.xor_msg.pack(fill="x", **pad)

        self._label(sec, "Clave (misma longitud exacta):").pack(anchor="w", **pad)
        self.xor_key = self._text(sec, h=4)
        self.xor_key.pack(fill="x", **pad)

        # contador de longitud en tiempo real
        len_frame = tk.Frame(sec, bg=C["bg"])
        len_frame.pack(anchor="w", padx=4)
        self.xor_len_lbl = tk.Label(len_frame, text="Mensaje: 0 chars  |  Clave: 0 chars",
                                    font=FS, fg=C["muted"], bg=C["bg"])
        self.xor_len_lbl.pack(side="left")
        self.xor_msg.bind("<KeyRelease>", self._xor_update_len)
        self.xor_key.bind("<KeyRelease>", self._xor_update_len)

        row = tk.Frame(sec, bg=C["bg"])
        row.pack(fill="x", **pad)
        self._btn(row, "◈  ENCRIPTAR XOR", self._xor_encrypt,
                  color=C["accent2"]).pack(side="left")
        self._btn(row, "⟳  Limpiar", self._clear_xor,
                  color=C["surface2"]).pack(side="left", padx=8)

        self._label(sec, "Resultado (Base64):").pack(anchor="w", **pad)
        self.xor_result = self._result_box(sec)

    def _xor_update_len(self, _event=None):
        m = self.xor_msg.get("1.0", "end-1c")
        k = self.xor_key.get("1.0", "end-1c")
        match = "✓ igual" if len(m) == len(k) else "✗ distinto"
        color = C["success"] if len(m) == len(k) else C["error"]
        self.xor_len_lbl.config(
            text=f"Mensaje: {len(m)} chars  |  Clave: {len(k)} chars  |  {match}",
            fg=color
        )

    def _xor_encrypt(self):
        try:
            res = encrypt_otp_xor(self.xor_msg.get("1.0", "end-1c"),
                                  self.xor_key.get("1.0", "end-1c"))
            self._set_result(self.xor_result, res)
        except Exception as e:
            self._set_result(self.xor_result, f"ERROR: {e}", error=True)

    def _clear_xor(self):
        self.xor_msg.delete("1.0", "end")
        self.xor_key.delete("1.0", "end")
        self._set_result(self.xor_result, "")
        self._xor_update_len()

    # ══════════════════════════════════════════
    #  TAB REJILLAS CRIPTOGRÁFICAS
    # ══════════════════════════════════════════
    def _build_rejilla_tab(self, parent):
        """
        Pestaña completa para encriptar y desencriptar usando rejilla criptográfica.
        
        Funcionamiento:
          - Se define una cuadrícula de F×C celdas.
          - Las "posiciones abiertas" de la rejilla son las celdas visibles
            (numeradas de 1 a F×C, de izq a der, fila a fila).
          - Al DESENCRIPTAR: se toma el texto cifrado que llena la cuadrícula
            y se extraen los caracteres en las posiciones abiertas.
          - Al ENCRIPTAR: se coloca el mensaje en las posiciones abiertas
            y se rellena el resto con texto de relleno (o letras aleatorias).
          - Se muestra la cuadrícula visual con las celdas activas resaltadas.
        """
        # Scrollable container
        canvas = tk.Canvas(parent, bg=C["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=C["bg"])

        scroll_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        pad = dict(padx=4, pady=5)
        A3 = C["accent3"]

        # ── Info ─────────────────────────────
        info_frame = tk.Frame(scroll_frame, bg=C["surface"],
                              highlightthickness=1,
                              highlightbackground=C["border"],
                              padx=14, pady=10)
        info_frame.pack(fill="x", padx=4, pady=(10, 6))

        tk.Label(info_frame,
                 text="◈  REJILLA CRIPTOGRÁFICA  (Grille Cipher)",
                 font=("Courier New", 11, "bold"),
                 fg=A3, bg=C["surface"]).pack(anchor="w")
        tk.Label(info_frame,
                 text=(
                     "Una rejilla es una plantilla con agujeros que se coloca sobre un texto.\n"
                     "Solo las celdas visibles (abiertas) revelan el mensaje oculto.\n"
                     "Define las dimensiones de la cuadrícula y las posiciones abiertas (1-based)."
                 ),
                 font=FS, fg=C["muted"], bg=C["surface"],
                 justify="left").pack(anchor="w", pady=(4, 0))

        # ── Configuración de la rejilla ──────
        cfg = self._section(scroll_frame, "CONFIGURACIÓN DE LA REJILLA", accent_color=A3)
        cfg.pack(fill="x", padx=4, pady=(4, 0))

        dim_row = tk.Frame(cfg, bg=C["bg"])
        dim_row.pack(anchor="w", **pad)

        tk.Label(dim_row, text="Filas:", font=FL, fg=C["muted"],
                 bg=C["bg"]).pack(side="left")
        self.rej_filas = tk.Spinbox(dim_row, from_=2, to=12, width=4,
                                    font=FM, bg=C["surface2"], fg=C["accent"],
                                    buttonbackground=C["border"],
                                    insertbackground=C["accent"],
                                    relief="flat", highlightthickness=1,
                                    highlightbackground=C["border"],
                                    justify="center")
        self.rej_filas.delete(0, "end")
        self.rej_filas.insert(0, "4")
        self.rej_filas.pack(side="left", padx=6)

        tk.Label(dim_row, text="Columnas:", font=FL, fg=C["muted"],
                 bg=C["bg"]).pack(side="left", padx=(14, 0))
        self.rej_cols = tk.Spinbox(dim_row, from_=2, to=12, width=4,
                                   font=FM, bg=C["surface2"], fg=C["accent"],
                                   buttonbackground=C["border"],
                                   insertbackground=C["accent"],
                                   relief="flat", highlightthickness=1,
                                   highlightbackground=C["border"],
                                   justify="center")
        self.rej_cols.delete(0, "end")
        self.rej_cols.insert(0, "4")
        self.rej_cols.pack(side="left", padx=6)

        self.rej_total_lbl = tk.Label(dim_row,
                                      text="→ 16 celdas en total",
                                      font=FS, fg=C["muted"], bg=C["bg"])
        self.rej_total_lbl.pack(side="left", padx=14)

        self.rej_filas.bind("<KeyRelease>", self._rej_update_total)
        self.rej_filas.bind("<<Decrement>>", self._rej_update_total)
        self.rej_filas.bind("<<Increment>>", self._rej_update_total)
        self.rej_cols.bind("<KeyRelease>", self._rej_update_total)
        self.rej_cols.bind("<<Decrement>>", self._rej_update_total)
        self.rej_cols.bind("<<Increment>>", self._rej_update_total)

        self._label(cfg, "Posiciones abiertas de la rejilla (números separados por coma o espacio):").pack(
            anchor="w", **pad)
        self.rej_posiciones = self._text(cfg, h=2)
        self.rej_posiciones.pack(fill="x", **pad)
        self.rej_posiciones.insert("1.0", "1, 6, 11, 16")

        tk.Label(cfg,
                 text="Ejemplo para 4×4: '1, 6, 11, 16' abre las posiciones de la diagonal principal.",
                 font=FS, fg=C["muted"], bg=C["bg"]).pack(anchor="w", padx=4)

        # ── Vista previa de la rejilla ────────
        prev_btn_row = tk.Frame(cfg, bg=C["bg"])
        prev_btn_row.pack(fill="x", **pad)
        self._btn(prev_btn_row, "⊞  PREVISUALIZAR REJILLA",
                  self._rej_preview, color=C["border"]).pack(side="left")

        self.rej_preview_frame = tk.Frame(cfg, bg=C["bg"])
        self.rej_preview_frame.pack(anchor="w", padx=4, pady=(4, 0))

        # ── Desencriptar ─────────────────────
        dec_sec = self._section(scroll_frame, "DESENCRIPTAR CON REJILLA", accent_color=A3)
        dec_sec.pack(fill="x", padx=4, pady=(12, 0))

        self._label(dec_sec, "Texto cifrado (llena la cuadrícula completa):").pack(
            anchor="w", **pad)
        self.rej_cipher_text = self._text(dec_sec, h=4)
        self.rej_cipher_text.pack(fill="x", **pad)

        row_dec = tk.Frame(dec_sec, bg=C["bg"])
        row_dec.pack(fill="x", **pad)
        self._btn(row_dec, "◈  DESENCRIPTAR", self._rej_decrypt,
                  color=A3).pack(side="left")
        self._btn(row_dec, "⟳  Limpiar", self._clear_rej_dec,
                  color=C["surface2"]).pack(side="left", padx=8)

        self._label(dec_sec, "Mensaje extraído:").pack(anchor="w", **pad)
        self.rej_dec_result = self._result_box(dec_sec)

        # cuadrícula visual del resultado decrypt
        self._label(dec_sec, "Visualización de la cuadrícula (celdas activas en dorado):").pack(
            anchor="w", **pad)
        self.rej_dec_grid_frame = tk.Frame(dec_sec, bg=C["bg"])
        self.rej_dec_grid_frame.pack(anchor="w", padx=4, pady=(2, 8))

        # ── Encriptar ─────────────────────────
        enc_sec = self._section(scroll_frame, "ENCRIPTAR CON REJILLA", accent_color=C["accent2"])
        enc_sec.pack(fill="x", padx=4, pady=(12, 0))

        self._label(enc_sec, "Mensaje a ocultar:").pack(anchor="w", **pad)
        self.rej_plain_text = self._text(enc_sec, h=3)
        self.rej_plain_text.pack(fill="x", **pad)

        self._label(enc_sec,
                    "Texto de relleno (opcional — si está vacío se usarán letras aleatorias):").pack(
            anchor="w", **pad)
        self.rej_relleno_text = self._text(enc_sec, h=2)
        self.rej_relleno_text.pack(fill="x", **pad)

        row_enc = tk.Frame(enc_sec, bg=C["bg"])
        row_enc.pack(fill="x", **pad)
        self._btn(row_enc, "◈  ENCRIPTAR", self._rej_encrypt,
                  color=C["accent2"]).pack(side="left")
        self._btn(row_enc, "⟳  Limpiar", self._clear_rej_enc,
                  color=C["surface2"]).pack(side="left", padx=8)

        self._label(enc_sec, "Texto cifrado resultante:").pack(anchor="w", **pad)
        self.rej_enc_result = self._result_box(enc_sec)

        # cuadrícula visual del resultado encrypt
        self._label(enc_sec, "Visualización de la cuadrícula (celdas activas en dorado):").pack(
            anchor="w", **pad)
        self.rej_enc_grid_frame = tk.Frame(enc_sec, bg=C["bg"])
        self.rej_enc_grid_frame.pack(anchor="w", padx=4, pady=(2, 8))

    # ── helpers rejilla ───────────────────────
    def _rej_get_dims(self):
        """Devuelve (filas, cols) como enteros, con validación."""
        try:
            filas = int(self.rej_filas.get())
            cols  = int(self.rej_cols.get())
        except ValueError:
            raise ValueError("Las dimensiones de la cuadrícula deben ser números enteros.")
        if filas < 2 or cols < 2:
            raise ValueError("La cuadrícula debe tener al menos 2 filas y 2 columnas.")
        if filas > 12 or cols > 12:
            raise ValueError("La cuadrícula no puede superar 12×12.")
        return filas, cols

    def _rej_update_total(self, _event=None):
        try:
            f = int(self.rej_filas.get())
            c = int(self.rej_cols.get())
            self.rej_total_lbl.config(
                text=f"→ {f*c} celdas en total",
                fg=C["muted"]
            )
        except ValueError:
            self.rej_total_lbl.config(text="→ ? celdas", fg=C["error"])

    def _rej_draw_grid(self, frame, matriz, posiciones_set, cell_size=36):
        """Dibuja la cuadrícula en el frame dado."""
        for widget in frame.winfo_children():
            widget.destroy()

        filas = len(matriz)
        cols  = len(matriz[0]) if filas > 0 else 0

        for r in range(filas):
            for c in range(cols):
                idx = r * cols + c
                char = matriz[r][c]
                is_open = idx in posiciones_set

                bg_color  = C["highlight"] if is_open else C["surface2"]
                fg_color  = C["bg"]        if is_open else C["muted"]
                border_c  = C["highlight"] if is_open else C["border"]

                cell = tk.Frame(frame,
                                width=cell_size, height=cell_size,
                                bg=bg_color,
                                highlightthickness=1,
                                highlightbackground=border_c)
                cell.grid(row=r, column=c, padx=1, pady=1)
                cell.grid_propagate(False)

                tk.Label(cell, text=char,
                         font=("Courier New", 11, "bold"),
                         fg=fg_color, bg=bg_color).place(
                             relx=0.5, rely=0.5, anchor="center")

    def _rej_preview(self):
        """Muestra una rejilla vacía con las posiciones marcadas."""
        for widget in self.rej_preview_frame.winfo_children():
            widget.destroy()
        try:
            filas, cols = self._rej_get_dims()
            total = filas * cols
            pos_raw = self.rej_posiciones.get("1.0", "end-1c")
            posiciones = rejilla_parse_posiciones(pos_raw, total)
            pos_set = set(posiciones)

            # Construir matriz con índices
            matriz = []
            for r in range(filas):
                fila = []
                for c in range(cols):
                    idx = r * cols + c
                    fila.append(str(idx + 1))  # mostrar número de celda
                matriz.append(fila)

            self._rej_draw_grid(self.rej_preview_frame, matriz, pos_set, cell_size=38)

            tk.Label(self.rej_preview_frame,
                     text=f"\n  {len(posiciones)} posiciones abiertas  |  "
                          f"{total - len(posiciones)} posiciones cerradas",
                     font=FS, fg=C["muted"], bg=C["bg"]).grid(
                         row=filas + 1, column=0, columnspan=cols, sticky="w", pady=(4, 0))

        except Exception as e:
            tk.Label(self.rej_preview_frame,
                     text=f"ERROR: {e}", font=FS,
                     fg=C["error"], bg=C["bg"]).pack(anchor="w")

    def _rej_decrypt(self):
        try:
            filas, cols = self._rej_get_dims()
            total = filas * cols
            pos_raw  = self.rej_posiciones.get("1.0", "end-1c")
            posiciones = rejilla_parse_posiciones(pos_raw, total)

            texto = self.rej_cipher_text.get("1.0", "end-1c")
            mensaje, matriz = rejilla_desencriptar(texto, filas, cols, posiciones)

            self._set_result(self.rej_dec_result,
                             f"Mensaje: {mensaje}  ({len(mensaje)} caracteres)")
            self._rej_draw_grid(self.rej_dec_grid_frame, matriz,
                                set(posiciones), cell_size=36)
        except Exception as e:
            self._set_result(self.rej_dec_result, f"ERROR: {e}", error=True)
            for w in self.rej_dec_grid_frame.winfo_children():
                w.destroy()

    def _rej_encrypt(self):
        try:
            filas, cols = self._rej_get_dims()
            total = filas * cols
            pos_raw = self.rej_posiciones.get("1.0", "end-1c")
            posiciones = rejilla_parse_posiciones(pos_raw, total)

            mensaje  = self.rej_plain_text.get("1.0", "end-1c")
            relleno  = self.rej_relleno_text.get("1.0", "end-1c")

            texto_cifrado, matriz = rejilla_encriptar(
                mensaje, filas, cols, posiciones, relleno)

            self._set_result(self.rej_enc_result,
                             f"Cifrado: {texto_cifrado}  ({len(texto_cifrado)} caracteres)")
            self._rej_draw_grid(self.rej_enc_grid_frame, matriz,
                                set(posiciones), cell_size=36)
        except Exception as e:
            self._set_result(self.rej_enc_result, f"ERROR: {e}", error=True)
            for w in self.rej_enc_grid_frame.winfo_children():
                w.destroy()

    def _clear_rej_dec(self):
        self.rej_cipher_text.delete("1.0", "end")
        self._set_result(self.rej_dec_result, "")
        for w in self.rej_dec_grid_frame.winfo_children():
            w.destroy()

    def _clear_rej_enc(self):
        self.rej_plain_text.delete("1.0", "end")
        self.rej_relleno_text.delete("1.0", "end")
        self._set_result(self.rej_enc_result, "")
        for w in self.rej_enc_grid_frame.winfo_children():
            w.destroy()

    # ══════════════════════════════════════════
    #  TAB ALFABETO
    # ══════════════════════════════════════════
    def _build_alfa_tab(self, parent):
        tk.Label(parent,
                 text="Alfabeto estándar — 27 caracteres (con Ñ)",
                 font=FL, fg=C["accent"], bg=C["bg"]).pack(
                     anchor="w", padx=4, pady=(12, 6))

        table_frame = tk.Frame(parent, bg=C["bg"])
        table_frame.pack(anchor="w", padx=4)

        cols_per_row = 9
        for idx, char in enumerate(ALFABETO):
            r, c_col = divmod(idx, cols_per_row)

            cell = tk.Frame(table_frame, bg=C["surface2"],
                            highlightthickness=1,
                            highlightbackground=C["border"],
                            padx=8, pady=6)
            cell.grid(row=r * 2, column=c_col, padx=3, pady=(3, 0))
            tk.Label(cell, text=char,
                     font=("Courier New", 13, "bold"),
                     fg=C["accent"], bg=C["surface2"]).pack()

            idx_cell = tk.Frame(table_frame, bg=C["bg"])
            idx_cell.grid(row=r * 2 + 1, column=c_col, pady=(0, 3))
            tk.Label(idx_cell, text=str(idx),
                     font=FS, fg=C["muted"], bg=C["bg"]).pack()

        note_frame = tk.Frame(parent, bg=C["surface"],
                              highlightthickness=1,
                              highlightbackground=C["border"],
                              padx=16, pady=12)
        note_frame.pack(fill="x", padx=4, pady=20)

        notas = [
            "◈  Total: 27 caracteres (índices 0–26)",
            "◈  A–Z incluye Ñ en posición 14 (…N=13, Ñ=14, O=15…)",
            "◈  Espacios ignorados durante el preprocesamiento",
            "◈  Tildes sustituidas: Á→A, É→E, Í→I, Ó→O, Ú/Ü→U",
            "◈  OTP XOR trabaja directamente sobre bytes UTF-8",
            "◈  Caracteres fuera del alfabeto generan error en OTP clásico",
            "◈  Rejilla: las posiciones se numeran 1..F×C de izq a der, fila a fila",
        ]
        for n in notas:
            tk.Label(note_frame, text=n,
                     font=("Courier New", 10),
                     fg=C["muted"], bg=C["surface"],
                     anchor="w").pack(anchor="w")


if __name__ == "__main__":
    app = CriptoApp()
    app.mainloop()