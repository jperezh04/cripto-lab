"""
Aplicación Criptográfica: One Time Pad & Rejillas Criptográficas
Interfaz gráfica con tkinter
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re

# ──────────────────────────────────────────────
#  ALFABETO ESTÁNDAR (38 caracteres)
# ──────────────────────────────────────────────
ALFABETO = list("ABCDEFGHIJKLMNÑOPQRSTUVWXYZ ") + list("0123456789")
# Posiciones:
#   A=0 ... N=13, Ñ=14, O=15 ... Z=25, ESPACIO=26(??)
# Re-construimos con el orden correcto:
# A B C D E F G H I J K L M N Ñ O P Q R S T U V W X Y Z [SP] 0 1 2 3 4 5 6 7 8 9
# índices 0..26=letras+Ñ, 27=espacio, 28-37=dígitos
ALFABETO = (
    list("ABCDEFGHIJKLMN") +   # 0-13
    ["Ñ"] +                     # 14
    list("OPQRSTUVWXYZ") +      # 15-26
    [" "] +                     # 27 = espacio
    list("0123456789")           # 28-37
)
N = len(ALFABETO)  # 38
CHAR_TO_IDX = {c: i for i, c in enumerate(ALFABETO)}

SUSTITUCIONES = {
    "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U", "Ü": "U",
    "á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u", "ü": "u",
}

# ──────────────────────────────────────────────
#  PRE-PROCESAMIENTO
# ──────────────────────────────────────────────
def preprocesar(texto: str) -> str:
    """Convierte a mayúsculas, elimina tildes, valida caracteres."""
    resultado = []
    for c in texto:
        c = SUSTITUCIONES.get(c, c)
        c = c.upper()
        if c not in CHAR_TO_IDX:
            raise ValueError(f"Carácter no permitido en el alfabeto: '{c}'")
        resultado.append(c)
    return "".join(resultado)

# ──────────────────────────────────────────────
#  ONE TIME PAD
# ──────────────────────────────────────────────
def otp_encriptar(mensaje: str, clave: str) -> str:
    m = preprocesar(mensaje)
    k = preprocesar(clave)
    if len(k) < len(m):
        raise ValueError(
            f"La clave debe tener al menos {len(m)} caracteres "
            f"(tiene {len(k)}, mensaje tiene {len(m)})."
        )
    cifrado = []
    for i, c in enumerate(m):
        idx = (CHAR_TO_IDX[c] + CHAR_TO_IDX[k[i]]) % N
        cifrado.append(ALFABETO[idx])
    return "".join(cifrado)

def otp_desencriptar(cifrado: str, clave: str) -> str:
    c = preprocesar(cifrado)
    k = preprocesar(clave)
    if len(k) < len(c):
        raise ValueError(
            f"La clave debe tener al menos {len(c)} caracteres "
            f"(tiene {len(k)}, cifrado tiene {len(c)})."
        )
    mensaje = []
    for i, ch in enumerate(c):
        idx = (CHAR_TO_IDX[ch] - CHAR_TO_IDX[k[i]]) % N
        mensaje.append(ALFABETO[idx])
    return "".join(mensaje)

# ──────────────────────────────────────────────
#  REJILLA CRIPTOGRÁFICA
# ──────────────────────────────────────────────
def rejilla_desencriptar(tabla_cifrada: list[list[str]], rejilla: list[list[bool]]) -> str:
    """
    tabla_cifrada: lista de listas con caracteres del alfabeto.
    rejilla: lista de listas de bool indicando qué celdas son 'agujeros'.
    Lee en orden: 0° → 90° → 180° → 270°.
    """
    rows = len(tabla_cifrada)
    cols = len(tabla_cifrada[0]) if rows > 0 else 0
    resultado = []

    def rotar_rejilla(rej, r, c):
        """Rota la rejilla 90° en sentido horario."""
        nueva = [[False]*r for _ in range(c)]
        for i in range(r):
            for j in range(c):
                nueva[j][r - 1 - i] = rej[i][j]
        return nueva

    rej_actual = [row[:] for row in rejilla]
    for _ in range(4):
        for i in range(rows):
            for j in range(cols):
                if rej_actual[i][j]:
                    resultado.append(tabla_cifrada[i][j])
        rej_actual = rotar_rejilla(rej_actual, rows, cols)

    return "".join(resultado)


# ══════════════════════════════════════════════
#  INTERFAZ GRÁFICA
# ══════════════════════════════════════════════
COLORS = {
    "bg":         "#0D0D0D",
    "surface":    "#141414",
    "surface2":   "#1C1C1C",
    "border":     "#2A2A2A",
    "accent":     "#C8FF00",   # verde lima vibrante
    "accent2":    "#FF6B35",   # naranja
    "text":       "#F0F0F0",
    "muted":      "#888888",
    "error":      "#FF4444",
    "success":    "#44FF88",
}

FONT_MONO  = ("Courier New", 11)
FONT_LABEL = ("Courier New", 10, "bold")
FONT_TITLE = ("Courier New", 18, "bold")
FONT_TAB   = ("Courier New", 11, "bold")

class CriptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CriptoLab — OTP & Rejillas")
        self.configure(bg=COLORS["bg"])
        self.geometry("900x760")
        self.resizable(True, True)
        self._build_ui()

    # ── cabecera ──────────────────────────────
    def _build_ui(self):
        hdr = tk.Frame(self, bg=COLORS["bg"], pady=18)
        hdr.pack(fill="x", padx=32)

        tk.Label(hdr, text="◈ CRIPTOLAB", font=FONT_TITLE,
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(side="left")
        tk.Label(hdr, text="  One Time Pad · Rejillas Criptográficas",
                 font=("Courier New", 11), fg=COLORS["muted"],
                 bg=COLORS["bg"]).pack(side="left", padx=12, pady=4)

        sep = tk.Frame(self, bg=COLORS["accent"], height=1)
        sep.pack(fill="x", padx=32)

        # Notebook
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",
                        background=COLORS["bg"],
                        borderwidth=0,
                        tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=COLORS["surface2"],
                        foreground=COLORS["muted"],
                        font=FONT_TAB,
                        padding=[20, 8],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["surface"])],
                  foreground=[("selected", COLORS["accent"])])

        nb = ttk.Notebook(self, style="TNotebook")
        nb.pack(fill="both", expand=True, padx=32, pady=16)

        tab_otp    = tk.Frame(nb, bg=COLORS["bg"])
        tab_rejilla = tk.Frame(nb, bg=COLORS["bg"])
        tab_alfa   = tk.Frame(nb, bg=COLORS["bg"])

        nb.add(tab_otp,     text=" OTP — Encriptar/Desencriptar ")
        nb.add(tab_rejilla, text=" Rejilla — Desencriptar ")
        nb.add(tab_alfa,    text=" Alfabeto ")

        self._build_otp_tab(tab_otp)
        self._build_rejilla_tab(tab_rejilla)
        self._build_alfa_tab(tab_alfa)

    # ── utilidades de widget ──────────────────
    def _label(self, parent, text, color=None):
        return tk.Label(parent, text=text,
                        font=FONT_LABEL,
                        fg=color or COLORS["muted"],
                        bg=COLORS["bg"],
                        anchor="w")

    def _entry(self, parent, **kw):
        e = tk.Entry(parent,
                     font=FONT_MONO,
                     bg=COLORS["surface2"],
                     fg=COLORS["text"],
                     insertbackground=COLORS["accent"],
                     relief="flat",
                     bd=0,
                     highlightthickness=1,
                     highlightbackground=COLORS["border"],
                     highlightcolor=COLORS["accent"],
                     **kw)
        return e

    def _text(self, parent, h=5, **kw):
        t = scrolledtext.ScrolledText(parent,
                                      height=h,
                                      font=FONT_MONO,
                                      bg=COLORS["surface2"],
                                      fg=COLORS["text"],
                                      insertbackground=COLORS["accent"],
                                      relief="flat",
                                      bd=0,
                                      highlightthickness=1,
                                      highlightbackground=COLORS["border"],
                                      highlightcolor=COLORS["accent"],
                                      wrap="word",
                                      **kw)
        return t

    def _btn(self, parent, text, cmd, color=None):
        c = color or COLORS["accent"]
        b = tk.Button(parent, text=text, command=cmd,
                      font=FONT_LABEL,
                      fg=COLORS["bg"],
                      bg=c,
                      activebackground=COLORS["text"],
                      activeforeground=COLORS["bg"],
                      relief="flat",
                      bd=0,
                      padx=18, pady=8,
                      cursor="hand2")
        return b

    def _result_box(self, parent):
        frame = tk.Frame(parent, bg=COLORS["surface"],
                         highlightthickness=1,
                         highlightbackground=COLORS["accent"])
        frame.pack(fill="x", pady=(4, 0))
        lbl = tk.Label(frame, text="", font=FONT_MONO,
                       fg=COLORS["success"],
                       bg=COLORS["surface"],
                       wraplength=780,
                       justify="left",
                       padx=12, pady=10,
                       anchor="w")
        lbl.pack(fill="x")
        return lbl

    def _set_result(self, lbl, text, error=False):
        lbl.config(text=text,
                   fg=COLORS["error"] if error else COLORS["success"])

    # ══════════════════════════════════════════
    #  TAB ONE TIME PAD
    # ══════════════════════════════════════════
    def _build_otp_tab(self, parent):
        pad = dict(padx=4, pady=6)

        # ── Encriptar ────────────────────────
        enc_frame = tk.LabelFrame(parent,
                                  text="  ENCRIPTAR  ",
                                  font=FONT_LABEL,
                                  fg=COLORS["accent"],
                                  bg=COLORS["bg"],
                                  bd=0,
                                  highlightthickness=1,
                                  highlightbackground=COLORS["border"],
                                  pady=10, padx=16)
        enc_frame.pack(fill="x", pady=(8, 0))

        self._label(enc_frame, "Mensaje en claro:").pack(anchor="w", **pad)
        self.otp_msg = self._text(enc_frame, h=3)
        self.otp_msg.pack(fill="x", **pad)

        self._label(enc_frame, "Clave (≥ longitud del mensaje):").pack(anchor="w", **pad)
        self.otp_key_enc = self._text(enc_frame, h=3)
        self.otp_key_enc.pack(fill="x", **pad)

        btn_row = tk.Frame(enc_frame, bg=COLORS["bg"])
        btn_row.pack(fill="x", **pad)
        self._btn(btn_row, "◈  ENCRIPTAR", self._otp_encrypt).pack(side="left")
        self._btn(btn_row, "⟳  Limpiar", self._clear_otp_enc,
                  color=COLORS["surface2"]).pack(side="left", padx=8)

        self._label(enc_frame, "Resultado cifrado:").pack(anchor="w", **pad)
        self.otp_enc_result = self._result_box(enc_frame)

        # ── Desencriptar ─────────────────────
        dec_frame = tk.LabelFrame(parent,
                                  text="  DESENCRIPTAR  ",
                                  font=FONT_LABEL,
                                  fg=COLORS["accent2"],
                                  bg=COLORS["bg"],
                                  bd=0,
                                  highlightthickness=1,
                                  highlightbackground=COLORS["border"],
                                  pady=10, padx=16)
        dec_frame.pack(fill="x", pady=(14, 0))

        self._label(dec_frame, "Texto cifrado:").pack(anchor="w", **pad)
        self.otp_cipher = self._text(dec_frame, h=3)
        self.otp_cipher.pack(fill="x", **pad)

        self._label(dec_frame, "Clave:").pack(anchor="w", **pad)
        self.otp_key_dec = self._text(dec_frame, h=3)
        self.otp_key_dec.pack(fill="x", **pad)

        btn_row2 = tk.Frame(dec_frame, bg=COLORS["bg"])
        btn_row2.pack(fill="x", **pad)
        self._btn(btn_row2, "◈  DESENCRIPTAR",
                  self._otp_decrypt, color=COLORS["accent2"]).pack(side="left")
        self._btn(btn_row2, "⟳  Limpiar", self._clear_otp_dec,
                  color=COLORS["surface2"]).pack(side="left", padx=8)

        self._label(dec_frame, "Resultado:").pack(anchor="w", **pad)
        self.otp_dec_result = self._result_box(dec_frame)

    def _otp_encrypt(self):
        try:
            msg  = self.otp_msg.get("1.0", "end-1c")
            key  = self.otp_key_enc.get("1.0", "end-1c")
            res  = otp_encriptar(msg, key)
            self._set_result(self.otp_enc_result, res)
        except Exception as e:
            self._set_result(self.otp_enc_result, f"ERROR: {e}", error=True)

    def _otp_decrypt(self):
        try:
            cif  = self.otp_cipher.get("1.0", "end-1c")
            key  = self.otp_key_dec.get("1.0", "end-1c")
            res  = otp_desencriptar(cif, key)
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
    #  TAB REJILLA
    # ══════════════════════════════════════════
    def _build_rejilla_tab(self, parent):
        pad = dict(padx=4, pady=5)

        info = tk.Label(parent,
                        text=(
                            "Ingresa el tamaño de la rejilla, completa la tabla con el texto cifrado "
                            "y marca los agujeros (celdas transparentes) con ✓."
                        ),
                        font=("Courier New", 10),
                        fg=COLORS["muted"],
                        bg=COLORS["bg"],
                        wraplength=820,
                        justify="left")
        info.pack(anchor="w", padx=4, pady=(8, 2))

        # dimensiones
        dim_frame = tk.Frame(parent, bg=COLORS["bg"])
        dim_frame.pack(anchor="w", **pad)

        self._label(dim_frame, "Filas:").pack(side="left")
        self.rej_rows = tk.Spinbox(dim_frame, from_=1, to=12, width=4,
                                   font=FONT_MONO,
                                   bg=COLORS["surface2"], fg=COLORS["text"],
                                   buttonbackground=COLORS["surface"],
                                   relief="flat")
        self.rej_rows.pack(side="left", padx=4)
        self.rej_rows.delete(0, "end"); self.rej_rows.insert(0, "4")

        self._label(dim_frame, "  Columnas:").pack(side="left")
        self.rej_cols = tk.Spinbox(dim_frame, from_=1, to=12, width=4,
                                   font=FONT_MONO,
                                   bg=COLORS["surface2"], fg=COLORS["text"],
                                   buttonbackground=COLORS["surface"],
                                   relief="flat")
        self.rej_cols.pack(side="left", padx=4)
        self.rej_cols.delete(0, "end"); self.rej_cols.insert(0, "4")

        self._btn(dim_frame, "  Generar tabla  ",
                  self._generar_rejilla).pack(side="left", padx=12)

        # contenedor dinámico
        self.rej_container = tk.Frame(parent, bg=COLORS["bg"])
        self.rej_container.pack(fill="both", expand=False, **pad)

        self.rej_cells   = []   # Entry widgets
        self.rej_checks  = []   # BooleanVar
        self.rej_ckbtn   = []   # Checkbutton widgets

        # botones de acción
        act_frame = tk.Frame(parent, bg=COLORS["bg"])
        act_frame.pack(anchor="w", **pad)
        self._btn(act_frame, "◈  DESENCRIPTAR REJILLA",
                  self._rejilla_decrypt, color=COLORS["accent2"]).pack(side="left")
        self._btn(act_frame, "⟳  Limpiar todo",
                  self._clear_rejilla,
                  color=COLORS["surface2"]).pack(side="left", padx=8)

        self._label(parent, "Mensaje descifrado:").pack(anchor="w", **pad)
        self.rej_result = self._result_box(parent)

        # generar tabla inicial 4x4
        self._generar_rejilla()

    def _generar_rejilla(self):
        try:
            rows = int(self.rej_rows.get())
            cols = int(self.rej_cols.get())
            if rows < 1 or cols < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Filas y columnas deben ser enteros positivos.")
            return

        for w in self.rej_container.winfo_children():
            w.destroy()
        self.rej_cells  = []
        self.rej_checks = []
        self.rej_ckbtn  = []

        CELL_W = 5
        hdr = tk.Frame(self.rej_container, bg=COLORS["bg"])
        hdr.pack(anchor="w")
        tk.Label(hdr, text="   Celda (char)    Agujero?",
                 font=("Courier New", 9), fg=COLORS["muted"],
                 bg=COLORS["bg"]).pack(side="left")

        grid_frame = tk.Frame(self.rej_container, bg=COLORS["bg"])
        grid_frame.pack(anchor="w")

        for i in range(rows):
            row_cells   = []
            row_checks  = []
            row_ckbtns  = []
            for j in range(cols):
                cell_frame = tk.Frame(grid_frame, bg=COLORS["bg"], padx=2, pady=2)
                cell_frame.grid(row=i, column=j, padx=3, pady=3)

                e = tk.Entry(cell_frame, width=CELL_W,
                             font=FONT_MONO,
                             bg=COLORS["surface2"],
                             fg=COLORS["text"],
                             insertbackground=COLORS["accent"],
                             relief="flat",
                             bd=0,
                             highlightthickness=1,
                             highlightbackground=COLORS["border"],
                             highlightcolor=COLORS["accent"],
                             justify="center")
                e.pack()

                var = tk.BooleanVar(value=False)
                cb = tk.Checkbutton(cell_frame,
                                    variable=var,
                                    text="✓",
                                    font=("Courier New", 9),
                                    fg=COLORS["accent"],
                                    bg=COLORS["bg"],
                                    selectcolor=COLORS["surface2"],
                                    activebackground=COLORS["bg"],
                                    activeforeground=COLORS["accent"],
                                    relief="flat",
                                    bd=0)
                cb.pack()

                row_cells.append(e)
                row_checks.append(var)
                row_ckbtns.append(cb)

            self.rej_cells.append(row_cells)
            self.rej_checks.append(row_checks)
            self.rej_ckbtn.append(row_ckbtns)

    def _rejilla_decrypt(self):
        try:
            rows = len(self.rej_cells)
            cols = len(self.rej_cells[0]) if rows > 0 else 0

            tabla = []
            rejilla = []
            for i in range(rows):
                fila_t = []
                fila_r = []
                for j in range(cols):
                    raw = self.rej_cells[i][j].get().strip()
                    # preprocesar el carácter
                    if len(raw) != 1:
                        raise ValueError(
                            f"Celda [{i+1},{j+1}] debe tener exactamente 1 carácter (tiene '{raw}')."
                        )
                    c = SUSTITUCIONES.get(raw, raw).upper()
                    if c not in CHAR_TO_IDX:
                        raise ValueError(
                            f"Carácter no válido en celda [{i+1},{j+1}]: '{raw}'"
                        )
                    fila_t.append(c)
                    fila_r.append(self.rej_checks[i][j].get())
                tabla.append(fila_t)
                rejilla.append(fila_r)

            resultado = rejilla_desencriptar(tabla, rejilla)
            self._set_result(self.rej_result, resultado or "(vacío — sin agujeros marcados)")
        except Exception as e:
            self._set_result(self.rej_result, f"ERROR: {e}", error=True)

    def _clear_rejilla(self):
        for i, row in enumerate(self.rej_cells):
            for j, e in enumerate(row):
                e.delete(0, "end")
                self.rej_checks[i][j].set(False)
        self._set_result(self.rej_result, "")

    # ══════════════════════════════════════════
    #  TAB ALFABETO
    # ══════════════════════════════════════════
    def _build_alfa_tab(self, parent):
        tk.Label(parent,
                 text="Alfabeto estándar — 38 caracteres",
                 font=FONT_LABEL,
                 fg=COLORS["accent"],
                 bg=COLORS["bg"]).pack(anchor="w", padx=4, pady=(12, 4))

        table_frame = tk.Frame(parent, bg=COLORS["bg"])
        table_frame.pack(anchor="w", padx=4)

        cols_per_row = 10
        for idx, char in enumerate(ALFABETO):
            r, c = divmod(idx, cols_per_row)
            display = "SP" if char == " " else char
            cell = tk.Frame(table_frame, bg=COLORS["surface2"],
                            highlightthickness=1,
                            highlightbackground=COLORS["border"],
                            padx=6, pady=6)
            cell.grid(row=r*2,   column=c, padx=3, pady=(3, 0))
            tk.Label(cell, text=display, font=("Courier New", 12, "bold"),
                     fg=COLORS["accent"], bg=COLORS["surface2"]).pack()

            idx_cell = tk.Frame(table_frame, bg=COLORS["bg"])
            idx_cell.grid(row=r*2+1, column=c, pady=(0, 3))
            tk.Label(idx_cell, text=str(idx), font=("Courier New", 9),
                     fg=COLORS["muted"], bg=COLORS["bg"]).pack()

        note_frame = tk.Frame(parent, bg=COLORS["surface"],
                              highlightthickness=1,
                              highlightbackground=COLORS["border"],
                              padx=16, pady=12)
        note_frame.pack(fill="x", padx=4, pady=20)

        notas = [
            "◈  Total: 38 caracteres (índices 0–37)",
            "◈  A–Z incluye Ñ en posición 14 (…N=13, Ñ=14, O=15…)",
            "◈  Espacio en posición 27",
            "◈  Dígitos 0–9 en posiciones 28–37",
            "◈  Pre-procesamiento: MAYÚSCULAS, tildes→sin tilde, Ñ válida",
            "◈  Caracteres fuera del alfabeto generan error",
        ]
        for n in notas:
            tk.Label(note_frame, text=n,
                     font=("Courier New", 10),
                     fg=COLORS["muted"],
                     bg=COLORS["surface"],
                     anchor="w").pack(anchor="w")


if __name__ == "__main__":
    app = CriptoApp()
    app.mainloop()