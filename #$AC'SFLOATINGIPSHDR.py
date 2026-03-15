import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct

# ------------------------------------------------------------
# BPS format helpers (variable‑length integers)
# ------------------------------------------------------------
def decode_bps_int(data, offset):
    """Decode a BPS variable‑length integer from data starting at offset.
       Returns (value, new_offset). Raises ValueError if data ends prematurely."""
    value = 0
    shift = 1
    while True:
        if offset >= len(data):
            raise ValueError("BPS file truncated in variable-length integer")
        b = data[offset]
        offset += 1
        value += (b & 0x7F) * shift
        if b & 0x80:
            break
        shift <<= 7
        value += shift
    return value, offset

def encode_bps_int(value):
    """Encode an integer into BPS variable‑length format (returns bytes)."""
    if value == 0:
        return b'\x80'
    result = bytearray()
    while value:
        x = value & 0x7F
        value >>= 7
        if value == 0:
            x |= 0x80
        result.append(x)
    return bytes(result)

# ------------------------------------------------------------
# IPS patching functions
# ------------------------------------------------------------
def apply_ips(patch_data, target_data):
    """Apply an IPS patch (bytes) to target_data (bytearray). Returns patched data."""
    if patch_data[:5] != b'PATCH' or patch_data[-3:] != b'EOF':
        raise ValueError("Invalid IPS file: missing header or EOF marker")

    pos = 5
    while pos < len(patch_data) - 3:
        offset = struct.unpack('>I', b'\x00' + patch_data[pos:pos+3])[0]
        pos += 3
        size = struct.unpack('>H', patch_data[pos:pos+2])[0]
        pos += 2

        if size == 0:  # RLE record
            rle_len = struct.unpack('>H', patch_data[pos:pos+2])[0]
            pos += 2
            value = patch_data[pos]
            pos += 1
            for i in range(rle_len):
                if offset + i < len(target_data):
                    target_data[offset + i] = value
                else:
                    target_data.append(value)
        else:  # normal record
            data = patch_data[pos:pos+size]
            pos += size
            for i, b in enumerate(data):
                if offset + i < len(target_data):
                    target_data[offset + i] = b
                else:
                    target_data.append(b)
    return target_data

def create_ips(orig_data, mod_data):
    """Create an IPS patch (bytes) from original and modified data."""
    patch = bytearray(b'PATCH')
    i = 0
    max_len = max(len(orig_data), len(mod_data))

    while i < max_len:
        # find next difference
        if i < len(orig_data) and i < len(mod_data) and orig_data[i] == mod_data[i]:
            i += 1
            continue

        start = i
        run_len = 0
        while i < max_len and run_len < 0xFFFF:
            if i < len(orig_data) and i < len(mod_data) and orig_data[i] == mod_data[i]:
                break
            run_len += 1
            i += 1

        # check for RLE (all bytes same in modified)
        if start + run_len <= len(mod_data):
            first = mod_data[start]
            rle = all(mod_data[j] == first for j in range(start, start + run_len))
        else:
            rle = False

        if rle and run_len > 0:
            # RLE record
            patch.extend(struct.pack('>I', start)[1:4])   # offset
            patch.extend(b'\x00\x00')                     # size = 0 for RLE
            patch.extend(struct.pack('>H', run_len))      # RLE length
            patch.append(first)                            # value
        else:
            # normal record
            patch.extend(struct.pack('>I', start)[1:4])   # offset
            patch.extend(struct.pack('>H', run_len))      # size
            for j in range(start, start + run_len):
                patch.append(mod_data[j] if j < len(mod_data) else 0)
    patch.extend(b'EOF')
    return bytes(patch)

# ------------------------------------------------------------
# BPS patching functions
# ------------------------------------------------------------
def apply_bps(patch_data, target_data):
    """Apply a BPS patch to target_data (bytearray). Returns patched data."""
    if patch_data[:4] != b'BPS1':
        raise ValueError("Invalid BPS file: missing header")

    pos = 4
    source_size, pos = decode_bps_int(patch_data, pos)
    target_size, pos = decode_bps_int(patch_data, pos)
    metadata_size, pos = decode_bps_int(patch_data, pos)

    # skip metadata
    pos += metadata_size
    if pos > len(patch_data):
        raise ValueError("BPS file truncated in metadata")

    source_data = target_data
    output = bytearray(target_size)

    # BPS spec: SourceRead uses outputOffset implicitly, no separate tracker needed.
    # SourceCopy and TargetCopy each have their own relative offset.
    target_offset = 0
    source_relative_offset = 0
    target_relative_offset = 0

    # BPS patches end with a 12-byte footer (checksums)
    patch_length = len(patch_data) - 12
    if patch_length < pos:
        patch_length = len(patch_data)  # Fallback if missing footer

    while pos < patch_length and target_offset < target_size:
        cmd, pos = decode_bps_int(patch_data, pos)
        length = (cmd >> 2) + 1
        mode = cmd & 3

        if mode == 0:          # SourceRead — copy from source at current OUTPUT position
            end = target_offset + length
            if end <= len(source_data):
                output[target_offset:end] = source_data[target_offset:end]
            else:
                for i in range(length):
                    idx = target_offset + i
                    output[idx] = source_data[idx] if idx < len(source_data) else 0
            target_offset += length

        elif mode == 1:        # TargetRead
            if pos + length > len(patch_data):
                raise ValueError("BPS file truncated in TargetRead block")
            output[target_offset:target_offset+length] = patch_data[pos:pos+length]
            pos += length
            target_offset += length

        elif mode == 2:        # SourceCopy
            data, pos = decode_bps_int(patch_data, pos)
            negative = (data & 1)
            data >>= 1
            if negative:
                source_relative_offset -= data
            else:
                source_relative_offset += data

            end_src = source_relative_offset + length
            if source_relative_offset >= 0 and end_src <= len(source_data):
                output[target_offset:target_offset+length] = source_data[source_relative_offset:end_src]
            else:
                for i in range(length):
                    src_idx = source_relative_offset + i
                    output[target_offset+i] = source_data[src_idx] if 0 <= src_idx < len(source_data) else 0
            source_relative_offset += length
            target_offset += length

        elif mode == 3:        # TargetCopy
            data, pos = decode_bps_int(patch_data, pos)
            negative = (data & 1)
            data >>= 1
            if negative:
                target_relative_offset -= data
            else:
                target_relative_offset += data

            # Must copy byte-by-byte because TargetCopy can overlap its own output (RLE trick)
            for i in range(length):
                if target_relative_offset < 0 or target_relative_offset >= target_size:
                    raise ValueError(f"TargetCopy out of bounds: {target_relative_offset}")
                output[target_offset] = output[target_relative_offset]
                target_relative_offset += 1
                target_offset += 1

        else:
            raise ValueError(f"Unknown BPS mode {mode}")

    return output

def create_bps(orig_data, mod_data):
    """Create a simple BPS patch (no move detection, just SourceRead+TargetRead)."""
    source_size = len(orig_data)
    target_size = len(mod_data)
    header = b'BPS1'
    header += encode_bps_int(source_size)
    header += encode_bps_int(target_size)
    header += b'\x80'  # metadata size = 0

    patch = bytearray(header)
    # simple diff: we emit SourceRead for matching blocks, TargetRead for changed blocks
    i = 0
    max_len = max(source_size, target_size)
    while i < max_len:
        # find matching run
        match_start = i
        while i < max_len and i < source_size and i < target_size and orig_data[i] == mod_data[i]:
            i += 1
        match_len = i - match_start
        if match_len:
            # SourceRead action
            while match_len > 0:
                chunk = min(match_len, 0x1FFFFFF)  # limit per action
                cmd = ((chunk - 1) << 2) | 0  # mode 0
                patch.extend(encode_bps_int(cmd))
                match_len -= chunk
                # no extra data for SourceRead

        # find changed run
        change_start = i
        while i < max_len and (i >= source_size or i >= target_size or orig_data[i] != mod_data[i]):
            i += 1
        change_len = i - change_start
        if change_len:
            while change_len > 0:
                chunk = min(change_len, 0x1FFFFFF)
                cmd = ((chunk - 1) << 2) | 1  # mode 1 (TargetRead)
                patch.extend(encode_bps_int(cmd))
                # write the new bytes
                for j in range(change_start, change_start + chunk):
                    patch.append(mod_data[j] if j < target_size else 0)
                change_len -= chunk
                change_start += chunk

    # Empty footer checksums for simple creator
    patch.extend(b'\x00' * 12)
    return bytes(patch)

# ------------------------------------------------------------
# Main GUI Application
# ------------------------------------------------------------
class CatIPSApp:
    def __init__(self, root):
        self.root = root
        # ----- Renamed here -----
        self.root.title("AC'S Floating BPS 1.X")
        self.root.geometry("550x350")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use('clam')

        notebook = ttk.Notebook(root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.apply_frame = ttk.Frame(notebook)
        notebook.add(self.apply_frame, text="Apply Patch")
        self.setup_apply_tab()

        self.create_frame = ttk.Frame(notebook)
        notebook.add(self.create_frame, text="Create Patch")
        self.setup_create_tab()

        self.status = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_apply_tab(self):
        ttk.Label(self.apply_frame, text="Patch File (IPS/BPS):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.apply_patch_path = tk.StringVar()
        ttk.Entry(self.apply_frame, textvariable=self.apply_patch_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(self.apply_frame, text="Browse", command=self.browse_apply_patch).grid(row=0, column=2)

        ttk.Label(self.apply_frame, text="Target File (ROM):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.apply_target_path = tk.StringVar()
        ttk.Entry(self.apply_frame, textvariable=self.apply_target_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(self.apply_frame, text="Browse", command=self.browse_apply_target).grid(row=1, column=2)

        self.apply_btn = ttk.Button(self.apply_frame, text="Apply Patch", command=self.apply_patch)
        self.apply_btn.grid(row=2, column=1, pady=20)

        self.apply_info = ttk.Label(self.apply_frame, text="", foreground="blue")
        self.apply_info.grid(row=3, column=0, columnspan=3)

        self.apply_frame.columnconfigure(1, weight=1)

    def setup_create_tab(self):
        ttk.Label(self.create_frame, text="Original File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.create_original_path = tk.StringVar()
        ttk.Entry(self.create_frame, textvariable=self.create_original_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(self.create_frame, text="Browse", command=self.browse_create_original).grid(row=0, column=2)

        ttk.Label(self.create_frame, text="Modified File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.create_modified_path = tk.StringVar()
        ttk.Entry(self.create_frame, textvariable=self.create_modified_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(self.create_frame, text="Browse", command=self.browse_create_modified).grid(row=1, column=2)

        ttk.Label(self.create_frame, text="Output Format:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.create_format = tk.StringVar(value="IPS")
        format_combo = ttk.Combobox(self.create_frame, textvariable=self.create_format, values=["IPS", "BPS"], state="readonly", width=10)
        format_combo.grid(row=2, column=1, sticky=tk.W, padx=5)

        ttk.Label(self.create_frame, text="Output Patch:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.create_output_path = tk.StringVar()
        ttk.Entry(self.create_frame, textvariable=self.create_output_path, width=50).grid(row=3, column=1, padx=5)
        ttk.Button(self.create_frame, text="Browse", command=self.browse_create_output).grid(row=3, column=2)

        self.create_btn = ttk.Button(self.create_frame, text="Create Patch", command=self.create_patch)
        self.create_btn.grid(row=4, column=1, pady=20)

        self.create_info = ttk.Label(self.create_frame, text="", foreground="blue")
        self.create_info.grid(row=5, column=0, columnspan=3)

        self.create_frame.columnconfigure(1, weight=1)

    # ---------- Browse methods ----------
    def browse_apply_patch(self):
        filename = filedialog.askopenfilename(title="Select patch file", filetypes=[("Patch files", "*.ips *.bps"), ("IPS files", "*.ips"), ("BPS files", "*.bps"), ("All files", "*.*")])
        if filename:
            self.apply_patch_path.set(filename)

    def browse_apply_target(self):
        filename = filedialog.askopenfilename(title="Select target file to patch")
        if filename:
            self.apply_target_path.set(filename)

    def browse_create_original(self):
        filename = filedialog.askopenfilename(title="Select original file")
        if filename:
            self.create_original_path.set(filename)

    def browse_create_modified(self):
        filename = filedialog.askopenfilename(title="Select modified file")
        if filename:
            self.create_modified_path.set(filename)

    def browse_create_output(self):
        ext = ".ips" if self.create_format.get() == "IPS" else ".bps"
        filename = filedialog.asksaveasfilename(title="Save patch as", defaultextension=ext, filetypes=[(f"{self.create_format.get()} files", f"*{ext}"), ("All files", "*.*")])
        if filename:
            self.create_output_path.set(filename)

    # ---------- Apply patch ----------
    def apply_patch(self):
        patch_file = self.apply_patch_path.get()
        target_file = self.apply_target_path.get()

        if not patch_file or not target_file:
            messagebox.showerror("Error", "Please select both patch and target files.")
            return

        if not os.path.exists(patch_file):
            messagebox.showerror("Error", "Patch file does not exist.")
            return

        if not os.path.exists(target_file):
            messagebox.showerror("Error", "Target file does not exist.")
            return

        try:
            with open(patch_file, 'rb') as f:
                patch_data = f.read()

            with open(target_file, 'rb') as f:
                target_data = bytearray(f.read())

            # IMPORTANT: Backup original before modifying memory bytes!
            backup = target_file + ".bak"
            with open(backup, 'wb') as f:
                f.write(target_data)

            # Detect format from header
            if patch_data[:5] == b'PATCH':
                patched = apply_ips(patch_data, target_data)
                fmt = "IPS"
            elif patch_data[:4] == b'BPS1':
                patched = apply_bps(patch_data, target_data)
                fmt = "BPS"
            else:
                messagebox.showerror("Error", "Unknown patch format (not IPS or BPS).")
                return

            # Write patched data
            with open(target_file, 'wb') as f:
                f.write(patched)

            self.apply_info.config(text=f"{fmt} patch applied. Backup saved as {os.path.basename(backup)}", foreground="green")
            self.status.config(text="Patch applied")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply patch:\n{str(e)}")
            self.apply_info.config(text="", foreground="red")

    # ---------- Create patch ----------
    def create_patch(self):
        original = self.create_original_path.get()
        modified = self.create_modified_path.get()
        output = self.create_output_path.get()
        fmt = self.create_format.get()

        if not original or not modified or not output:
            messagebox.showerror("Error", "Please select original, modified, and output files.")
            return

        if not os.path.exists(original):
            messagebox.showerror("Error", "Original file does not exist.")
            return

        if not os.path.exists(modified):
            messagebox.showerror("Error", "Modified file does not exist.")
            return

        try:
            with open(original, 'rb') as f:
                orig_data = f.read()
            with open(modified, 'rb') as f:
                mod_data = f.read()

            if fmt == "IPS":
                patch_data = create_ips(orig_data, mod_data)
            else:  # BPS
                patch_data = create_bps(orig_data, mod_data)

            with open(output, 'wb') as f:
                f.write(patch_data)

            self.create_info.config(text=f"{fmt} patch created successfully: {os.path.basename(output)}", foreground="green")
            self.status.config(text="Patch created")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create patch:\n{str(e)}")
            self.create_info.config(text="", foreground="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = CatIPSApp(root)
    root.mainloop()