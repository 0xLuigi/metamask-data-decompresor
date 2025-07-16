import sys
import os
import struct
import binascii
from typing import Optional, Tuple, List
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import multiprocessing
import re
import json
import tkinter.font as tkFont
from multiprocessing import Pool
import time

# --- CRC32C Implementácia ---
crc32c_table = [
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f,
    0x35f1141c, 0x26a1e7e8, 0xd4ca64eb, 0x8ad958cf, 0x78b2dbcc,
    0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27,
    0x5e133c24, 0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
    0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384, 0x9a879fa0,
    0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc,
    0xbc267848, 0x4e4dfb4b, 0x20bd8ede, 0xd2d60ddd, 0xc186fe29,
    0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e,
    0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa, 0x30e349b1, 0xc288cab2,
    0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59,
    0xe4292d5a, 0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
    0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595, 0x417b1dbc,
    0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0,
    0x67dafa54, 0x95b17957, 0xcba24573, 0x39c9c670, 0x2a993584,
    0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc,
    0x64d4cecf, 0x77843d3b, 0x85efbe38, 0xdbfc821c, 0x2997011f,
    0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4,
    0x0f36e6f7, 0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
    0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789, 0xeb1fcbad,
    0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1,
    0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81,
    0xfc588982, 0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
    0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622, 0x38cc2a06,
    0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a,
    0x1e6dcdee, 0xec064eed, 0xc38d26c4, 0x31e6a5c7, 0x22b65633,
    0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914,
    0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0
]

def crc32c_lookup(index: int) -> int:
    return crc32c_table[index & 0xff]

def crc32c(current_crc: int, data: bytes) -> int:
    crc = current_crc
    for byte in data:
        tabval = crc32c_lookup(crc ^ byte)
        crc = tabval ^ (crc >> 8)
    return crc & 0xFFFFFFFF

def crc32c_init() -> int:
    return 0xffffffff

def crc32c_fini(crc: int, firefox_crc: bool = False) -> int:
    if not firefox_crc:
        crc ^= 0xffffffff
    crc = ((crc << 17) | (crc >> 15)) & 0xFFFFFFFF
    crc = (crc + 0xa282ead8) & 0xFFFFFFFF
    return crc

class SnappyDecompressor:
    """Trieda na dekompresiu Snappy formátu"""

    def __init__(self):
        self.debug = False
        self.ignore_offset_errors = False
        self.firefox_crc = True

    def read_varint(self, data: bytes, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        pos = offset

        while pos < len(data):
            byte = data[pos]
            result |= (byte & 0x7F) << shift
            pos += 1

            if (byte & 0x80) == 0:
                break

            shift += 7
            if shift >= 64:
                raise ValueError("Varint too long")

        return result, pos - offset

    def decompress_block(self, compressed_data: bytes, uncompressed_length: int) -> Tuple[bytes, int]:
        output = bytearray()
        pos = 0

        while pos < len(compressed_data) and len(output) < uncompressed_length:
            if pos >= len(compressed_data):
                break

            tag = compressed_data[pos]
            pos += 1

            if (tag & 0x03) == 0x00: # Literal
                literal_length = (tag >> 2) + 1
                if (tag >> 2) >= 60:
                    extra_bytes = (tag >> 2) - 59
                    literal_length = 0
                    for i in range(extra_bytes):
                        if pos >= len(compressed_data):
                            break
                        literal_length |= compressed_data[pos] << (i * 8)
                        pos += 1
                    literal_length += 1

                if pos + literal_length > len(compressed_data):
                    if self.ignore_offset_errors:
                        literal_length = len(compressed_data) - pos
                    else:
                        raise ValueError(f"Error: Not enough data for literal. Needed: {literal_length}, Available: {len(compressed_data) - pos}")

                if literal_length > 0:
                    output.extend(compressed_data[pos:pos + literal_length])
                    pos += literal_length

            elif (tag & 0x03) == 0x01: # Copy with 1-byte offset
                length = ((tag >> 2) & 0x07) + 4
                if pos >= len(compressed_data):
                    raise ValueError("Error: Not enough data for 1-byte copy offset.")
                offset = ((tag >> 5) << 8) | compressed_data[pos]
                pos += 1
                self._copy_bytes(output, offset, length)

            elif (tag & 0x03) == 0x02: # Copy with 2-byte offset
                length = (tag >> 2) + 1
                if pos + 1 >= len(compressed_data):
                    raise ValueError("Error: Not enough data for 2-byte copy offset.")
                offset = struct.unpack('<H', compressed_data[pos:pos+2])[0]
                pos += 2
                self._copy_bytes(output, offset, length)

            elif (tag & 0x03) == 0x03: # Copy with 4-byte offset
                length = (tag >> 2) + 1
                if pos + 3 >= len(compressed_data):
                    raise ValueError("Error: Not enough data for 4-byte copy offset.")
                offset = struct.unpack('<I', compressed_data[pos:pos+4])[0]
                pos += 4
                self._copy_bytes(output, offset, length)
        return bytes(output), pos

    def _copy_bytes(self, output: bytearray, offset: int, length: int):
        if offset == 0:
            for _ in range(length):
                output.append(0)
            return

        if offset > len(output):
            if self.ignore_offset_errors:
                for _ in range(length):
                    output.append(0)
                return
            else:
                raise ValueError(f"Offset {offset} is greater than output length {len(output)}")

        src_pos = len(output) - offset
        for i in range(length):
            if src_pos + i < len(output):
                output.append(output[src_pos + i])
            else:
                pattern_pos = src_pos + (i % offset)
                if pattern_pos < len(output):
                    output.append(output[pattern_pos])
                else:
                    output.append(0)

    def decompress(self, input_data: bytes) -> bytes:
        return self._decompress_raw_snappy(input_data)[0]

    def _decompress_raw_snappy(self, input_data: bytes) -> Tuple[bytes, int]:
        try:
            uncompressed_length, pos = self.read_varint(input_data, 0)
            if uncompressed_length > 1000000000:
                raise ValueError(f"Uncompressed length is too large ({uncompressed_length} bytes).")
            compressed_data = input_data[pos:]
            result, consumed_bytes = self.decompress_block(compressed_data, uncompressed_length)
            return result, pos + consumed_bytes
        except Exception as e:
            result, consumed_bytes = self.decompress_block(input_data, len(input_data) * 4)
            return result, consumed_bytes

# --- Funkcia na dekompresiu jedného chunk-u ---
def decompress_chunk(chunk_data: bytes, uncompressed_length: int) -> bytes:
    decompressor = SnappyDecompressor()
    result, _ = decompressor.decompress_block(chunk_data, uncompressed_length)
    return result

# --- Funkcia na rozdelenie dát na chunk-y ---
def split_into_chunks(input_data: bytes, current_pos: int, total_input_size: int) -> List[Tuple[bytes, int]]:
    chunks = []
    while current_pos < total_input_size:
        if current_pos >= total_input_size:
            break

        chunk_type = input_data[current_pos]
        current_pos += 1

        if chunk_type == 0x00:  # Compressed data chunk
            if current_pos + 7 > total_input_size:
                return chunks

            compressed_chunk_len_bytes = input_data[current_pos: current_pos + 3]
            compressed_chunk_len = int.from_bytes(compressed_chunk_len_bytes, 'little')
            current_pos += 3

            current_pos += 4  # Skip CRC

            actual_compressed_data_len = compressed_chunk_len - 4
            if current_pos + actual_compressed_data_len > total_input_size:
                return chunks

            compressed_data_block = input_data[current_pos: current_pos + actual_compressed_data_len]
            current_pos += actual_compressed_data_len

            decompressor = SnappyDecompressor()
            uncompressed_length, varint_bytes_consumed = decompressor.read_varint(compressed_data_block, 0)
            snappy_data_for_block = compressed_data_block[varint_bytes_consumed:]
            chunks.append((snappy_data_for_block, uncompressed_length))

        elif chunk_type >= 0x80 and chunk_type <= 0xfe:  # Skippable chunk
            if current_pos + 3 > total_input_size:
                return chunks
            chunk_len_bytes = input_data[current_pos: current_pos + 3]
            chunk_len = int.from_bytes(chunk_len_bytes, 'little')
            current_pos += 3

            if current_pos + chunk_len > total_input_size:
                return chunks
            current_pos += chunk_len
        else:
            return chunks

    return chunks

# --- Funkcia na vyhľadávanie údajov (MetaMask a ETH adresa) ---
def search_data_task(data: bytes, queue: multiprocessing.Queue, search_metamask: bool, eth_address_to_find: Optional[str], output_file: str):
    # Vykoná vyhľadávanie MetaMask a ETH adresy v dekomprimovaných údajoch a pošle výsledok
    try:
        queue.put(('status', "Searching for data"))
        current_decompressed_text = data.decode('utf-8', errors='ignore')
        metamask_found = False
        eth_address_found = False

        if search_metamask:
            queue.put(('progress', 90, 100, "Searching for MetaMask data"))
            metamask_pattern = re.compile(r'\{"data":"[^"]+","iv":"[^"]+","keyMetadata":\{.*?\},"salt":"[^"]+"\}', re.DOTALL)
            found_metamask_data = metamask_pattern.search(current_decompressed_text)
            queue.put(('progress', 95, 100, "Searching for MetaMask data"))
            if found_metamask_data:
                queue.put(('metamask_found', found_metamask_data.group(0)))
                metamask_found = True
            else:
                queue.put(('metamask_not_found',))

        if eth_address_to_find:
            queue.put(('progress', 95, 100, "Searching for ETH address"))
            if re.search(re.escape(eth_address_to_find), current_decompressed_text, re.IGNORECASE):
                queue.put(('eth_address_found', eth_address_to_find))
                eth_address_found = True
            else:
                queue.put(('eth_address_not_found', eth_address_to_find))

        queue.put(('progress', 100, 100, "Finalizing search"))
        # Poslať záverečnú správu o výsledku vyhľadávania
        if metamask_found or eth_address_found:
            queue.put(('status', f"Decompression 100% finished, saved to {os.path.basename(output_file)}"))
            queue.put(('success', len(data), output_file, True))
        else:
            queue.put(('status', f"Decompression 100% finished, saved to {os.path.basename(output_file)}"))
            queue.put(('success', len(data), output_file, False))

    except Exception as e:
        queue.put(('error', f"Error searching data: {e}"))
        queue.put(('status', f"Decompression 100% finished with error, saved to {os.path.basename(output_file)}"))
        queue.put(('progress', 100, 100, "Search failed"))

# --- Dekompresná funkcia pre samostatný proces ---
def decompress_process_task(input_file: str, output_file: str, queue: multiprocessing.Queue, search_metamask: bool, eth_address_to_find: Optional[str]):
    decompressor = SnappyDecompressor()
    try:
        # Načítanie vstupného súboru (0-10 %)
        queue.put(('status', "Reading input file"))
        queue.put(('progress', 0, 100, "Reading input file"))
        with open(input_file, 'rb') as f:
            input_data = f.read()
        queue.put(('progress', 10, 100, "Input file read"))

        total_input_size = len(input_data)
        current_pos = 0
        total_decompressed_size = 0

        if total_input_size >= 10 and input_data[0] == 0xff and input_data[1:10] == b'\x06\x00\x00sNaPpY':
            current_pos += 10

        # Rozdelenie dát na chunk-y (10-20 %)
        queue.put(('status', "Splitting into chunks"))
        queue.put(('progress', 10, 100, "Splitting into chunks"))
        chunks = split_into_chunks(input_data, current_pos, total_input_size)
        total_chunks = len(chunks)
        queue.put(('progress', 20, 100, "Chunks identified"))

        # Vytvorenie výstupného súboru (otvorí sa v append móde)
        with open(output_file, 'wb') as f:
            # Paralelná dekompresia chunk-ov (20-50 %)
            queue.put(('status', "Decompressing chunks"))
            with Pool(processes=multiprocessing.cpu_count()) as pool:
                results = []
                for i, (chunk_data, uncompressed_length) in enumerate(chunks):
                    results.append(pool.apply_async(decompress_chunk, args=(chunk_data, uncompressed_length)))
                    current_pos += len(chunk_data)
                    # Poslať progres po načítaní chunk-u (20-50 %)
                    progress = 20 + ((i + 1) / total_chunks) * 30
                    queue.put(('progress', progress, 100, f"Decompressing chunk {i+1}/{total_chunks}"))

                # Spracovanie a zápis každého chunk-u (50-90 %)
                for i, result in enumerate(results):
                    decompressed_data = result.get()
                    total_decompressed_size += len(decompressed_data)
                    # Zápis chunk-u do súboru
                    queue.put(('status', f"Writing chunk {i+1}/{total_chunks} to file"))
                    f.write(decompressed_data)
                    # Poslať progres po zápise chunk-u (50-90 %)
                    progress = 50 + ((i + 1) / total_chunks) * 40
                    queue.put(('progress', progress, 100, f"Writing chunk {i+1}/{total_chunks}"))

        queue.put(('progress', 90, 100, "Finalizing decompression"))

        if total_decompressed_size > 0:
            # Spustenie vyhľadávania v samostatnom procese (90-100 %)
            queue.put(('status', "Starting search, please wait"))
            with open(output_file, 'rb') as f:
                total_decompressed_data = f.read()
            search_process = multiprocessing.Process(
                target=search_data_task,
                args=(total_decompressed_data, queue, search_metamask, eth_address_to_find, output_file)
            )
            search_process.start()

        else:
            queue.put(('warning', "Decompressed data is empty."))
            queue.put(('status', f"Decompression 100% finished, saved to {os.path.basename(output_file)}"))
            queue.put(('progress', 100, 100, "Decompression completed"))
            queue.put(('success', 0, output_file, False))

    except Exception as e:
        queue.put(('error', f"An unexpected error occurred: {e}"))
        queue.put(('status', f"Decompression 100% finished with error, saved to {os.path.basename(output_file)}"))
        queue.put(('progress', 100, 100, "Decompression failed"))
    finally:
        queue.put(('done',))

class SnappyGUI:
    def __init__(self, master):
        self.master = master
        master.title("MetaMask Data Decompressor v1.3")
        master.geometry("650x600")

        # Nastavenie ikony okna
        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'images', 'icon.ico')
            self.master.iconbitmap(icon_path)
        except tk.TclError as e:
            print(f"Warning: Could not load icon file 'images/icon.ico': {e}")

        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.status_message = tk.StringVar()
        self.status_message.set("Ready")
        self.eth_address_to_search = tk.StringVar()
        self.found_eth_address_display = tk.StringVar()
        self.found_eth_address_display.set("No ETH address found yet.")

        self.decompression_process: Optional[multiprocessing.Process] = None
        self.message_queue = multiprocessing.Queue()

        self.normal_font = tkFont.Font(weight="normal")
        self.bold_font = tkFont.Font(weight="bold")

        # Vyhľadanie číslovaných súborov v adresári
        self.scan_for_numbered_files()

        # Rámec pre výber vstupného súboru
        input_frame = tk.LabelFrame(master, text="Input File")
        input_frame.pack(padx=10, pady=5, fill="x")
        tk.Entry(input_frame, textvariable=self.input_file_path).pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")
        tk.Button(input_frame, text="Browse...", command=self.browse_input_file).pack(side=tk.RIGHT, padx=5, pady=5)

        # Rámec pre výber výstupného súboru
        output_frame = tk.LabelFrame(master, text="Output File")
        output_frame.pack(padx=10, pady=5, fill="x")
        tk.Entry(output_frame, textvariable=self.output_file_path).pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")
        tk.Button(output_frame, text="Save As...", command=self.browse_output_file).pack(side=tk.RIGHT, padx=5, pady=5)

        # Rámec pre vyhľadávanie ETH adresy
        eth_search_frame = tk.LabelFrame(master, text="Search ETH Address (Optional)")
        eth_search_frame.pack(padx=10, pady=5, fill="x")
        self.eth_address_entry = tk.Entry(eth_search_frame, textvariable=self.eth_address_to_search)
        self.eth_address_entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")
        self.eth_address_status_label = tk.Label(eth_search_frame, textvariable=self.found_eth_address_display, fg="blue", font=self.normal_font)
        self.eth_address_status_label.pack(side=tk.RIGHT, padx=5, pady=5)

        # Kontextové menu pre pole ETH adresy
        self.eth_address_context_menu = tk.Menu(master, tearoff=0)
        self.eth_address_context_menu.add_command(label="Paste", command=self.paste_eth_address)
        self.eth_address_entry.bind("<Button-3>", self.show_eth_address_context_menu)

        # Rámec pre zobrazenie priebehu
        progress_frame = tk.LabelFrame(master, text="Progress")
        progress_frame.pack(padx=10, pady=5, fill="x")
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(padx=5, pady=5, fill="x")
        tk.Label(progress_frame, textvariable=self.status_message).pack(pady=2)

        # Rámec pre zobrazenie MetaMask údajov
        metamask_frame = tk.LabelFrame(master, text="MetaMask Vault Data")
        metamask_frame.pack(padx=10, pady=5, fill="x", expand=True)

        text_scroll_frame = tk.Frame(metamask_frame)
        text_scroll_frame.pack(side=tk.TOP, fill="both", expand=True, padx=5, pady=5)

        self.metamask_vault_text = tk.Text(text_scroll_frame, height=13, wrap="word", state=tk.DISABLED, bg="lightgray", fg="black")
        self.metamask_vault_text.pack(side=tk.LEFT, expand=True, fill="both")
        
        metamask_scrollbar = tk.Scrollbar(text_scroll_frame, command=self.metamask_vault_text.yview)
        metamask_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.metamask_vault_text.config(yscrollcommand=metamask_scrollbar.set)

        # Rámec pre tlačidlá
        button_frame = tk.Frame(master)
        button_frame.pack(padx=10, pady=(5, 10))

        self.decompress_button = tk.Button(button_frame, text="Decompress", command=self.start_decompression_process,
                                           bg="#4CAF50", fg="white", activebackground="#45a049", activeforeground="white")
        self.decompress_button.pack(side=tk.LEFT, padx=5)

        self.copy_metamask_button = tk.Button(button_frame, text="Copy MetaMask Data", command=self.copy_metamask_data, state=tk.DISABLED,
                                              bg="#008CBA", fg="white", activebackground="#007B9E", activeforeground="white")
        self.copy_metamask_button.pack(side=tk.LEFT, padx=5)

        # Kontextové menu pre MetaMask textové pole
        self.metamask_context_menu = tk.Menu(master, tearoff=0)
        self.metamask_context_menu.add_command(label="Copy", command=self.copy_metamask_data)
        self.metamask_vault_text.bind("<Button-3>", self.show_metamask_context_menu)

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        # Ukončenie procesu pri zatvorení okna, ak dekompresia stále prebieha
        if self.decompression_process and self.decompression_process.is_alive():
            if messagebox.askyesno("Terminate Decompression?", "Decompression is still running. Do you really want to close the application and cancel decompression?"):
                self.decompression_process.terminate()
                self.decompression_process.join()
                self.master.destroy()
        else:
            self.master.destroy()

    def scan_for_numbered_files(self):
        # Vyhľadá číslované súbory v aktuálnom adresári a automaticky nastaví vstupný a výstupný súbor
        script_dir = os.path.dirname(sys.argv[0])
        if not script_dir:
            script_dir = os.getcwd()

        numbered_file_pattern = re.compile(r"^\d+$")

        found_file = None
        for filename in os.listdir(script_dir):
            if numbered_file_pattern.match(filename):
                file_path = os.path.join(script_dir, filename)
                if os.path.isfile(file_path):
                    found_file = file_path
                    break

        if found_file:
            self.input_file_path.set(found_file)
            dir_name, base_name = os.path.split(found_file)
            name_without_ext = os.path.splitext(base_name)[0]
            self.output_file_path.set(os.path.join(dir_name, f"{name_without_ext}_decompressed.txt"))
            self.status_message.set(f"Automatically found file: {os.path.basename(found_file)}")
        else:
            self.status_message.set("Ready (no numbered files found).")

    def browse_input_file(self):
        # Otvorí dialóg na výber vstupného súboru
        file_path = filedialog.askopenfilename(
            title="Select Snappy File",
            filetypes=[("All Files", "*.*"), ("Snappy Files", "*.snappy")]
        )
        if file_path:
            self.input_file_path.set(file_path)
            dir_name, base_name = os.path.split(file_path)
            name_without_ext = os.path.splitext(base_name)[0]
            self.output_file_path.set(os.path.join(dir_name, f"{name_without_ext}_decompressed.txt"))
            self.status_message.set("Ready")
            self.progress_bar['value'] = 0
            self.clear_metamask_display()
            self.found_eth_address_display.set("No ETH address found yet.")
            self.eth_address_status_label.config(fg="blue", font=self.normal_font)

    def browse_output_file(self):
        # Otvorí dialóg na výber výstupného súboru
        file_path = filedialog.asksaveasfilename(
            title="Save Decompressed File As",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            self.output_file_path.set(file_path)

    def clear_metamask_display(self):
        # Vymaže obsah textového poľa MetaMask
        self.metamask_vault_text.config(state=tk.NORMAL)
        self.metamask_vault_text.delete(1.0, tk.END)
        self.metamask_vault_text.config(state=tk.DISABLED)
        self.copy_metamask_button.config(state=tk.DISABLED)

    def copy_metamask_data(self):
        # Skopíruje obsah MetaMask údajov do schránky
        try:
            content = self.metamask_vault_text.get(1.0, tk.END).strip()
            if content:
                self.master.clipboard_clear()
                self.master.clipboard_append(content)
                messagebox.showinfo("Copy", "MetaMask data copied to clipboard!")
            else:
                messagebox.showwarning("Copy", "No MetaMask data to copy.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy data: {e}")

    def show_metamask_context_menu(self, event):
        # Zobrazí kontextové menu pre MetaMask textové pole
        try:
            self.metamask_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.metamask_context_menu.grab_release()
    
    def show_eth_address_context_menu(self, event):
        # Zobrazí kontextové menu pre pole ETH adresy
        try:
            self.eth_address_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.eth_address_context_menu.grab_release()

    def paste_eth_address(self):
        # Vloží obsah schránky do poľa ETH adresy
        try:
            clipboard_content = self.master.clipboard_get()
            self.eth_address_to_search.set(clipboard_content)
        except tk.TclError:
            messagebox.showwarning("Paste Error", "No content in clipboard or cannot access clipboard.")

    def update_gui_from_queue(self):
        # Spracuje správy z fronty a aktualizuje GUI (pokrok, stav, MetaMask údaje, ETH adresu)
        while not self.message_queue.empty():
            try:
                message = self.message_queue.get_nowait()
                msg_type = message[0]

                # Aktualizácia pokroku s popisom aktuálnej operácie
                if msg_type == 'progress':
                    current, total, operation = message[1], message[2], message[3]
                    if total > 0:
                        percent = (current / total) * 100
                        self.progress_bar['value'] = percent
                        self.status_message.set(f"Processing: {percent:.2f}% ({operation})")
                    else:
                        self.progress_bar['value'] = 0
                        self.status_message.set("Processing: 0.00% (Initializing)")
                
                # Aktualizácia stavu s popisom aktuálnej operácie
                elif msg_type == 'status':
                    self.status_message.set(f"{message[1]}")
                
                # Spracovanie úspešnej dekompresie (zobraziť až na konci)
                elif msg_type == 'success':
                    decompressed_len, output_file, data_found = message[1], message[2], message[3]
                    self.final_output_file = output_file  # Uložiť názov súboru pre záverečnú správu
                    self.final_decompressed_len = decompressed_len
                    self.final_data_found = data_found
                
                # Spracovanie nájdených MetaMask údajov
                elif msg_type == 'metamask_found':
                    found_data = message[1]
                    self.metamask_vault_text.config(state=tk.NORMAL)
                    self.metamask_vault_text.delete(1.0, tk.END)
                    self.metamask_vault_text.insert(tk.END, found_data)
                    self.metamask_vault_text.config(state=tk.DISABLED)
                    self.copy_metamask_button.config(state=tk.NORMAL)
                
                # Spracovanie nenájdených MetaMask údajov
                elif msg_type == 'metamask_not_found':
                    self.metamask_vault_text.config(state=tk.NORMAL)
                    self.metamask_vault_text.delete(1.0, tk.END)
                    self.metamask_vault_text.insert(tk.END, "MetaMask vault data not found in the decompressed content.")
                    self.metamask_vault_text.config(state=tk.DISABLED)
                    self.copy_metamask_button.config(state=tk.DISABLED)
                
                # Spracovanie nájdenej ETH adresy
                elif msg_type == 'eth_address_found':
                    self.found_eth_address_display.set("Address Found")
                    self.eth_address_status_label.config(fg="green", font=self.bold_font)
                
                # Spracovanie nenájdenej ETH adresy
                elif msg_type == 'eth_address_not_found':
                    searched_address = message[1]
                    self.found_eth_address_display.set("Address Not Found")
                    self.eth_address_status_label.config(fg="red", font=self.normal_font)
                
                # Spracovanie varovania
                elif msg_type == 'warning':
                    messagebox.showwarning("Decompression", message[1])
                    self.status_message.set("Decompression completed (with warning).")
                
                # Spracovanie chyby
                elif msg_type == 'error':
                    messagebox.showerror("Decompression Error", message[1])
                    self.status_message.set("Decompression failed.")
                
                # Ukončenie procesu a zobrazenie záverečnej správy
                elif msg_type == 'done':
                    self.decompress_button.config(state=tk.NORMAL)
                    if self.decompression_process and not self.decompression_process.is_alive():
                        self.decompression_process.join()
                        self.decompression_process = None
                        # Zobraziť záverečnú správu
                        if hasattr(self, 'final_output_file'):
                            status = "data found" if self.final_data_found else "data not found"
                            messagebox.showinfo(
                                "Decompression",
                                f"Decompression 100% finished, saved to {os.path.basename(self.final_output_file)} "
                                f"(total output: {self.final_decompressed_len} bytes, {status})."
                            )
            except multiprocessing.queues.Empty:
                pass

        # Naplánovanie ďalšej aktualizácie GUI
        if self.decompression_process and self.decompression_process.is_alive():
            self.master.after(100, self.update_gui_from_queue)
        elif self.decompression_process and not self.decompression_process.is_alive():
            self.decompress_button.config(state=tk.NORMAL)
            self.decompression_process.join()
            self.decompression_process = None

    def start_decompression_process(self):
        # Spustí dekompresný proces a inicializuje GUI
        input_file = self.input_file_path.get()
        output_file = self.output_file_path.get()
        search_metamask = True
        eth_address_to_find = self.eth_address_to_search.get().strip()

        if eth_address_to_find and not re.match(r"^0x[a-fA-F0-9]{40}$", eth_address_to_find):
            messagebox.showwarning("Invalid ETH Address", "Please enter a valid ETH address (e.g., 0x...). Search will proceed without it.")
            eth_address_to_find = None

        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"Input file '{input_file}' does not exist.")
            return

        if not output_file:
            messagebox.showerror("Error", "Please specify an output file.")
            return
        
        self.decompress_button.config(state=tk.DISABLED)
        self.copy_metamask_button.config(state=tk.DISABLED)
        self.progress_bar['value'] = 0
        self.status_message.set("Starting decompression...")
        self.clear_metamask_display()
        self.found_eth_address_display.set("Searching for ETH address...")
        self.eth_address_status_label.config(fg="blue", font=self.normal_font)

        self.decompression_process = multiprocessing.Process(
            target=decompress_process_task,
            args=(input_file, output_file, self.message_queue, search_metamask, eth_address_to_find)
        )
        self.decompression_process.start()
        
        self.master.after(100, self.update_gui_from_queue)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = SnappyGUI(root)
    root.mainloop()