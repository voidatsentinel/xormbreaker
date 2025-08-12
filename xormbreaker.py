
from argparse import ArgumentParser
from shutil import get_terminal_size
from pathlib import Path
from sys import stdout
from enum import Enum
from typing import Optional, Dict, List
from dataclasses import dataclass
import codecs

__DEV = True
NULL_PADDING = b"\x00" * 8

@dataclass
class FileType:
    """File type with name, extension, and magic"""
    name: str
    ext: str
    magic: bytes

FILETYPES = [
    FileType("Windows Executable", ".exe", b"MZ"),
    FileType("Linux Executable", ".elf", b"\x7fELF"),
    FileType("ZIP Archive", ".zip", b"PK\x03\x04"),
    FileType("PDF Document", ".pdf", b"%PDF"),
    FileType("RAR Archive", ".rar", b"Rar!"),
    FileType("PNG Image", ".png", b"\x89PNG"),
    FileType("GIF Image", ".gif", b"GIF8"),
    FileType("JPEG Image", ".jpg", b"\xff\xd8\xff"),
    FileType("7-Zip Archive", ".7z", b"7z\xbc\xaf'\x1c"),
    FileType("BZip2 Archive", ".bz2", b"BZh"),
]
FILETYPES.append(FileType("Unknown", ".bin", b""))


class Tag(Enum):
    """Message format"""
    STATUS = "*"
    SUCCESS = "+"
    WARN = "!"
    SKIP = "-"

class StatusBar:
    """Status bar and printing"""

    _stream = stdout

    def __init__(self):
        self.status: str = ""
        self._clear()

    def _write(self, msg: str) -> None:
        self._stream.write(msg)

    def _flush(self) -> None:
        self._stream.flush()

    def _clear(self, flush: bool = True) -> None:
        cols = get_terminal_size().columns
        self._write("\r" + " " * cols + "\r")
        if flush: self._flush()

    def _msg(self, tag: Tag, left: str, right: str = None) -> str:
        right = right or ""
        cols = get_terminal_size().columns
        return f"[{tag.value}] {left:<32} {right:<48}"[:cols]

    def clear_status(self) -> None:
        self.status = "..."
        self._clear()

    def print_status(self, tag: Tag, left: str, right: Optional[str] = None, flush: bool = True) -> None:
        """Print status"""
        self.status = self._msg(tag=tag, left=left, right=right)
        self._clear(flush=False)
        self._write(self.status + "\r")
        if flush: self._flush()

    def print_line(self, tag: Tag, left: str, right: Optional[str] = None, flush: bool = True) -> None:
        """Print line, restore status"""
        self._clear(False)
        msg = self._msg(tag=tag, left=left, right=right)
        self._write(f"\r{msg}\n{self.status}\r")
        if flush: self._flush()


status_bar = StatusBar()


def xor(data: bytes, key: bytes) -> bytes:
    """XOR bytes with repeating key"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rotate_key(b: bytes) -> List[bytes]:
    """Give all key rotations"""
    return [b[i:] + b[:i] for i in range(len(b))]


def key_identifier(b: bytes) -> bytes:
    """Give first key rotation"""
    return sorted(rotate_key(b))[0]


def dupe_check(a: bytes, b: bytes) -> bool:
    """Check if key is a sub-repetition"""
    return a * (len(b) // len(a)) == b if len(a) <= len(b) else b * (len(a) // len(b)) == a

def printable_key(b: bytes, n: int = 16, file_safe:bool=False) -> str:
    """Printable key"""
    file_safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(map(lambda c: chr(c) if chr(c) in file_safe_chars else '_' if file_safe else '.', b[:n]))

def find_keys_by_repetition(data: bytes, min_len: int = 1, max_len: int = 255) -> List[bytes]:
    """Find repeated patterns in data as potential XOR keys"""
    status_bar.print_line(Tag.STATUS, "Scanning patterns")
    keys: List[bytes] = []
    tried = 0
    # Try different key lengths
    for n in range(min_len, max_len):
        # Scan through adjacent sections of length n
        for i in range(len(data) - 2 * n):
            a, b = data[i:i + n], data[i + n:i + 2 * n]
            # Print status, but not spammy so it won't slow the program too much
            tried += 1
            if tried % 0xFFFF == 0:
                status_bar.print_status(Tag.STATUS, f"Size [{n:3}]", printable_key(a))
            # If not a match, skip
            if a != b: continue
            # Get the minimal rotated key
            key = key_identifier(a)
            # Check key against all rotated forms of the key, and break if seen
            if any(k in rotate_key(key) for k in keys): break
            # Check if the key is a duplicate or a shorter already seen key
            if any(dupe_check(existing, key) for existing in keys):
                status_bar.print_line(Tag.SKIP, "Longer duplicate skipped", printable_key(key))
                break
            # Save key for testing
            keys.append(key)
            status_bar.print_line(Tag.WARN, f"Key [{n:>3}] {n<3 and "(junk?)" or ""}", printable_key(key))
    return keys


def try_keys_on_data(
    data: bytes,
    keys: List[bytes],
    cribs: List[bytes],
    output_path: Path,
    save_all: bool = False
) -> bool:
    """
    Try XOR decrypting with each key/rotation.
    Saves when the crib appears anywhere in the plaintext.
    Returns True if at least one output was written.
    """
    any_found = None
    for key in keys:
        for rotated in rotate_key(key):
            # Decrypt using rotated key
            status_bar.print_status(Tag.STATUS, "Decrypting", printable_key(rotated))
            decrypted = xor(data, rotated)
            # No crib, no match (unless save all)
            found = False
            # Check for null padding
            if NULL_PADDING in decrypted:
                status_bar.print_line(Tag.STATUS, "Null padding found", printable_key(NULL_PADDING))
                found = True
            # Check filetypes
            for filetype in FILETYPES:
                if filetype.name == "Unknown": continue
                if decrypted.startswith(filetype.magic):
                    status_bar.print_line(Tag.STATUS, "Crib file magic found", f"[{printable_key(filetype.magic)}] [{filetype.name}]")
                    found = True
            # Check cribs
            for crib in cribs:
                if crib in decrypted:
                    status_bar.print_line(Tag.STATUS, f"Crib found", f"[{printable_key(crib)}]")
                    found = True
            # Save a success if anything is found
            if found: any_found = True
            # If something is found, continue, if save_all enabled, just save everything anyway
            if not save_all and not found: continue
            # Check if there's a known magic
            filetype = [ft for ft in FILETYPES if decrypted.startswith(ft.magic)][0]
            # Set file name
            rotated_safe = printable_key(rotated, file_safe=True)
            ext = output_path.suffix or filetype.ext
            file_name = f"{output_path.stem}_{len(rotated)}_{rotated_safe}"
            output_folder = output_path.parent
            out_file = Path(f"{output_folder}/{file_name}{ext}")
            key_file = Path(f"{output_folder}/{file_name}.key")
            # Save
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "wb") as f: f.write(decrypted)
            with open(key_file, "wb") as f: f.write(rotated)
            status_bar.print_line(Tag.SUCCESS, f"Saving file {file_name} ({ext} and .key)")
    # Return if a match is found
    return any_found == True


def main() -> None:
    """Parse args, find XOR key(s), try to decrypt"""

    # Args
    parser = ArgumentParser(description="XORmBreaker")
    parser.add_argument("--input", required=True, metavar="input_file.bin", help="input file path")
    parser.add_argument("--output", metavar="output_file(.exe)", help="output file path, with or without extension")
    parser.add_argument("--key", metavar="qwe123asd", help="if you know the key")
    parser.add_argument("--crib", metavar="\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00", help="known pattern, like null padding or potato")
    parser.add_argument("--all", action="store_true", help="save all rotations of all found keys, regardless of crib")
    parser.add_argument("--dev", action="store_true", help="debug mode, allows errors")
    parser.add_argument("--version", action="version", version="XORmBreaker v1.0.0")
    args = parser.parse_args()

    # Housekeeping
    global __DEV
    __DEV = args.dev == True

    # Values
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else Path(f"out/{input_path.stem}_decrypted")
    save_all = args.all

    key = codecs.decode(args.key.strip(), "unicode_escape").encode("latin1") if args.key else None
    cribs = [
        codecs.decode(c.strip(), "unicode_escape").encode("latin1")
        for c in args.crib.split(",")
    ] if args.crib else []


    # Read file
    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    # Determine keys
    keys: List[bytes] = []
    if key:
        status_bar.print_line(Tag.STATUS, "Using manual key", printable_key(key))
        keys.append(key)
    else:
        keys = find_keys_by_repetition(encrypted_data)

    # Try keys
    success = try_keys_on_data(
        encrypted_data, keys, cribs, output_path, save_all=save_all
    )
    if success:
        status_bar.print_line(Tag.SUCCESS, "Match(es) found")
    else:
        status_bar.print_line(Tag.STATUS, "No matches found")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print("\r\n[!] Interrupted by user")
    except Exception as e:
        print(f"\r\n[!] Error: {e}")
        if __DEV:
            raise e
