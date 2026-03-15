#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WUPify.py

Features:
  1) Add .app to files without an extension
  2) Keep only highest tmd.XXX -> rename to title.tmd (delete lower ones)
  3) Keep only highest cetk.XXX -> rename to title.tik (delete lower ones)
  4) If cetk/title.tik is missing, generate title.tik from title.tmd
     using the Wii U ticket generation algorithm (TitleID, TitleVersion,
     key generation, encrypted title key, ticket template)
  5) Copy title.cert (adjacent to this script or --cert-path) ONLY to folders that contain BOTH title.tmd and title.tik
     - Verify title.cert hashes before copying:
         CRC32: 0B80C239
         MD5  : 420D5E6BB1BCB09B234F02CF6A6F4597
         
     Credits for 4) & 5) : https://github.com/Xpl0itU/WiiUDownloader
     
Output style:
  - English messages
  - No per-file details
  - Final summary with success/skip/error counts
  - List of problematic folders (path + reason)

Examples:
  python WUPify.py --path . --recursive
  python WUPify.py --path . --only-cert --cert-path /path/to/title.cert --force-cert
"""

from __future__ import annotations
import argparse
import logging
import sys
import re
from pathlib import Path
import shutil
from typing import Iterable, List, Tuple
import hashlib
import zlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


EXPECTED_CRC32 = "0B80C239"
EXPECTED_MD5   = "420D5E6BB1BCB09B234F02CF6A6F4597"

KEYGEN_SECRET = "fd040105060b111c2d49"
WIIU_COMMON_KEY = bytes([0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56])
TITLE_KEY_PASSWORDS = {
    0: b"mypass",
    1: b"nintendo",
    2: b"test",
    3: b"1234567890",
    4: b"Lucy131211",
    5: b"fbf10",
    6: b"5678",
    7: b"1234",
    8: b"",
    9: b"MAGIC",
}

TICKET_ENCRYPTED_KEY_OFFSET = 0x1BF
TICKET_ENCRYPTED_KEY_SIZE   = 0x10
TICKET_TITLE_ID_OFFSET      = 476
TICKET_TITLE_ID_SIZE        = 8
TICKET_TITLE_VERSION_OFFSET = 486
TICKET_TITLE_VERSION_SIZE   = 2
TICKET_TEMPLATE_HEX = "" +     "00010004d15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed15abe11ad15ea5ed" +     "15abe11a00000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "526f6f742d434130303030303030332d58533030303030303063000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface" +     "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000cc" +     "cccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaa" +     "aaaaaaaa00000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "0001000000000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "0000000000010014000000ac0000001400010014000000000000002800000001" +     "00000084000000840003000000000000ffffffffffffffffffffffffffffffff" +     "ffffffffffffffffffffffffffffffff00000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "0000000000000000000000000000000000000000000000000000000000000000" +     "00000000000000000000000000000000"

CONTENT_TYPE_HASHED = 0x02
BLOCK_SIZE_HASHED = 0x10000
HASH_BLOCK_SIZE = 0xFC00
HASHES_SIZE = 0x0400
HASH_ENTRY_SIZE = 0x14
TMD_VERSION_WII = 0x00
TMD_VERSION_WIIU = 0x01

# --------------------------------------------------------------------
# Logging (summary-oriented: INFO shows only step headers + totals)
# --------------------------------------------------------------------
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def iter_files(base: Path, recursive: bool) -> Iterable[Path]:
    if recursive:
        yield from (p for p in base.rglob("*") if p.is_file())
    else:
        yield from (p for p in base.iterdir() if p.is_file())

def file_exists_case_insensitive(d: Path, name: str) -> Path | None:
    lname = name.lower()
    for p in d.iterdir():
        if p.is_file() and p.name.lower() == lname:
            return p
    return None

def compute_crc32_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08X}"

def compute_md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest().upper()

# --------------------------------------------------------------------
# Step 1: add .app to files without extension
# --------------------------------------------------------------------
def add_app_extension(base: Path, recursive: bool, dry_run: bool) -> Tuple[int, int, List[Tuple[Path, str]]]:
    renamed = 0
    skipped = 0
    problems: List[Tuple[Path, str]] = []
    for f in iter_files(base, recursive):
        if f.suffix == "" and not f.name.startswith("."):
            target = f.with_suffix(".app")
            if target.exists():
                skipped += 1
                problems.append((f.parent, f"skip .app: target exists ({target.name})"))
                continue
            try:
                if not dry_run:
                    f.rename(target)
                renamed += 1
            except Exception as e:
                problems.append((f.parent, f".app rename failed: {e}"))
    return renamed, skipped, problems

# --------------------------------------------------------------------
# Steps 2 & 3: numbered series (tmd.XXX / cetk.XXX)
# --------------------------------------------------------------------
def process_numbered_series(
    base: Path,
    recursive: bool,
    dry_run: bool,
    overwrite: bool,
    prefix: str,
    target_name: str,
) -> Tuple[int, int, int, List[Tuple[Path, str]]]:
    """
    Keep highest `<prefix>.NUM` -> rename to `target_name`, delete lower ones.
    Returns (changed_dirs, skipped_dirs, deleted_files_count, problems[])
    """
    pattern = re.compile(rf"^{re.escape(prefix)}\.(\d+)$", re.IGNORECASE)
    changed_dirs = 0
    skipped_dirs = 0
    deleted_files = 0
    problems: List[Tuple[Path, str]] = []

    dirs = {base}
    if recursive:
        dirs |= {d for d in base.rglob("*") if d.is_dir()}

    for d in sorted(dirs):
        try:
            numbered = []
            for f in d.iterdir():
                if f.is_file():
                    m = pattern.match(f.name)
                    if m:
                        numbered.append((int(m.group(1)), f))
            if not numbered:
                continue

            numbered.sort(key=lambda x: x[0])
            _, highest_file = numbered[-1]
            lower_files = [f for _, f in numbered[:-1]]
            target = d / target_name

            if target.exists() and not overwrite:
                skipped_dirs += 1
                # still delete lower ones
                for lf in lower_files:
                    try:
                        if not dry_run:
                            lf.unlink(missing_ok=True)
                        deleted_files += 1
                    except Exception as e:
                        problems.append((d, f"delete lower {prefix} failed: {lf.name}: {e}"))
                problems.append((d, f"skip {prefix}: {target_name} exists (use --overwrite)"))
                continue

            # rename highest
            try:
                if target.exists() and overwrite and not dry_run:
                    target.unlink()
                if not dry_run:
                    highest_file.rename(target)
            except Exception as e:
                skipped_dirs += 1
                problems.append((d, f"rename highest {prefix} -> {target_name} failed: {e}"))
                continue

            # delete lower ones
            for lf in lower_files:
                try:
                    if not dry_run:
                        lf.unlink(missing_ok=True)
                    deleted_files += 1
                except Exception as e:
                    problems.append((d, f"delete lower {prefix} failed: {lf.name}: {e}"))

            changed_dirs += 1
        except Exception as e:
            problems.append((d, f"series processing failed for {prefix}: {e}"))

    return changed_dirs, skipped_dirs, deleted_files, problems

# --------------------------------------------------------------------
# Step 4: generate missing title.tik from title.tmd (default keyType=0)
# --------------------------------------------------------------------
def trim_leading_zero_pairs(s: str) -> str:
    while len(s) >= 2 and s.startswith("00"):
        s = s[2:]
    return s


def weird_hex_to_bytes(s: str) -> bytes:
    out = bytearray()
    for i in range(0, len(s), 2):
        a = ((ord(s[i]) % 32 + 9) % 25)
        b = ((ord(s[i + 1]) % 32 + 9) % 25)
        out.append(a * 16 + b)
    return bytes(out)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def align16(n: int) -> int:
    return (n + 15) & ~15


class ParsedContent:
    def __init__(self, cid: int, index: int, ctype: int, size: int, h: bytes) -> None:
        self.id = cid
        self.index = index
        self.type = ctype
        self.size = size
        self.hash = h


class ParsedTMD:
    def __init__(self, title_id: int, version: int, title_version: int, contents: List[ParsedContent]) -> None:
        self.title_id = title_id
        self.version = version
        self.title_version = title_version
        self.contents = contents


def parse_tmd(path: Path) -> ParsedTMD:
    data = path.read_bytes()
    if len(data) < 0x1E0:
        raise ValueError("TMD too small")

    version = data[0x180]
    if version == TMD_VERSION_WII:
        content_start, stride, hash_size = 0x1E4, 0x24, 0x14
    elif version == TMD_VERSION_WIIU:
        content_start, stride, hash_size = 0xB04, 0x30, 0x20
    else:
        raise ValueError(f"Unknown TMD version: {version}")

    title_id = struct.unpack(">Q", data[0x18C:0x194])[0]
    title_version = struct.unpack(">H", data[0x1DC:0x1DE])[0]
    content_count = struct.unpack(">H", data[0x1DE:0x1E0])[0]
    contents: List[ParsedContent] = []
    for i in range(content_count):
        off = content_start + (stride * i)
        end = off + 16 + hash_size
        if end > len(data):
            raise ValueError("TMD content table truncated")
        cid = struct.unpack(">I", data[off:off+4])[0]
        index = struct.unpack(">H", data[off+4:off+6])[0]
        ctype = struct.unpack(">H", data[off+6:off+8])[0]
        size = struct.unpack(">Q", data[off+8:off+16])[0]
        h = data[off+16:off+16+hash_size]
        contents.append(ParsedContent(cid, index, ctype, size, h))
    return ParsedTMD(title_id, version, title_version, contents)


def derive_plain_title_key(title_id_hex: str, key_type: int) -> bytes:
    if len(title_id_hex) != 16:
        raise ValueError(f"Invalid title ID length: {len(title_id_hex)}")
    int(title_id_hex, 16)
    tmp = trim_leading_zero_pairs(title_id_hex)
    h = KEYGEN_SECRET + tmp
    bh = weird_hex_to_bytes(h)
    md5sum = hashlib.md5(bh).digest()
    password = TITLE_KEY_PASSWORDS.get(key_type, b"mypass")
    return hashlib.pbkdf2_hmac("sha1", password, md5sum, 20, 16)


def generate_encrypted_title_key(title_id_hex: str, key_type: int) -> bytes:
    plain_key = derive_plain_title_key(title_id_hex, key_type)
    iv = weird_hex_to_bytes(title_id_hex) + (b"\x00" * 8)
    return aes_cbc_encrypt(pkcs7_pad(plain_key, 16), WIIU_COMMON_KEY, iv)


def write_ticket_file(tik_path: Path, title_id: int, encrypted_title_key: bytes, title_version: int) -> None:
    ticket = bytearray.fromhex(TICKET_TEMPLATE_HEX)
    ticket[TICKET_ENCRYPTED_KEY_OFFSET:TICKET_ENCRYPTED_KEY_OFFSET + 16] = encrypted_title_key[:16]
    ticket[TICKET_TITLE_ID_OFFSET:TICKET_TITLE_ID_OFFSET + 8] = struct.pack(">Q", title_id)
    ticket[TICKET_TITLE_VERSION_OFFSET:TICKET_TITLE_VERSION_OFFSET + 2] = struct.pack(">H", title_version)
    tik_path.write_bytes(ticket)


def find_content_file(d: Path, cid: int) -> Path | None:
    names = [f"{cid:08X}.app", f"{cid:08x}.app"]
    for name in names:
        p = file_exists_case_insensitive(d, name)
        if p is not None:
            return p
    return None


def verify_non_hashed_content(app_path: Path, content: ParsedContent, title_key: bytes) -> bool:
    iv = bytearray(16)
    iv[0:2] = struct.pack(">H", content.index)
    decryptor = Cipher(algorithms.AES(title_key), modes.CBC(bytes(iv))).decryptor()
    h = hashlib.sha1()
    left_plain = content.size
    with app_path.open("rb") as f:
        while left_plain > 0:
            to_plain = min(8 * 1024 * 1024, left_plain)
            to_read = align16(int(to_plain))
            chunk = f.read(to_read)
            if len(chunk) != to_read:
                return False
            dec = decryptor.update(chunk)
            h.update(dec[:to_plain])
            left_plain -= to_plain
    return h.digest() == content.hash[:20]


def verify_hashed_content(app_path: Path, h3_path: Path, content: ParsedContent, title_key: bytes) -> bool:
    try:
        h3_data = h3_path.read_bytes()
    except Exception:
        return False
    if hashlib.sha1(h3_data).digest() != content.hash[:20]:
        return False

    with app_path.open("rb") as f:
        block = f.read(BLOCK_SIZE_HASHED)
    if len(block) < HASHES_SIZE + 16 or len(block) % 16 != 0:
        return False

    hashes_enc = block[:HASHES_SIZE]
    body_enc = block[HASHES_SIZE:]
    hashes = aes_cbc_decrypt(hashes_enc, title_key, b"\x00" * 16)

    h0_hash = bytearray(hashes[0:HASH_ENTRY_SIZE])
    iv_block = bytearray(hashes[0:16])
    iv_block[1] ^= (content.index & 0xFF)

    body_dec = aes_cbc_decrypt(body_enc, title_key, bytes(iv_block))
    payload = body_dec[:HASH_BLOCK_SIZE]
    calc = bytearray(hashlib.sha1(payload).digest())
    calc[1] ^= (content.index & 0xFF)
    return bytes(calc) == bytes(h0_hash)


def choose_verification_target(d: Path, tmd: ParsedTMD) -> tuple[ParsedContent, Path, Path | None] | None:
    hashed_candidates = []
    normal_candidates = []
    for content in tmd.contents:
        app_path = find_content_file(d, content.id)
        if app_path is None:
            continue
        if content.type & CONTENT_TYPE_HASHED:
            h3 = file_exists_case_insensitive(d, f"{app_path.stem}.h3")
            if h3 is not None:
                hashed_candidates.append((content.size, content, app_path, h3))
        else:
            normal_candidates.append((content.size, content, app_path, None))
    if hashed_candidates:
        hashed_candidates.sort(key=lambda x: x[0])
        _, content, app_path, h3 = hashed_candidates[0]
        return content, app_path, h3
    if normal_candidates:
        normal_candidates.sort(key=lambda x: x[0])
        _, content, app_path, _ = normal_candidates[0]
        return content, app_path, None
    return None


def get_default_key_type() -> int:
    return 0


def generate_missing_tik(
    base: Path,
    recursive: bool,
    dry_run: bool,
    overwrite: bool,
    verbose: bool,
) -> Tuple[int, int, List[Tuple[Path, str]]]:
    generated = 0
    skipped = 0
    problems: List[Tuple[Path, str]] = []

    dirs = [base]
    if recursive:
        dirs.extend(sorted(d for d in base.rglob("*") if d.is_dir()))

    for d in dirs:
        try:
            tik_path = file_exists_case_insensitive(d, "title.tik")
            tmd_path = file_exists_case_insensitive(d, "title.tmd")
            if tik_path is not None and not overwrite:
                skipped += 1
                continue
            if tmd_path is None:
                continue
            tmd = parse_tmd(tmd_path)
            key_type = get_default_key_type()
            if verbose:
                logging.debug("Using default keyType=%d for %s", key_type, d)
            encrypted = generate_encrypted_title_key(f"{tmd.title_id:016x}", key_type)
            target = d / "title.tik"
            if not dry_run:
                write_ticket_file(target, tmd.title_id, encrypted, tmd.title_version)
            generated += 1
        except Exception as e:
            problems.append((d, f"title.tik generation failed: {e}"))

    return generated, skipped, problems

# --------------------------------------------------------------------
# Step 5: copy title.cert if BOTH title.tmd and title.tik exist (with hash checks)
# --------------------------------------------------------------------
def copy_title_cert(
    base: Path,
    recursive: bool,
    dry_run: bool,
    cert_path: Path | None,
    force: bool
) -> Tuple[int, int, List[Tuple[Path, str]]]:
    """
    Returns (copied_count, skipped_count, problems[])
    """
    source_cert = cert_path if cert_path is not None else Path(__file__).resolve().parent / "title.cert"
    problems: List[Tuple[Path, str]] = []
    if not source_cert.exists():
        problems.append((source_cert.parent, f"title.cert not found at {source_cert}"))
        return 0, 0, problems

    # Verify hashes once
    data = source_cert.read_bytes()
    crc32_hex = compute_crc32_hex(data)
    md5_hex = compute_md5_hex(data)
    if crc32_hex != EXPECTED_CRC32 or md5_hex != EXPECTED_MD5:
        problems.append((source_cert.parent,
                         f"title.cert hash check failed: CRC32={crc32_hex} (expected {EXPECTED_CRC32}), "
                         f"MD5={md5_hex} (expected {EXPECTED_MD5})"))
        return 0, 0, problems

    dirs_to_check = [base]
    if recursive:
        dirs_to_check.extend(d for d in base.rglob("*") if d.is_dir())

    copied = 0
    skipped = 0
    for d in dirs_to_check:
        try:
            has_tmd = file_exists_case_insensitive(d, "title.tmd") is not None
            has_tik = file_exists_case_insensitive(d, "title.tik") is not None
            if not (has_tmd and has_tik):
                # Track as skipped-with-reason
                if has_tmd or has_tik:
                    missing = "title.tik" if has_tmd and not has_tik else "title.tmd"
                    problems.append((d, f"cert skipped: missing {missing}"))
                continue

            dest = d / "title.cert"
            if dest.exists() and not force:
                skipped += 1
                problems.append((d, "cert skipped: title.cert already exists (use --force-cert)"))
                continue

            if not dry_run:
                d.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_cert, dest)
            copied += 1
        except Exception as e:
            problems.append((d, f"cert copy failed: {e}"))

    return copied, skipped, problems

# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="WUPify: .app, tmd.*, cetk.*, title.cert (summary logs)")
    p.add_argument("--path", type=Path, required=True, help="Base directory")
    p.add_argument("--recursive", action="store_true", help="Include subdirectories")
    p.add_argument("--overwrite", action="store_true", help="Allow replacing existing title.tmd/title.tik")
    p.add_argument("--dry-run", action="store_true", help="Preview only (no changes)")
    p.add_argument("--only-app", action="store_true", help="Run only step .app")
    p.add_argument("--only-tmd", action="store_true", help="Run only step tmd.*")
    p.add_argument("--only-cetk", action="store_true", help="Run only step cetk.*")
    p.add_argument("--only-tik-gen", action="store_true", help="Run only the missing title.tik generation step")
    p.add_argument("--only-cert", action="store_true", help="Run only step title.cert copy")
    p.add_argument("--cert-path", type=Path, help="Explicit path to title.cert (default: next to this script)")
    p.add_argument("--force-cert", action="store_true", help="Overwrite existing title.cert")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logs")
    return p.parse_args(argv)

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    setup_logging(args.verbose)

    base = args.path
    if not base.exists() or not base.is_dir():
        logging.error("Base path is not a directory: %s", base)
        return 2

    if sum([args.only_app, args.only_tmd, args.only_cetk, args.only_tik_gen, args.only_cert]) > 1:
        logging.error("Choose at most one --only-* option.")
        return 2

    run_app = run_tmd = run_cetk = run_tik_gen = run_cert = True
    if args.only_app:
        run_tmd = run_cetk = run_cert = False
    elif args.only_tmd:
        run_app = run_cetk = run_cert = False
    elif args.only_cetk:
        run_app = run_tmd = run_cert = False
    elif args.only_tik_gen:
        run_app = run_tmd = run_cetk = run_cert = False
    elif args.only_cert:
        run_app = run_tmd = run_cetk = run_tik_gen = False

    # Step 1
    total_app = (0, 0, [])
    if run_app:
        logging.info("== Step 1: add .app to files without extension ==")
        total_app = add_app_extension(base, args.recursive, args.dry_run)

    # Step 2
    total_tmd = (0, 0, 0, [])
    if run_tmd:
        logging.info("== Step 2: tmd.XXX -> title.tmd (keep highest) ==")
        total_tmd = process_numbered_series(base, args.recursive, args.dry_run, args.overwrite, "tmd", "title.tmd")

    # Step 3
    total_cetk = (0, 0, 0, [])
    if run_cetk:
        logging.info("== Step 3: cetk.XXX -> title.tik (keep highest) ==")
        total_cetk = process_numbered_series(base, args.recursive, args.dry_run, args.overwrite, "cetk", "title.tik")

    # Step 4
    total_tik_gen = (0, 0, [])
    if run_tik_gen:
        logging.info("== Step 4: generate missing title.tik from title.tmd (default keyType=0) ==")
        total_tik_gen = generate_missing_tik(base, args.recursive, args.dry_run, args.overwrite, args.verbose)

    # Step 5
    total_cert = (0, 0, [])
    if run_cert:
        logging.info("== Step 5: copy title.cert (only if title.tmd & title.tik) + hash verification ==")
        total_cert = copy_title_cert(base, args.recursive, args.dry_run, args.cert_path, args.force_cert)

    # ----------------- Summary -----------------
    app_renamed, app_skipped, app_problems = total_app
    tmd_changed, tmd_skipped, tmd_deleted, tmd_problems = total_tmd
    cetk_changed, cetk_skipped, cetk_deleted, cetk_problems = total_cetk
    tik_generated, tik_skipped, tik_problems = total_tik_gen
    cert_copied, cert_skipped, cert_problems = total_cert

    problems = app_problems + tmd_problems + cetk_problems + tik_problems + cert_problems

    print("")
    print("========== SUMMARY ==========")
    if run_app:
        print(f"Step 1 (.app): renamed={app_renamed}, skipped={app_skipped}")
    if run_tmd:
        print(f"Step 2 (tmd):  changed_dirs={tmd_changed}, skipped_dirs={tmd_skipped}, lower_deleted={tmd_deleted}")
    if run_cetk:
        print(f"Step 3 (cetk): changed_dirs={cetk_changed}, skipped_dirs={cetk_skipped}, lower_deleted={cetk_deleted}")
    if run_tik_gen:
        print(f"Step 4 (tik gen): generated={tik_generated}, skipped={tik_skipped}")
    if run_cert:
        print(f"Step 5 (cert): copied={cert_copied}, skipped={cert_skipped}")

    if problems:
        print("\nProblems:")
        # Deduplicate (dir, reason) pairs while keeping order
        seen = set()
        for d, reason in problems:
            key = (str(d.resolve()), reason)
            if key in seen:
                continue
            seen.add(key)
            print(f"- {d} -> {reason}")
    else:
        print("\nProblems: none 🎉")
    print("=============================")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
