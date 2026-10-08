#!/usr/bin/env python3
"""
Model Download and Checksum Verification Script (Phase 1 Baseline)

Downloads Qwen2.5-1.5B-Instruct-Q4_K_M GGUF from official HuggingFace repository,
computes the SHA-256 checksum, and strictly verifies it against the pinned hash.
Complies with PRD requirements: FR-015, LLM-008.
"""

import argparse
import hashlib
import os
import sys
import urllib.request

MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_FILENAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
PINNED_SHA256 = "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"


def compute_sha256(filepath: str, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file in streaming chunks."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


def download_with_progress(url: str, output_path: str):
    """Download a file with console progress indication."""
    print(f"Downloading model from: {url}")
    print(f"Destination: {output_path}")

    temp_path = output_path + ".tmp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Bayora-Adversarial-Platform/0.1"})
        with urllib.request.urlopen(req) as response, open(temp_path, "wb") as out_file:
            total_size = int(response.headers.get("content-length", 0))
            downloaded = 0
            block_size = 1024 * 1024  # 1MB chunks

            while chunk := response.read(block_size):
                out_file.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    mb_downloaded = downloaded / (1024 * 1024)
                    mb_total = total_size / (1024 * 1024)
                    sys.stdout.write(f"\rProgress: {mb_downloaded:.1f}/{mb_total:.1f} MB ({percent:.1f}%)")
                    sys.stdout.flush()

        print("\nDownload finished. Finalizing file...")
        os.replace(temp_path, output_path)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise RuntimeError(f"Download failed: {e}") from e


def verify_model(filepath: str, pinned_hash: str) -> bool:
    """Verify that file exists and matches the pinned SHA-256 hash."""
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return False

    print(f"Computing SHA-256 checksum for: {filepath} ...")
    computed_hash = compute_sha256(filepath)
    print(f"Computed SHA-256: {computed_hash}")
    print(f"Pinned   SHA-256: {pinned_hash}")

    if computed_hash.lower() == pinned_hash.lower():
        print("✅ Checksum VERIFIED successfully. Weights match official pinned digest.")
        return True
    else:
        print("❌ CHECKSUM MISMATCH! Pinned hash does not match computed hash.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Download and verify Qwen2.5-1.5B GGUF model.")
    parser.add_argument("--dest-dir", default="models", help="Directory where model should be stored.")
    parser.add_argument("--verify-only", action="store_true", help="Only verify existing file without downloading.")
    args = parser.parse_args()

    os.makedirs(args.dest_dir, exist_ok=True)
    target_path = os.path.join(args.dest_dir, MODEL_FILENAME)

    if os.path.exists(target_path):
        print(f"Model file already exists at: {target_path}")
        if verify_model(target_path, PINNED_SHA256):
            return 0
        elif args.verify_only:
            return 1
        else:
            print("Existing file failed verification. Re-downloading...")
            os.remove(target_path)

    if args.verify_only:
        print(f"Error: Model file {target_path} does not exist.")
        return 1

    download_with_progress(MODEL_URL, target_path)

    if not verify_model(target_path, PINNED_SHA256):
        print("Error: Downloaded file failed SHA-256 verification. Deleting corrupted file.")
        if os.path.exists(target_path):
            os.remove(target_path)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
