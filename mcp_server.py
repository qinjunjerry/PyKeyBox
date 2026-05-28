#!/usr/bin/env python3

"""A stdio MCP server exposing the PyKeyBox password manager.

Reuses the KeyBox class directly. The master password is supplied at runtime
via the `unlock` tool (or the KEYBOX_MASTER env var) and the derived AES key is
held only in this process's memory, never written to disk.

Run with a local MCP client over stdio only — never expose this over HTTP/network.
"""

import os
import time

from mcp.server.fastmcp import FastMCP

from keybox import KeyBox, get_default_db_file

DB_FILE = os.environ.get("KEYBOX_DB") or get_default_db_file()

mcp = FastMCP("pykeybox")

# AES key for the current process session; None until unlocked.
_state = {"aes_key": None}


def _open(require_unlock=True):
    box = KeyBox(DB_FILE)
    if require_unlock:
        if _state["aes_key"] is None:
            raise ValueError("KeyBox is locked. Call `unlock` with the master password first.")
        box.aes_key = _state["aes_key"]
    return box


# Unlock eagerly from the environment if a master password was provided.
def _try_env_unlock():
    password = os.environ.get("KEYBOX_MASTER")
    if not password:
        return
    box = KeyBox(DB_FILE)
    if box.is_initialized() and box.check_master_password(password):
        _state["aes_key"] = box.aes_key


@mcp.tool()
def unlock(password: str) -> str:
    """Unlock the keybox with the master password for this session."""
    box = KeyBox(DB_FILE)
    if not box.is_initialized():
        raise ValueError("KeyBox is not initialized. Set a master password via the CLI or web UI first.")
    if not box.check_master_password(password):
        raise ValueError("Incorrect master password.")
    _state["aes_key"] = box.aes_key
    return "Unlocked."


@mcp.tool()
def lock() -> str:
    """Lock the keybox, clearing the in-memory key for this session."""
    _state["aes_key"] = None
    return "Locked."


@mcp.tool()
def list_keys() -> list[dict]:
    """List all key titles with their last-modified time (newest first)."""
    box = _open()
    return [
        {"title": title, "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mod_time))}
        for title, mod_time in box.list()
    ]


@mcp.tool()
def search_keys(keywords: list[str]) -> list[dict]:
    """Find key titles matching all of the given keywords (case-insensitive)."""
    box = _open()
    return [
        {"title": title, "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mod_time))}
        for title, mod_time in box.search(keywords)
    ]


@mcp.tool()
def view_key(title: str) -> dict:
    """View the decrypted content for an exact key title."""
    box = _open()
    if not box.exists(title):
        raise ValueError("No key with title %r." % title)
    mod_time, content = box.view(title)
    return {
        "title": title,
        "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mod_time)),
        "content": content,
    }


@mcp.tool()
def add_key(title: str, content: str) -> str:
    """Add a new key with the given title and content."""
    box = _open()
    if box.exists(title):
        raise ValueError("A key titled %r already exists; use edit_key to change it." % title)
    box.set(title, content, mod_time=time.time())
    return "Added %r." % title


@mcp.tool()
def edit_key(title: str, content: str) -> str:
    """Replace the content of an existing key."""
    box = _open()
    if not box.exists(title):
        raise ValueError("No key with title %r." % title)
    box.set(title, content, mod_time=time.time())
    return "Updated %r." % title


@mcp.tool()
def delete_key(title: str) -> str:
    """Delete an existing key by exact title."""
    box = _open()
    if not box.exists(title):
        raise ValueError("No key with title %r." % title)
    box.delete(title)
    return "Deleted %r." % title


if __name__ == "__main__":
    _try_env_unlock()
    mcp.run()
