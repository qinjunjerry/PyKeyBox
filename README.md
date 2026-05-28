# PyKeyBox
A mini key/password manager written in python using the AES encryption
algorithm from PyCrypto -- the python cryptography toolkit.

It stores your secret data, encrypted with AES, as key contents and associates
them with key titles you gave to provide you maximum

- flexibility: you can put whatever you want, in whatever format, into key
               contents including not only password, but also license keys,
               security questions, secret URLs, etc.

- simplicity : easy operations to any of your keys: add/view/edit/delete/list


## It is mini
Only one python file with size less than 10k bytes, and less than 250
lines of code, excluding empty lines and comments.


## Simple
```
keybox help             : Show this help message and exit
keybox list             : List all key titles
keybox add    <title>   : Add a new key title and content
keybox view   <keyword> : View the content for the key title matching the given keywords
keybox edit   <keyword> : Edit the content for the key title matching the given keywords
keybox del    <keyword> : Delete an existing key title matching the given keywords and the key content
keybox rm    <keyword>  : Alias for 'del'
keybox import <file>    : Import all key titles and contents from a text file
keybox export [file]    : Export all key titles and contents to stdout or a file
keybox reset            : Reset the master password
```


## Portable
Just take the python script file and the sqlite database file with you
anywhere you want.


## Yet secure enough
It is based on the well known AES encryption algorithm.


## Web UI
A minimal Flask web UI is included in `webapp.py`. It reuses the same
`KeyBox` core and SQLite database as the CLI.

```
pip install -r requirements.txt
python webapp.py
```

Then open http://127.0.0.1:5000 in your browser. On first run you set the
master password; afterwards you unlock with it. The master key is held only
in server-side session memory (never in the browser cookie).

Configuration via environment variables:

- `KEYBOX_DB`    : path to the keybox database file (default: same as the CLI)
- `KEYBOX_HOST`  : bind host (default: 127.0.0.1)
- `KEYBOX_PORT`  : bind port (default: 5000)
- `KEYBOX_SECRET`: Flask session secret (default: random per start)

The bundled server is Flask's development server; put a production WSGI
server (e.g. gunicorn) in front of it for real deployments.


## MCP server
An MCP (Model Context Protocol) server is included in `mcp_server.py`, exposing
the same `KeyBox` core to MCP clients such as Claude Desktop and Claude Code. It
speaks stdio only and reuses the same SQLite database as the CLI and web UI.

```
pip install -r requirements.txt
```

Register it with your MCP client. For Claude Code:

```
claude mcp add pykeybox -- /path/to/PyKeyBox/.venv/bin/python /path/to/PyKeyBox/mcp_server.py
```

Or in a client config file (e.g. Claude Desktop's `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pykeybox": {
      "command": "/path/to/PyKeyBox/.venv/bin/python",
      "args": ["/path/to/PyKeyBox/mcp_server.py"]
    }
  }
}
```

Tools: `unlock`, `lock`, `list_keys`, `search_keys`, `view_key`, `add_key`,
`edit_key`, `delete_key`. Call `unlock` with the master password once per
session before the others; the derived AES key is held only in the server
process's memory and is never written to disk.

Configuration via environment variables:

- `KEYBOX_DB`     : path to the keybox database file (default: same as the CLI)
- `KEYBOX_MASTER` : master password to auto-unlock at startup (optional; prefer
                    the `unlock` tool, since this places the password in the
                    client config)

Security: run this over stdio on localhost only -- never expose it over the
network. Any model connected to the server can read every secret in plaintext
once unlocked.
