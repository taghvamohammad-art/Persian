"""Prints --hidden-import arguments for the standard library, so code that
arrives through "get new features" can use any stdlib module, not only the
ones the .exe's own copy happened to import."""
import sys

SKIP = ("test", "idlelib", "tkinter", "turtle", "turtledemo", "lib2to3", "ensurepip", "venv", "pydoc_data",
        "this", "antigravity", "__phello__", "_tkinter", "msilib", "nis", "spwd", "crypt", "ossaudiodev",
        "readline", "curses", "_curses", "_curses_panel", "dbm", "_dbm", "_gdbm", "posix", "pwd", "grp",
        "termios", "resource", "fcntl", "syslog", "_posixsubprocess", "_posixshmem", "tty", "pty")
for name in sorted(sys.stdlib_module_names):
    if name.startswith("_") or name in SKIP:
        continue
    print("--hidden-import=" + name)
