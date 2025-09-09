# Keylogger-Defense-Tool
Demonstrating how to detect suspicious processes that may be capturing keystrokes. Built in Python with psutil.

How this works:

-Uses the psutil library to inspect running processes.
-Flags anything with names/commands that look like “keylogger” (you can expand the keyword list).
-Runs safely — it does not interfere with normal processes.
