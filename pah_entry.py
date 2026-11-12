"""Entry point for the Claude Code plugin's hooks and commands. Always run it with `python -I`.

Isolated mode keeps the current directory (the project being worked on, which may be hostile) and PYTHON* variables
out of the import path; this file then adds only its own folder. Hook calls skip the command-line parser, because
they run before every tool call.
"""
import sys

if sys.version_info < (3, 10):  # noqa: UP036 (whatever Python the hook finds, say why the guard is off)
    sys.stdout.write('{"systemMessage": "agent-virus-check needs Python 3.10 or newer; the guard is not running."}\n')
    sys.exit(0)

import os  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if (len(sys.argv) in (3, 5) and sys.argv[1] == "hook" and sys.argv[2] in ("pre", "post", "session-start")
        and (len(sys.argv) == 3 or sys.argv[3] == "--agent")):
    from pah.hooks import main as hook_main  # noqa: E402

    sys.exit(hook_main(sys.argv[2], sys.argv[4] if len(sys.argv) == 5 else "claude"))

from pah.cli import main  # noqa: E402

sys.exit(main())
