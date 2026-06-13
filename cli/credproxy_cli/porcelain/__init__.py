"""credproxy porcelain: the human/CLI front-end.

Resolves convenience (the default workspace name), renders output, runs
the delete confirmation prompt, and exec-s docker for the interactive
verbs (shell, logs). Calls the core with fully-explicit inputs and
catches the core's typed exceptions.

Dependency runs one way: porcelain -> core. The core never imports this.
"""
