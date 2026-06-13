"""credproxy host CLI.

A credproxy *workspace* is a named, persistent pair of containers -- a
proxy container and a workspace container sharing one netns. See
design-v1.md for the container model; design-v2.md for the core/porcelain
split and XDG storage layout this package implements.

The package is laid out in two layers:

  core/      -- the engine. Takes fully-explicit, already-validated
                inputs (concrete workspace names, no defaults
                resolution), returns structured data or raises typed
                exceptions. No printing, no prompting, no argparse.
  porcelain/ -- argparse wiring, default-name resolution, the delete
                confirmation prompt, all rendering, and exec-ing docker
                for shell/logs. Calls core with explicit inputs.

Dependency runs one way: porcelain -> core.
"""
