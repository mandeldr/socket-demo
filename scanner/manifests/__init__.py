"""Readers that turn a manifest file into what it installs.

One module per format, each with a single `parse` function. What they return
differs, and deliberately so: a requirements.txt names ranges that still have
to be resolved against a registry, while a lock file names versions somebody
already committed, so it can hand back a finished graph.
"""
