"""
__author__ = "Jon Waggoner, Patrick Renner"
__copyright__ = "Copyright 2020, Pomfort GmbH"
"""

import sys

import click

verbose_logging = False
debug_logging = False
# VENDORED PATCH (not in upstream): when True, suppress all logger output. The
# engine is driven in-process by mhlver, which collects structured results and
# renders its own terminal output through a rich console; letting upstream also
# echo to stdout/stderr would double the output and tear through the live bar.
quiet: bool = False


def debug(msg, *args):
    """Logs a message to stdout only if debug is enabled."""
    if debug_logging:
        info(msg, *args)


def verbose(msg, *args):
    """Logs a message to stdout only if verbose is enabled."""
    if verbose_logging:
        info(msg, *args)


def info(msg, *args):
    """Logs a message to stdout."""
    if quiet:
        return
    if args:
        msg %= args
    click.echo(msg, file=sys.stdout)


def error(msg, *args):
    """Logs a message to stderr"""
    if quiet:
        return
    if args:
        msg %= args
    click.echo(click.style(msg, fg="red", bold=True), file=sys.stderr)


def fatal(msg, *args):
    """Logs a message to stderr, then exits"""
    if args:
        msg %= args
    click.echo(click.style(msg, fg="red", bold=True, blink=True), file=sys.stderr)
    click.get_current_context().abort()
