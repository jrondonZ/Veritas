"""Operator-supplied recordings and documents, read as hostile input (docs/architecture.md §4, TZ4).

Nothing here sends traffic or fetches what a recording names. Readers keep the shape of
what they read and drop every value that could authenticate or identify someone.
"""
