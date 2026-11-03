# Phase 2 - Section 1 (Header Anlaysis Fixation)

This helps to do proper header analysis, helping to fetch headers relevant to the .eml files. Critical bugs fixed.

Earlier version detected only Content-Type: text/plain / text/html (Single-part) their primary purpose included. Their primary purpose was Simple messages or raw encoded blocks. No boundaries; a single data payload stream.

> **Updated:** Added Content-Type Structure - (**multipart/alternative**: Multiple formats of the same text. Contains plain text + HTML options for client compatibility | | | **multipart/mixed:**: Combining text bodies with file attachments. Contains the message body + discrete file attachments.)   
