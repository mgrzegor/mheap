mheap – Portable C implementation of custom heap with optional compaction

Overview
--------
This is a portable, low overhead C99 implementation of a custom allocator with an option to compact (defragment) and/or reallocate heap(s) via user-provided callbacks.
It borrows some ideas from the well-known Doug Lea’s *dlmalloc*;
however, it is much simpler and adds some functionality of its own.

This code has been originally written in year 2012 for a private project.

Licence
-------
This code is released under the MIT No Attribution Licence.
See the file `LICENSE` for details.

Configuration
-------------
Many details can be configured by pre-defining certain macros via compiler options.
See `cfg.h`, `myassert.h`, and `mheap.h` for more information.

Assertions
----------
This code uses its own assertion macros, including one that overrides the standard `assert()` macro.
Assertion failures result in a call to `InternalError()` which must be provided externally.
See `myassert.h` for more information.
