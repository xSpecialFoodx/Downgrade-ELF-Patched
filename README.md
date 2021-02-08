# Downgrade-ELF-Patched
the downgrade elf script by flatz, patched with adding more options and adding another method of fixing memory holes in SDKs lower than 6.00.

the first method is of flatz's, and it's to set the size of the segment before the memory hole to cover the whole memory hole, by setting it to the difference between the virtual addresses of the segment before the memory hole to the segment after the memory hole.

the new method is to move the segment after the memory hole to right after the segment before the memory hole and its memory size, the bad part is that the references for the old addresses should be changed too, and the script isn't doing that, for this you need the ida segments fixer script.

the new method does however handles the program headers, dynamic section, relocation section, and symbol table.
