# Raw Tar
This is a fork of archive/tar package in Go to expose raw headers of the tar files

# What is new compared to archive/tar ?
The reader expose a `func (tr *Reader) NextRaw() (*Header, *Block, error)` method that also returns the raw tar file headers.

`Block`, `HeaderV7`, `HeaderGNU`, `HeaderSTAR`, `HeaderUSTAR`, `SparseArray`, `SparseElem` are now publicly available