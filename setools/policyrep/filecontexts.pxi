# SPDX-License-Identifier: LGPL-2.1-only

class FileContextsFiletype(PolicyEnum):

    """Enumeration of file types in FileContexts."""

    any = 0
    dir = 1
    chr_file = 2
    blk_file = 3
    sock_file = 4
    fifo_file = 5
    lnk_file = 6
    file = 7


cdef class FileContexts:
    cdef:
        selinux.selabel_handle *handle

        readonly SELinuxPolicy policy
        readonly str path

    def __cinit__(self, policy: SELinuxPolicy | None, fc_path: str | None = None):
        """
        Parameter:
        policy   Policy to use for context lookups. If None, lookup()
                 will return the raw context string.
        fc_path  Path to a file_contexts to open. If not specified, the
                 system's file_contexts will be used.
        """

        cdef selinux.selinux_opt selabel_opt
        if fc_path:
            selabel_opt.type = selinux.SELABEL_OPT_PATH
            selabel_opt.value = fc_path
        else:
            selabel_opt.type = selinux.SELABEL_OPT_UNUSED

        self.handle = selinux.selabel_open(selinux.SELABEL_CTX_FILE, &selabel_opt, 1)
        if self.handle == NULL:
            if errno == ENOMEM:
                PyErr_NoMemory()
            else:
                PyErr_SetFromErrnoWithFilename(OSError, fc_path)

        self.path = fc_path
        self.policy = policy

    def __dealloc__(self):
        if self.handle != NULL:
            selinux.selabel_close(self.handle)

    def lookup(self, path: str, filetype: FileContextsFiletype = FileContextsFiletype.any):
        """Look up a path in the file_contexts."""
        cdef char *ctx
        if selinux.selabel_lookup_raw(self.handle, &ctx, path, filetype.value) < 0:
            if errno == ENOENT:
                raise NoFileContextsMatch(f"\"{path}\" ({filetype}) does not match.")
            else:
                PyErr_SetFromErrno(OSError)

        return self.policy.lookup_context(ctx) if self.policy else ctx
