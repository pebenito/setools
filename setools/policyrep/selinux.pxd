# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

# Directly use libselinux rather than the Python bindings, since
# only a few functions are needed.

cdef extern from "<selinux/selinux.h>":
    bint selinuxfs_exists()
    const char* selinux_current_policy_path()
    const char* selinux_binary_policy_path()
    char* selinux_boolean_sub(const char *boolean_name);

cdef extern from "<selinux/label.h>":
    #
    # selabel_handle
    #
    cdef struct selabel_handle:
        pass

    #
    # struct selinux_opt
    #
    enum:
        SELABEL_OPT_UNUSED
        SELABEL_OPT_VALIDATE
        SELABEL_OPT_DIGEST

    cdef struct selinux_opt:
        int type
        const char *value

    #
    # functions
    #
    enum:
        SELABEL_CTX_FILE
        SELABEL_CTX_MEDIA
        SELABEL_CTX_X
        SELABEL_CTX_DB

    enum:
        SELABEL_OPT_PATH
        SELABEL_OPT_BASEONLY
        SELABEL_OPT_SUBSET

    enum:
        SELABEL_X_PROP
        SELABEL_X_SELN
        SELABEL_X_EXT
        SELABEL_X_EVENT
        SELABEL_X_CLIENT
        SELABEL_X_POLYPROP
        SELABEL_X_POLYSELN

    enum:
        SELABEL_DB_DATABASE
        SELABEL_DB_SCHEMA
        SELABEL_DB_TABLE
        SELABEL_DB_COLUMN
        SELABEL_DB_TUPLE
        SELABEL_DB_PROCEDURE
        SELABEL_DB_SEQUENCE
        SELABEL_DB_BLOB
        SELABEL_DB_VIEW
        SELABEL_DB_LANGUAGE
        SELABEL_DB_EXCEPTION
        SELABEL_DB_DATATYPE

    selabel_handle* selabel_open(unsigned int backend, const selinux_opt * options, unsigned nopt)
    int selabel_lookup_raw(selabel_handle * handle, char ** con, const char * key, int type)
    void selabel_close(selabel_handle *hnd)
