/**
libEtPan! -- a mail stuff library

Copyright (C) 2001 - 2005 - DINH Viet Hoa
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the libEtPan! project nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

This project contains code from sendmail, NetBSD,
RSA Data Security MD5 Message-Digest Algorithm, Cyrus IMAP.

*/
module libetpan;
import std.conv:octal;
import core.stdc.config;
import core.stdc.stdarg: va_list;
import std.string;

struct __locale_data { int dummy; }

alias _Bool = bool;

extern(C)
{
    struct struct_mailstream_cancel;
    union sigval
    {
        int sival_int;
        void* sival_ptr;
    }
    struct _Anonymous_1
    {
        c_ulong[16] __val;
    }
    alias __sigset_t = _Anonymous_1;


    alias __FILE = _IO_FILE;






    alias time_t = c_long;
    struct tm
    {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        c_long tm_gmtoff;
        const(char)* tm_zone;
    }
    alias sigset_t = __sigset_t;
    alias timer_t = void*;
    alias clockid_t = int;
    alias clock_t = c_long;


    alias FILE = _IO_FILE;


    struct timeval
    {
        __time_t tv_sec;
        __suseconds_t tv_usec;
    }
    struct itimerspec
    {
        timespec it_interval;
        timespec it_value;
    }




    alias sig_atomic_t = int;


    struct timespec
    {
        __time_t tv_sec;
        __syscall_slong_t tv_nsec;
    }
    alias sigval_t = sigval;






    alias __mbstate_t = _Anonymous_2;
    struct _Anonymous_2
    {
        int __count;
        union _Anonymous_3
        {
            uint __wch;
            char[4] __wchb;
        }
        _Anonymous_3 __value;
    }
    struct sigevent
    {
        sigval_t sigev_value;
        int sigev_signo;
        int sigev_notify;
        union _Anonymous_4
        {
            int[12] _pad;
            __pid_t _tid;
            struct _Anonymous_5
            {
                void function(sigval) _function;
                pthread_attr_t* _attribute;
            }
            _Anonymous_5 _sigev_thread;
        }
        _Anonymous_4 _sigev_un;
    }
    alias sigevent_t = sigevent;
    struct _Anonymous_6
    {
        __off_t __pos;
        __mbstate_t __state;
    }


    alias _G_fpos_t = _Anonymous_6;
    struct sigstack
    {
        void* ss_sp;
        int ss_onstack;
    }




    alias uint8_t = ubyte;


    alias int8_t = byte;
    struct sigaction
    {
        union _Anonymous_7
        {
            __sighandler_t sa_handler;
            void function(int, siginfo_t*, void*) sa_sigaction;
        }
        _Anonymous_7 __sigaction_handler;
        __sigset_t sa_mask;
        int sa_flags;
        void function() sa_restorer;
    }
    alias locale_t = __locale_struct*;
    alias int16_t = short;


    alias uint16_t = ushort;
    alias uint32_t = uint;
    alias stack_t = _Anonymous_8;


    extern __gshared int sys_nerr;
    alias int32_t = int;
    struct _Anonymous_8
    {
        void* ss_sp;
        int ss_flags;
        size_t ss_size;
    }


    alias _G_fpos64_t = _Anonymous_9;
    struct _Anonymous_9
    {
        __off64_t __pos;
        __mbstate_t __state;
    }


    enum _Anonymous_10
    {
        SIGEV_SIGNAL = 0,
        SIGEV_NONE = 1,
        SIGEV_THREAD = 2,
        SIGEV_THREAD_ID = 4,
    }
    enum SIGEV_SIGNAL = _Anonymous_10.SIGEV_SIGNAL;
    enum SIGEV_NONE = _Anonymous_10.SIGEV_NONE;
    enum SIGEV_THREAD = _Anonymous_10.SIGEV_THREAD;
    enum SIGEV_THREAD_ID = _Anonymous_10.SIGEV_THREAD_ID;
    enum _Anonymous_11
    {
        SS_ONSTACK = 1,
        SS_DISABLE = 2,
    }
    enum SS_ONSTACK = _Anonymous_11.SS_ONSTACK;
    enum SS_DISABLE = _Anonymous_11.SS_DISABLE;
    alias int64_t = c_long;




    alias uint64_t = c_ulong;


    alias pthread_t = c_ulong;
    extern __gshared const(const(char)*)[0] sys_errlist;


    struct __locale_struct
    {
        __locale_data*[13] __locales;
        const(ushort)* __ctype_b;
        const(int)* __ctype_tolower;
        const(int)* __ctype_toupper;
        const(char)*[13] __names;
    }
    alias __u_char = ubyte;
    alias __u_short = ushort;







    int pthread_sigmask(int, const(__sigset_t)*, __sigset_t*, );
    struct _fpx_sw_bytes
    {
        __uint32_t magic1;
        __uint32_t extended_size;
        __uint64_t xstate_bv;
        __uint32_t xstate_size;
        __uint32_t[7] __glibc_reserved1;
    }
    __uint16_t __uint16_identity(__uint16_t, );


    alias __u_int = uint;


    alias pthread_mutexattr_t = _Anonymous_12;
    union _Anonymous_12
    {
        char[4] __size;
        int __align;
    }
    alias u_char = ubyte;
    alias __u_long = c_ulong;
    alias __gwchar_t = int;




    alias u_short = ushort;
    enum _Anonymous_13
    {
        SI_ASYNCNL = -60,
        SI_TKILL = -6,
        SI_SIGIO = -5,
        SI_ASYNCIO = -4,
        SI_MESGQ = -3,
        SI_TIMER = -2,
        SI_QUEUE = -1,
        SI_USER = 0,
        SI_KERNEL = 128,
    }
    enum SI_ASYNCNL = _Anonymous_13.SI_ASYNCNL;
    enum SI_TKILL = _Anonymous_13.SI_TKILL;
    enum SI_SIGIO = _Anonymous_13.SI_SIGIO;
    enum SI_ASYNCIO = _Anonymous_13.SI_ASYNCIO;
    enum SI_MESGQ = _Anonymous_13.SI_MESGQ;
    enum SI_TIMER = _Anonymous_13.SI_TIMER;
    enum SI_QUEUE = _Anonymous_13.SI_QUEUE;
    enum SI_USER = _Anonymous_13.SI_USER;
    enum SI_KERNEL = _Anonymous_13.SI_KERNEL;


    alias u_int = uint;
    alias u_long = c_ulong;
    int pthread_kill(pthread_t, int, );


    alias __int8_t = byte;
    alias siginfo_t = _Anonymous_14;
    struct _Anonymous_14
    {
        int si_signo;
        int si_errno;
        int si_code;
        int __pad0;
        union _Anonymous_15
        {
            int[28] _pad;
            struct _Anonymous_16
            {
                __pid_t si_pid;
                __uid_t si_uid;
            }
            _Anonymous_16 _kill;
            struct _Anonymous_17
            {
                int si_tid;
                int si_overrun;
                sigval_t si_sigval;
            }
            _Anonymous_17 _timer;
            struct _Anonymous_18
            {
                __pid_t si_pid;
                __uid_t si_uid;
                sigval_t si_sigval;
            }
            _Anonymous_18 _rt;
            struct _Anonymous_19
            {
                __pid_t si_pid;
                __uid_t si_uid;
                int si_status;
                __clock_t si_utime;
                __clock_t si_stime;
            }
            _Anonymous_19 _sigchld;
            struct _Anonymous_20
            {
                void* si_addr;
                short si_addr_lsb;
                union _Anonymous_21
                {
                    struct _Anonymous_22
                    {
                        void* _lower;
                        void* _upper;
                    }
                    _Anonymous_22 _addr_bnd;
                    __uint32_t _pkey;
                }
                _Anonymous_21 _bounds;
            }
            _Anonymous_20 _sigfault;
            struct _Anonymous_23
            {
                c_long si_band;
                int si_fd;
            }
            _Anonymous_23 _sigpoll;
            struct _Anonymous_24
            {
                void* _call_addr;
                int _syscall;
                uint _arch;
            }
            _Anonymous_24 _sigsys;
        }
        _Anonymous_15 _sifields;
    }
    alias quad_t = c_long;


    alias greg_t = long;
    newsfeed_item_enclosure* newsfeed_item_enclosure_new();




    alias __uint8_t = ubyte;
    enum _Anonymous_25
    {
        MAILIMAP_NAMESPACE_TYPE_NAMESPACE = 0,
    }
    enum MAILIMAP_NAMESPACE_TYPE_NAMESPACE = _Anonymous_25.MAILIMAP_NAMESPACE_TYPE_NAMESPACE;
    __uint32_t __uint32_identity(__uint32_t, );
    alias u_quad_t = c_ulong;
    enum _Anonymous_26
    {
        NEWSFEED_NO_ERROR = 0,
        NEWSFEED_ERROR_CANCELLED = 1,
        NEWSFEED_ERROR_INTERNAL = 2,
        NEWSFEED_ERROR_BADURL = 3,
        NEWSFEED_ERROR_RESOLVE_PROXY = 4,
        NEWSFEED_ERROR_RESOLVE_HOST = 5,
        NEWSFEED_ERROR_CONNECT = 6,
        NEWSFEED_ERROR_STREAM = 7,
        NEWSFEED_ERROR_PROTOCOL = 8,
        NEWSFEED_ERROR_PARSE = 9,
        NEWSFEED_ERROR_ACCESS = 10,
        NEWSFEED_ERROR_AUTHENTICATION = 11,
        NEWSFEED_ERROR_FTP = 12,
        NEWSFEED_ERROR_PARTIAL_FILE = 13,
        NEWSFEED_ERROR_FETCH = 14,
        NEWSFEED_ERROR_HTTP = 15,
        NEWSFEED_ERROR_FILE = 16,
        NEWSFEED_ERROR_PUT = 17,
        NEWSFEED_ERROR_MEMORY = 18,
        NEWSFEED_ERROR_SSL = 19,
        NEWSFEED_ERROR_LDAP = 20,
        NEWSFEED_ERROR_UNSUPPORTED_PROTOCOL = 21,
    }
    enum NEWSFEED_NO_ERROR = _Anonymous_26.NEWSFEED_NO_ERROR;
    enum NEWSFEED_ERROR_CANCELLED = _Anonymous_26.NEWSFEED_ERROR_CANCELLED;
    enum NEWSFEED_ERROR_INTERNAL = _Anonymous_26.NEWSFEED_ERROR_INTERNAL;
    enum NEWSFEED_ERROR_BADURL = _Anonymous_26.NEWSFEED_ERROR_BADURL;
    enum NEWSFEED_ERROR_RESOLVE_PROXY = _Anonymous_26.NEWSFEED_ERROR_RESOLVE_PROXY;
    enum NEWSFEED_ERROR_RESOLVE_HOST = _Anonymous_26.NEWSFEED_ERROR_RESOLVE_HOST;
    enum NEWSFEED_ERROR_CONNECT = _Anonymous_26.NEWSFEED_ERROR_CONNECT;
    enum NEWSFEED_ERROR_STREAM = _Anonymous_26.NEWSFEED_ERROR_STREAM;
    enum NEWSFEED_ERROR_PROTOCOL = _Anonymous_26.NEWSFEED_ERROR_PROTOCOL;
    enum NEWSFEED_ERROR_PARSE = _Anonymous_26.NEWSFEED_ERROR_PARSE;
    enum NEWSFEED_ERROR_ACCESS = _Anonymous_26.NEWSFEED_ERROR_ACCESS;
    enum NEWSFEED_ERROR_AUTHENTICATION = _Anonymous_26.NEWSFEED_ERROR_AUTHENTICATION;
    enum NEWSFEED_ERROR_FTP = _Anonymous_26.NEWSFEED_ERROR_FTP;
    enum NEWSFEED_ERROR_PARTIAL_FILE = _Anonymous_26.NEWSFEED_ERROR_PARTIAL_FILE;
    enum NEWSFEED_ERROR_FETCH = _Anonymous_26.NEWSFEED_ERROR_FETCH;
    enum NEWSFEED_ERROR_HTTP = _Anonymous_26.NEWSFEED_ERROR_HTTP;
    enum NEWSFEED_ERROR_FILE = _Anonymous_26.NEWSFEED_ERROR_FILE;
    enum NEWSFEED_ERROR_PUT = _Anonymous_26.NEWSFEED_ERROR_PUT;
    enum NEWSFEED_ERROR_MEMORY = _Anonymous_26.NEWSFEED_ERROR_MEMORY;
    enum NEWSFEED_ERROR_SSL = _Anonymous_26.NEWSFEED_ERROR_SSL;
    enum NEWSFEED_ERROR_LDAP = _Anonymous_26.NEWSFEED_ERROR_LDAP;
    enum NEWSFEED_ERROR_UNSUPPORTED_PROTOCOL = _Anonymous_26.NEWSFEED_ERROR_UNSUPPORTED_PROTOCOL;
    newsfeed_item* newsfeed_item_new(newsfeed*, );
    enum _Anonymous_27
    {
        MAILIMAP_CONDSTORE_TYPE_FETCH_DATA = 0,
        MAILIMAP_CONDSTORE_TYPE_RESP_TEXT_CODE = 1,
        MAILIMAP_CONDSTORE_TYPE_SEARCH_DATA = 2,
        MAILIMAP_CONDSTORE_TYPE_STATUS_INFO = 3,
    }
    enum MAILIMAP_CONDSTORE_TYPE_FETCH_DATA = _Anonymous_27.MAILIMAP_CONDSTORE_TYPE_FETCH_DATA;
    enum MAILIMAP_CONDSTORE_TYPE_RESP_TEXT_CODE = _Anonymous_27.MAILIMAP_CONDSTORE_TYPE_RESP_TEXT_CODE;
    enum MAILIMAP_CONDSTORE_TYPE_SEARCH_DATA = _Anonymous_27.MAILIMAP_CONDSTORE_TYPE_SEARCH_DATA;
    enum MAILIMAP_CONDSTORE_TYPE_STATUS_INFO = _Anonymous_27.MAILIMAP_CONDSTORE_TYPE_STATUS_INFO;
    enum _Anonymous_28
    {
        MAILIMAP_QRESYNC_TYPE_VANISHED = 0,
        MAILIMAP_QRESYNC_TYPE_RESP_TEXT_CODE = 1,
    }
    enum MAILIMAP_QRESYNC_TYPE_VANISHED = _Anonymous_28.MAILIMAP_QRESYNC_TYPE_VANISHED;
    enum MAILIMAP_QRESYNC_TYPE_RESP_TEXT_CODE = _Anonymous_28.MAILIMAP_QRESYNC_TYPE_RESP_TEXT_CODE;






    void newsfeed_item_enclosure_free(newsfeed_item_enclosure*, );


    alias __int16_t = short;
    int mailsmtp_oauth2_authenticate(mailsmtp*, const(char)*, const(char)*, );
    alias __uint16_t = ushort;
    alias fsid_t = __fsid_t;
    void newsfeed_item_free(newsfeed_item*, );
    newsfeed* newsfeed_new();
    enum _Anonymous_29
    {
        MAIL_NO_ERROR = 0,
        MAIL_NO_ERROR_AUTHENTICATED = 1,
        MAIL_NO_ERROR_NON_AUTHENTICATED = 2,
        MAIL_ERROR_NOT_IMPLEMENTED = 3,
        MAIL_ERROR_UNKNOWN = 4,
        MAIL_ERROR_CONNECT = 5,
        MAIL_ERROR_BAD_STATE = 6,
        MAIL_ERROR_FILE = 7,
        MAIL_ERROR_STREAM = 8,
        MAIL_ERROR_LOGIN = 9,
        MAIL_ERROR_CREATE = 10,
        MAIL_ERROR_DELETE = 11,
        MAIL_ERROR_LOGOUT = 12,
        MAIL_ERROR_NOOP = 13,
        MAIL_ERROR_RENAME = 14,
        MAIL_ERROR_CHECK = 15,
        MAIL_ERROR_EXAMINE = 16,
        MAIL_ERROR_SELECT = 17,
        MAIL_ERROR_MEMORY = 18,
        MAIL_ERROR_STATUS = 19,
        MAIL_ERROR_SUBSCRIBE = 20,
        MAIL_ERROR_UNSUBSCRIBE = 21,
        MAIL_ERROR_LIST = 22,
        MAIL_ERROR_LSUB = 23,
        MAIL_ERROR_APPEND = 24,
        MAIL_ERROR_COPY = 25,
        MAIL_ERROR_FETCH = 26,
        MAIL_ERROR_STORE = 27,
        MAIL_ERROR_SEARCH = 28,
        MAIL_ERROR_DISKSPACE = 29,
        MAIL_ERROR_MSG_NOT_FOUND = 30,
        MAIL_ERROR_PARSE = 31,
        MAIL_ERROR_INVAL = 32,
        MAIL_ERROR_PART_NOT_FOUND = 33,
        MAIL_ERROR_REMOVE = 34,
        MAIL_ERROR_FOLDER_NOT_FOUND = 35,
        MAIL_ERROR_MOVE = 36,
        MAIL_ERROR_STARTTLS = 37,
        MAIL_ERROR_CACHE_MISS = 38,
        MAIL_ERROR_NO_TLS = 39,
        MAIL_ERROR_EXPUNGE = 40,
        MAIL_ERROR_MISC = 41,
        MAIL_ERROR_PROTOCOL = 42,
        MAIL_ERROR_CAPABILITY = 43,
        MAIL_ERROR_CLOSE = 44,
        MAIL_ERROR_FATAL = 45,
        MAIL_ERROR_READONLY = 46,
        MAIL_ERROR_NO_APOP = 47,
        MAIL_ERROR_COMMAND_NOT_SUPPORTED = 48,
        MAIL_ERROR_NO_PERMISSION = 49,
        MAIL_ERROR_PROGRAM_ERROR = 50,
        MAIL_ERROR_SUBJECT_NOT_FOUND = 51,
        MAIL_ERROR_CHAR_ENCODING_FAILED = 52,
        MAIL_ERROR_SEND = 53,
        MAIL_ERROR_COMMAND = 54,
        MAIL_ERROR_SYSTEM = 55,
        MAIL_ERROR_UNABLE = 56,
        MAIL_ERROR_FOLDER = 57,
        MAIL_ERROR_SSL = 58,
    }
    enum MAIL_NO_ERROR = _Anonymous_29.MAIL_NO_ERROR;
    enum MAIL_NO_ERROR_AUTHENTICATED = _Anonymous_29.MAIL_NO_ERROR_AUTHENTICATED;
    enum MAIL_NO_ERROR_NON_AUTHENTICATED = _Anonymous_29.MAIL_NO_ERROR_NON_AUTHENTICATED;
    enum MAIL_ERROR_NOT_IMPLEMENTED = _Anonymous_29.MAIL_ERROR_NOT_IMPLEMENTED;
    enum MAIL_ERROR_UNKNOWN = _Anonymous_29.MAIL_ERROR_UNKNOWN;
    enum MAIL_ERROR_CONNECT = _Anonymous_29.MAIL_ERROR_CONNECT;
    enum MAIL_ERROR_BAD_STATE = _Anonymous_29.MAIL_ERROR_BAD_STATE;
    enum MAIL_ERROR_FILE = _Anonymous_29.MAIL_ERROR_FILE;
    enum MAIL_ERROR_STREAM = _Anonymous_29.MAIL_ERROR_STREAM;
    enum MAIL_ERROR_LOGIN = _Anonymous_29.MAIL_ERROR_LOGIN;
    enum MAIL_ERROR_CREATE = _Anonymous_29.MAIL_ERROR_CREATE;
    enum MAIL_ERROR_DELETE = _Anonymous_29.MAIL_ERROR_DELETE;
    enum MAIL_ERROR_LOGOUT = _Anonymous_29.MAIL_ERROR_LOGOUT;
    enum MAIL_ERROR_NOOP = _Anonymous_29.MAIL_ERROR_NOOP;
    enum MAIL_ERROR_RENAME = _Anonymous_29.MAIL_ERROR_RENAME;
    enum MAIL_ERROR_CHECK = _Anonymous_29.MAIL_ERROR_CHECK;
    enum MAIL_ERROR_EXAMINE = _Anonymous_29.MAIL_ERROR_EXAMINE;
    enum MAIL_ERROR_SELECT = _Anonymous_29.MAIL_ERROR_SELECT;
    enum MAIL_ERROR_MEMORY = _Anonymous_29.MAIL_ERROR_MEMORY;
    enum MAIL_ERROR_STATUS = _Anonymous_29.MAIL_ERROR_STATUS;
    enum MAIL_ERROR_SUBSCRIBE = _Anonymous_29.MAIL_ERROR_SUBSCRIBE;
    enum MAIL_ERROR_UNSUBSCRIBE = _Anonymous_29.MAIL_ERROR_UNSUBSCRIBE;
    enum MAIL_ERROR_LIST = _Anonymous_29.MAIL_ERROR_LIST;
    enum MAIL_ERROR_LSUB = _Anonymous_29.MAIL_ERROR_LSUB;
    enum MAIL_ERROR_APPEND = _Anonymous_29.MAIL_ERROR_APPEND;
    enum MAIL_ERROR_COPY = _Anonymous_29.MAIL_ERROR_COPY;
    enum MAIL_ERROR_FETCH = _Anonymous_29.MAIL_ERROR_FETCH;
    enum MAIL_ERROR_STORE = _Anonymous_29.MAIL_ERROR_STORE;
    enum MAIL_ERROR_SEARCH = _Anonymous_29.MAIL_ERROR_SEARCH;
    enum MAIL_ERROR_DISKSPACE = _Anonymous_29.MAIL_ERROR_DISKSPACE;
    enum MAIL_ERROR_MSG_NOT_FOUND = _Anonymous_29.MAIL_ERROR_MSG_NOT_FOUND;
    enum MAIL_ERROR_PARSE = _Anonymous_29.MAIL_ERROR_PARSE;
    enum MAIL_ERROR_INVAL = _Anonymous_29.MAIL_ERROR_INVAL;
    enum MAIL_ERROR_PART_NOT_FOUND = _Anonymous_29.MAIL_ERROR_PART_NOT_FOUND;
    enum MAIL_ERROR_REMOVE = _Anonymous_29.MAIL_ERROR_REMOVE;
    enum MAIL_ERROR_FOLDER_NOT_FOUND = _Anonymous_29.MAIL_ERROR_FOLDER_NOT_FOUND;
    enum MAIL_ERROR_MOVE = _Anonymous_29.MAIL_ERROR_MOVE;
    enum MAIL_ERROR_STARTTLS = _Anonymous_29.MAIL_ERROR_STARTTLS;
    enum MAIL_ERROR_CACHE_MISS = _Anonymous_29.MAIL_ERROR_CACHE_MISS;
    enum MAIL_ERROR_NO_TLS = _Anonymous_29.MAIL_ERROR_NO_TLS;
    enum MAIL_ERROR_EXPUNGE = _Anonymous_29.MAIL_ERROR_EXPUNGE;
    enum MAIL_ERROR_MISC = _Anonymous_29.MAIL_ERROR_MISC;
    enum MAIL_ERROR_PROTOCOL = _Anonymous_29.MAIL_ERROR_PROTOCOL;
    enum MAIL_ERROR_CAPABILITY = _Anonymous_29.MAIL_ERROR_CAPABILITY;
    enum MAIL_ERROR_CLOSE = _Anonymous_29.MAIL_ERROR_CLOSE;
    enum MAIL_ERROR_FATAL = _Anonymous_29.MAIL_ERROR_FATAL;
    enum MAIL_ERROR_READONLY = _Anonymous_29.MAIL_ERROR_READONLY;
    enum MAIL_ERROR_NO_APOP = _Anonymous_29.MAIL_ERROR_NO_APOP;
    enum MAIL_ERROR_COMMAND_NOT_SUPPORTED = _Anonymous_29.MAIL_ERROR_COMMAND_NOT_SUPPORTED;
    enum MAIL_ERROR_NO_PERMISSION = _Anonymous_29.MAIL_ERROR_NO_PERMISSION;
    enum MAIL_ERROR_PROGRAM_ERROR = _Anonymous_29.MAIL_ERROR_PROGRAM_ERROR;
    enum MAIL_ERROR_SUBJECT_NOT_FOUND = _Anonymous_29.MAIL_ERROR_SUBJECT_NOT_FOUND;
    enum MAIL_ERROR_CHAR_ENCODING_FAILED = _Anonymous_29.MAIL_ERROR_CHAR_ENCODING_FAILED;
    enum MAIL_ERROR_SEND = _Anonymous_29.MAIL_ERROR_SEND;
    enum MAIL_ERROR_COMMAND = _Anonymous_29.MAIL_ERROR_COMMAND;
    enum MAIL_ERROR_SYSTEM = _Anonymous_29.MAIL_ERROR_SYSTEM;
    enum MAIL_ERROR_UNABLE = _Anonymous_29.MAIL_ERROR_UNABLE;
    enum MAIL_ERROR_FOLDER = _Anonymous_29.MAIL_ERROR_FOLDER;
    enum MAIL_ERROR_SSL = _Anonymous_29.MAIL_ERROR_SSL;
    char* newsfeed_item_enclosure_get_url(newsfeed_item_enclosure*, );




    alias __int32_t = int;
    struct _fpreg
    {
        ushort[4] significand;
        ushort exponent;
    }




    alias __uint32_t = uint;
    struct mailimap_id_params_list
    {
        clist* idpa_list;
    }


    void newsfeed_free(newsfeed*, );


    int newsfeed_item_enclosure_set_url(newsfeed_item_enclosure*, const(char)*, );


    newsfeed* newsfeed_item_get_feed(newsfeed_item*, );
    union _Anonymous_30
    {
        char[4] __size;
        int __align;
    }
    alias pthread_condattr_t = _Anonymous_30;






    struct mailsem
    {
        void* sem_sem;
        int sem_kind;
    }


    struct mailimap_namespace_response_extension
    {
        char* ns_name;
        clist* ns_values;
    }
    alias __locale_t = __locale_struct*;




    extern __gshared mailimap_extension_api mailimap_extension_qresync;
    struct mailimap_msg_att_xgmlabels
    {
        clist* att_labels;
    }
    extern __gshared mailimap_extension_api mailimap_extension_xgmmsgid;


    int mailimap_idle(mailimap*, );
    int mailsmtp_oauth2_outlook_authenticate(mailsmtp*, const(char)*, const(char)*, );
    maildir* maildir_new(const(char)*, );
    extern __gshared mailimap_extension_api mailimap_extension_xgmthrid;


    alias __int64_t = c_long;
    int mailfolder_noop(mailfolder*, );
    alias suseconds_t = c_long;
    alias int_least8_t = byte;


    int mailprivacy_smime_init(mailprivacy*, );
    int newsfeed_get_response_code(newsfeed*, );
    extern __gshared mailimap_extension_api mailimap_extension_enable;
    int mailprivacy_gnupg_init(mailprivacy*, );


    const(char)* newsfeed_item_get_url(newsfeed_item*, );


    struct mailimap_qresync_vanished
    {
        int qr_earlier;
        mailimap_set* qr_known_uids;
    }
    int maillock_read_lock(const(char)*, int, );
    __uint64_t __uint64_identity(__uint64_t, );
    alias int_least16_t = short;
    extern __gshared mailimap_extension_api mailimap_extension_id;


    enum _Anonymous_31
    {
        MAILIMAP_EXTENSION_ANNOTATEMORE = 0,
        MAILIMAP_EXTENSION_ACL = 1,
        MAILIMAP_EXTENSION_UIDPLUS = 2,
        MAILIMAP_EXTENSION_QUOTA = 3,
        MAILIMAP_EXTENSION_NAMESPACE = 4,
        MAILIMAP_EXTENSION_XLIST = 5,
        MAILIMAP_EXTENSION_XGMLABELS = 6,
        MAILIMAP_EXTENSION_XGMMSGID = 7,
        MAILIMAP_EXTENSION_XGMTHRID = 8,
        MAILIMAP_EXTENSION_ID = 9,
        MAILIMAP_EXTENSION_ENABLE = 10,
        MAILIMAP_EXTENSION_CONDSTORE = 11,
        MAILIMAP_EXTENSION_QRESYNC = 12,
        MAILIMAP_EXTENSION_SORT = 13,
    }
    enum MAILIMAP_EXTENSION_ANNOTATEMORE = _Anonymous_31.MAILIMAP_EXTENSION_ANNOTATEMORE;
    enum MAILIMAP_EXTENSION_ACL = _Anonymous_31.MAILIMAP_EXTENSION_ACL;
    enum MAILIMAP_EXTENSION_UIDPLUS = _Anonymous_31.MAILIMAP_EXTENSION_UIDPLUS;
    enum MAILIMAP_EXTENSION_QUOTA = _Anonymous_31.MAILIMAP_EXTENSION_QUOTA;
    enum MAILIMAP_EXTENSION_NAMESPACE = _Anonymous_31.MAILIMAP_EXTENSION_NAMESPACE;
    enum MAILIMAP_EXTENSION_XLIST = _Anonymous_31.MAILIMAP_EXTENSION_XLIST;
    enum MAILIMAP_EXTENSION_XGMLABELS = _Anonymous_31.MAILIMAP_EXTENSION_XGMLABELS;
    enum MAILIMAP_EXTENSION_XGMMSGID = _Anonymous_31.MAILIMAP_EXTENSION_XGMMSGID;
    enum MAILIMAP_EXTENSION_XGMTHRID = _Anonymous_31.MAILIMAP_EXTENSION_XGMTHRID;
    enum MAILIMAP_EXTENSION_ID = _Anonymous_31.MAILIMAP_EXTENSION_ID;
    enum MAILIMAP_EXTENSION_ENABLE = _Anonymous_31.MAILIMAP_EXTENSION_ENABLE;
    enum MAILIMAP_EXTENSION_CONDSTORE = _Anonymous_31.MAILIMAP_EXTENSION_CONDSTORE;
    enum MAILIMAP_EXTENSION_QRESYNC = _Anonymous_31.MAILIMAP_EXTENSION_QRESYNC;
    enum MAILIMAP_EXTENSION_SORT = _Anonymous_31.MAILIMAP_EXTENSION_SORT;


    void mailprivacy_mime_clear(mailmime*, );
    char* newsfeed_item_enclosure_get_type(newsfeed_item_enclosure*, );
    int newsfeed_item_set_url(newsfeed_item*, const(char)*, );


    extern __gshared mailimap_extension_api mailimap_extension_uidplus;
    extern __gshared mailmessage_driver* mime_message_driver;
    void maildir_free(maildir*, );


    extern __gshared mailimap_extension_api mailimap_extension_xlist;


    extern __gshared mailimap_extension_api mailimap_extension_sort;
    alias __uint64_t = c_ulong;
    extern __gshared int mailstream_cfstream_enabled;
    struct mailimap_quota_quota_resource
    {
        char* resource_name;
        uint32_t usage;
        uint32_t limit;
    }


    alias loff_t = c_long;


    mailprivacy* mailprivacy_new(char*, int, );


    int maillock_read_unlock(const(char)*, int, );
    extern __gshared mailimap_extension_api mailimap_extension_namespace;




    mailimap_fetch_att* mailimap_fetch_att_new_xgmthrid();
    mailimap_fetch_att* mailimap_fetch_att_new_xgmmsgid();
    int mailimap_idle_done(mailimap*, );
    enum _Anonymous_32
    {
        MAILIMAP_UIDPLUS_RESP_CODE_APND = 0,
        MAILIMAP_UIDPLUS_RESP_CODE_COPY = 1,
        MAILIMAP_UIDPLUS_RESP_CODE_UIDNOTSTICKY = 2,
    }
    enum MAILIMAP_UIDPLUS_RESP_CODE_APND = _Anonymous_32.MAILIMAP_UIDPLUS_RESP_CODE_APND;
    enum MAILIMAP_UIDPLUS_RESP_CODE_COPY = _Anonymous_32.MAILIMAP_UIDPLUS_RESP_CODE_COPY;
    enum MAILIMAP_UIDPLUS_RESP_CODE_UIDNOTSTICKY = _Anonymous_32.MAILIMAP_UIDPLUS_RESP_CODE_UIDNOTSTICKY;
    struct mailprivacy
    {
        char* tmp_dir;
        chash* msg_ref;
        chash* mmapstr;
        chash* mime_ref;
        carray* protocols;
        int make_alternative;
    }
    extern __gshared mailimap_extension_api mailimap_extension_quota;


    struct mailimap_condstore_fetch_mod_resp
    {
        uint64_t cs_modseq_value;
    }


    extern __gshared mailimap_extension_api mailimap_extension_condstore;
    extern __gshared mailimap_extension_api mailimap_extension_annotatemore;
    alias int_least32_t = int;
    int newsfeed_set_url(newsfeed*, const(char)*, );






    int newsfeed_item_enclosure_set_type(newsfeed_item_enclosure*, const(char)*, );
    extern __gshared mailmessage_driver* mbox_cached_message_driver;
    extern __gshared mailmessage_driver* mh_cached_message_driver;
    extern __gshared mailsession_driver* mbox_session_driver;
    void mailprivacy_gnupg_done(mailprivacy*, );
    extern __gshared mailmessage_driver* mbox_message_driver;
    int maillock_write_lock(const(char)*, int, );
    int mailmime_disposition_parse(const(char)*, size_t, size_t*, mailmime_disposition**, );
    int mailpop3_login_apop(mailpop3*, const(char)*, const(char)*, );
    void mailprivacy_smime_done(mailprivacy*, );
    int mailmbox_append_message_list(mailmbox_folder*, carray*, );
    extern __gshared mailsession_driver* mh_session_driver;
    extern __gshared mailsession_driver* mh_cached_session_driver;
    mailmessage* mime_message_init(mailmime*, );
    extern __gshared mailsession_driver* nntp_cached_session_driver;
    extern __gshared mailmessage_driver* nntp_cached_message_driver;
    extern __gshared mailmessage_driver* nntp_message_driver;
    extern __gshared mailsession_driver* pop3_session_driver;
    extern __gshared mailsession_driver* pop3_cached_session_driver;
    extern __gshared mailmessage_driver* pop3_cached_message_driver;
    extern __gshared mailmessage_driver* pop3_message_driver;
    int mailfolder_check(mailfolder*, );


    struct _fpxreg
    {
        ushort[4] significand;
        ushort exponent;
        ushort[3] __glibc_reserved1;
    }
    extern __gshared mailmessage_driver* maildir_message_driver;
    extern __gshared mailmessage_driver* maildir_cached_message_driver;
    int maildir_update(maildir*, );


    extern __gshared mailsession_driver* nntp_session_driver;
    extern __gshared mailmessage_driver* imap_message_driver;
    extern __gshared mailsession_driver* imap_cached_session_driver;
    extern __gshared mailsession_driver* imap_session_driver;
    extern __gshared mailmessage_driver* feed_message_driver;
    extern __gshared mailsession_driver* feed_session_driver;
    int mailimap_enable(mailimap*, mailimap_capability_data*, mailimap_capability_data**, );
    extern __gshared mailmessage_driver* db_message_driver;
    alias gregset_t = long[23];
    extern __gshared mailmessage_driver* imap_cached_message_driver;
    extern __gshared mailmessage_driver* mh_message_driver;
    mailimap_id_params_list* mailimap_id_params_list_new(clist*, );
    const(char)* newsfeed_get_url(newsfeed*, );
    const(char)* newsfeed_item_get_title(newsfeed_item*, );


    extern __gshared mailimap_extension_api mailimap_extension_xgmlabels;
    int mailimap_has_id(mailimap*, );
    int mailmime_fields_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailmime_fields*, );
    int mailimap_fetch_rfc822(mailimap*, uint32_t, char**, );


    int newsfeed_item_set_title(newsfeed_item*, const(char)*, );
    int hotmail_mailstorage_init(mailstorage*, char*, char*, int, char*, char*, );
    extern __gshared mailsession_driver* maildir_cached_session_driver;
    enum _Anonymous_33
    {
        MAILSMTP_NO_ERROR = 0,
        MAILSMTP_ERROR_UNEXPECTED_CODE = 1,
        MAILSMTP_ERROR_SERVICE_NOT_AVAILABLE = 2,
        MAILSMTP_ERROR_STREAM = 3,
        MAILSMTP_ERROR_HOSTNAME = 4,
        MAILSMTP_ERROR_NOT_IMPLEMENTED = 5,
        MAILSMTP_ERROR_ACTION_NOT_TAKEN = 6,
        MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION = 7,
        MAILSMTP_ERROR_IN_PROCESSING = 8,
        MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE = 9,
        MAILSMTP_ERROR_MAILBOX_UNAVAILABLE = 10,
        MAILSMTP_ERROR_MAILBOX_NAME_NOT_ALLOWED = 11,
        MAILSMTP_ERROR_BAD_SEQUENCE_OF_COMMAND = 12,
        MAILSMTP_ERROR_USER_NOT_LOCAL = 13,
        MAILSMTP_ERROR_TRANSACTION_FAILED = 14,
        MAILSMTP_ERROR_MEMORY = 15,
        MAILSMTP_ERROR_AUTH_NOT_SUPPORTED = 16,
        MAILSMTP_ERROR_AUTH_LOGIN = 17,
        MAILSMTP_ERROR_AUTH_REQUIRED = 18,
        MAILSMTP_ERROR_AUTH_TOO_WEAK = 19,
        MAILSMTP_ERROR_AUTH_TRANSITION_NEEDED = 20,
        MAILSMTP_ERROR_AUTH_TEMPORARY_FAILTURE = 21,
        MAILSMTP_ERROR_AUTH_ENCRYPTION_REQUIRED = 22,
        MAILSMTP_ERROR_STARTTLS_TEMPORARY_FAILURE = 23,
        MAILSMTP_ERROR_STARTTLS_NOT_SUPPORTED = 24,
        MAILSMTP_ERROR_CONNECTION_REFUSED = 25,
        MAILSMTP_ERROR_AUTH_AUTHENTICATION_FAILED = 26,
        MAILSMTP_ERROR_SSL = 27,
    }
    enum MAILSMTP_NO_ERROR = _Anonymous_33.MAILSMTP_NO_ERROR;
    enum MAILSMTP_ERROR_UNEXPECTED_CODE = _Anonymous_33.MAILSMTP_ERROR_UNEXPECTED_CODE;
    enum MAILSMTP_ERROR_SERVICE_NOT_AVAILABLE = _Anonymous_33.MAILSMTP_ERROR_SERVICE_NOT_AVAILABLE;
    enum MAILSMTP_ERROR_STREAM = _Anonymous_33.MAILSMTP_ERROR_STREAM;
    enum MAILSMTP_ERROR_HOSTNAME = _Anonymous_33.MAILSMTP_ERROR_HOSTNAME;
    enum MAILSMTP_ERROR_NOT_IMPLEMENTED = _Anonymous_33.MAILSMTP_ERROR_NOT_IMPLEMENTED;
    enum MAILSMTP_ERROR_ACTION_NOT_TAKEN = _Anonymous_33.MAILSMTP_ERROR_ACTION_NOT_TAKEN;
    enum MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION = _Anonymous_33.MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION;
    enum MAILSMTP_ERROR_IN_PROCESSING = _Anonymous_33.MAILSMTP_ERROR_IN_PROCESSING;
    enum MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE = _Anonymous_33.MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE;
    enum MAILSMTP_ERROR_MAILBOX_UNAVAILABLE = _Anonymous_33.MAILSMTP_ERROR_MAILBOX_UNAVAILABLE;
    enum MAILSMTP_ERROR_MAILBOX_NAME_NOT_ALLOWED = _Anonymous_33.MAILSMTP_ERROR_MAILBOX_NAME_NOT_ALLOWED;
    enum MAILSMTP_ERROR_BAD_SEQUENCE_OF_COMMAND = _Anonymous_33.MAILSMTP_ERROR_BAD_SEQUENCE_OF_COMMAND;
    enum MAILSMTP_ERROR_USER_NOT_LOCAL = _Anonymous_33.MAILSMTP_ERROR_USER_NOT_LOCAL;
    enum MAILSMTP_ERROR_TRANSACTION_FAILED = _Anonymous_33.MAILSMTP_ERROR_TRANSACTION_FAILED;
    enum MAILSMTP_ERROR_MEMORY = _Anonymous_33.MAILSMTP_ERROR_MEMORY;
    enum MAILSMTP_ERROR_AUTH_NOT_SUPPORTED = _Anonymous_33.MAILSMTP_ERROR_AUTH_NOT_SUPPORTED;
    enum MAILSMTP_ERROR_AUTH_LOGIN = _Anonymous_33.MAILSMTP_ERROR_AUTH_LOGIN;
    enum MAILSMTP_ERROR_AUTH_REQUIRED = _Anonymous_33.MAILSMTP_ERROR_AUTH_REQUIRED;
    enum MAILSMTP_ERROR_AUTH_TOO_WEAK = _Anonymous_33.MAILSMTP_ERROR_AUTH_TOO_WEAK;
    enum MAILSMTP_ERROR_AUTH_TRANSITION_NEEDED = _Anonymous_33.MAILSMTP_ERROR_AUTH_TRANSITION_NEEDED;
    enum MAILSMTP_ERROR_AUTH_TEMPORARY_FAILTURE = _Anonymous_33.MAILSMTP_ERROR_AUTH_TEMPORARY_FAILTURE;
    enum MAILSMTP_ERROR_AUTH_ENCRYPTION_REQUIRED = _Anonymous_33.MAILSMTP_ERROR_AUTH_ENCRYPTION_REQUIRED;
    enum MAILSMTP_ERROR_STARTTLS_TEMPORARY_FAILURE = _Anonymous_33.MAILSMTP_ERROR_STARTTLS_TEMPORARY_FAILURE;
    enum MAILSMTP_ERROR_STARTTLS_NOT_SUPPORTED = _Anonymous_33.MAILSMTP_ERROR_STARTTLS_NOT_SUPPORTED;
    enum MAILSMTP_ERROR_CONNECTION_REFUSED = _Anonymous_33.MAILSMTP_ERROR_CONNECTION_REFUSED;
    enum MAILSMTP_ERROR_AUTH_AUTHENTICATION_FAILED = _Anonymous_33.MAILSMTP_ERROR_AUTH_AUTHENTICATION_FAILED;
    enum MAILSMTP_ERROR_SSL = _Anonymous_33.MAILSMTP_ERROR_SSL;






    FILE* mailprivacy_get_tmp_file(mailprivacy*, char*, size_t, );


    int maillock_write_unlock(const(char)*, int, );
    alias int_least64_t = c_long;
    extern __gshared mailsession_driver* maildir_session_driver;




    struct mail_flags_store
    {
        carray* fls_tab;
        chash* fls_hash;
    }
    char* mailstream_read_line(mailstream*, MMAPString*, );
    extern __gshared int mailstream_cfstream_voip_enabled;
    int mailmime_transfer_encoding_get(mailmime_fields*, );
    char* mailmime_content_charset_get(mailmime_content*, );
    int mailimap_uid_expunge(mailimap*, mailimap_set*, );


    extern __gshared mailsession_driver* db_session_driver;
    void mailimap_quota_free(mailimap_extension_data*, );
    int mailmime_encoded_phrase_parse(const(char)*, const(char)*, size_t, size_t*, const(char)*, char**, );


    int mailimap_idle_get_fd(mailimap*, );
    int mailimap_namespace(mailimap*, mailimap_namespace_data**, );



    int mailimap_store_unchangedsince(mailimap*, mailimap_set*, uint64_t, mailimap_store_att_flags*, );


    void mailprivacy_free(mailprivacy*, );
    int newsfeed_set_title(newsfeed*, const(char)*, );
    mailimap_namespace_response_extension* mailimap_namespace_response_extension_new(char*, clist*, );


    extern __gshared mailsession_driver* mbox_cached_session_driver;
    int maildir_message_add_uid(maildir*, const(char)*, size_t, char*, size_t, );


    extern __gshared mailmessage_driver* data_message_driver;
    int mailmime_fields_write_mem(MMAPString*, int*, mailmime_fields*, );


    extern __gshared mailstream_low_driver* mailstream_socket_driver;


    int mailsmtp_socket_connect(mailsmtp*, const(char)*, uint16_t, );
    void mime_message_detach_mime(mailmessage*, );
    size_t newsfeed_item_enclosure_get_size(newsfeed_item_enclosure*, );
    mailsem* mailsem_new();
    enum _Anonymous_34
    {
        MAILIMAP_QRESYNC_RESPTEXTCODE_CLOSED = 0,
    }
    enum MAILIMAP_QRESYNC_RESPTEXTCODE_CLOSED = _Anonymous_34.MAILIMAP_QRESYNC_RESPTEXTCODE_CLOSED;
    alias ino_t = c_ulong;
    enum _Anonymous_35
    {
        MAILIMAP_SORT_KEY_ARRIVAL = 0,
        MAILIMAP_SORT_KEY_CC = 1,
        MAILIMAP_SORT_KEY_DATE = 2,
        MAILIMAP_SORT_KEY_FROM = 3,
        MAILIMAP_SORT_KEY_SIZE = 4,
        MAILIMAP_SORT_KEY_SUBJECT = 5,
        MAILIMAP_SORT_KEY_TO = 6,
        MAILIMAP_SORT_KEY_MULTIPLE = 7,
    }
    enum MAILIMAP_SORT_KEY_ARRIVAL = _Anonymous_35.MAILIMAP_SORT_KEY_ARRIVAL;
    enum MAILIMAP_SORT_KEY_CC = _Anonymous_35.MAILIMAP_SORT_KEY_CC;
    enum MAILIMAP_SORT_KEY_DATE = _Anonymous_35.MAILIMAP_SORT_KEY_DATE;
    enum MAILIMAP_SORT_KEY_FROM = _Anonymous_35.MAILIMAP_SORT_KEY_FROM;
    enum MAILIMAP_SORT_KEY_SIZE = _Anonymous_35.MAILIMAP_SORT_KEY_SIZE;
    enum MAILIMAP_SORT_KEY_SUBJECT = _Anonymous_35.MAILIMAP_SORT_KEY_SUBJECT;
    enum MAILIMAP_SORT_KEY_TO = _Anonymous_35.MAILIMAP_SORT_KEY_TO;
    enum MAILIMAP_SORT_KEY_MULTIPLE = _Anonymous_35.MAILIMAP_SORT_KEY_MULTIPLE;
    void newsfeed_item_enclosure_set_size(newsfeed_item_enclosure*, size_t, );
    enum _Anonymous_36
    {
        MAILIMAP_CONDSTORE_RESPTEXTCODE_HIGHESTMODSEQ = 0,
        MAILIMAP_CONDSTORE_RESPTEXTCODE_NOMODSEQ = 1,
        MAILIMAP_CONDSTORE_RESPTEXTCODE_MODIFIED = 2,
    }
    enum MAILIMAP_CONDSTORE_RESPTEXTCODE_HIGHESTMODSEQ = _Anonymous_36.MAILIMAP_CONDSTORE_RESPTEXTCODE_HIGHESTMODSEQ;
    enum MAILIMAP_CONDSTORE_RESPTEXTCODE_NOMODSEQ = _Anonymous_36.MAILIMAP_CONDSTORE_RESPTEXTCODE_NOMODSEQ;
    enum MAILIMAP_CONDSTORE_RESPTEXTCODE_MODIFIED = _Anonymous_36.MAILIMAP_CONDSTORE_RESPTEXTCODE_MODIFIED;
    void mailimap_id_params_list_free(mailimap_id_params_list*, );
    enum _Anonymous_37
    {
        MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_CERTIFICATES = 1,
        MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_ROOTS = 2,
        MAILSTREAM_CFSTREAM_SSL_ALLOWS_ANY_ROOT = 4,
        MAILSTREAM_CFSTREAM_SSL_DISABLE_VALIDATES_CERTIFICATE_CHAIN = 8,
        MAILSTREAM_CFSTREAM_SSL_NO_VERIFICATION = 15,
    }
    enum MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_CERTIFICATES = _Anonymous_37.MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_CERTIFICATES;
    enum MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_ROOTS = _Anonymous_37.MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_ROOTS;
    enum MAILSTREAM_CFSTREAM_SSL_ALLOWS_ANY_ROOT = _Anonymous_37.MAILSTREAM_CFSTREAM_SSL_ALLOWS_ANY_ROOT;
    enum MAILSTREAM_CFSTREAM_SSL_DISABLE_VALIDATES_CERTIFICATE_CHAIN = _Anonymous_37.MAILSTREAM_CFSTREAM_SSL_DISABLE_VALIDATES_CERTIFICATE_CHAIN;
    enum MAILSTREAM_CFSTREAM_SSL_NO_VERIFICATION = _Anonymous_37.MAILSTREAM_CFSTREAM_SSL_NO_VERIFICATION;
    char* mailstream_read_line_append(mailstream*, MMAPString*, );
    alias __fd_mask = c_long;
    int mailfolder_expunge(mailfolder*, );




    const(char)* newsfeed_get_title(newsfeed*, );
    clist* mailprivacy_gnupg_encryption_id_list(mailprivacy*, mailmessage*, );
    alias pthread_key_t = uint;


    void mailprivacy_smime_set_cert_dir(mailprivacy*, char*, );
    const(char)* newsfeed_item_get_summary(newsfeed_item*, );
    enum _Anonymous_38
    {
        NEWSNNTP_NO_ERROR = 0,
        NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_USERNAME = 1,
        NEWSNNTP_ERROR_REQUEST_AUTHORIZATION_USERNAME = 1,
        NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_PASSWORD = 2,
        NEWSNNTP_ERROR_STREAM = 3,
        NEWSNNTP_ERROR_UNEXPECTED = 4,
        NEWSNNTP_ERROR_NO_NEWSGROUP_SELECTED = 5,
        NEWSNNTP_ERROR_NO_ARTICLE_SELECTED = 6,
        NEWSNNTP_ERROR_INVALID_ARTICLE_NUMBER = 7,
        NEWSNNTP_ERROR_ARTICLE_NOT_FOUND = 8,
        NEWSNNTP_ERROR_UNEXPECTED_RESPONSE = 9,
        NEWSNNTP_ERROR_INVALID_RESPONSE = 10,
        NEWSNNTP_ERROR_NO_SUCH_NEWS_GROUP = 11,
        NEWSNNTP_ERROR_POSTING_NOT_ALLOWED = 12,
        NEWSNNTP_ERROR_POSTING_FAILED = 13,
        NEWSNNTP_ERROR_PROGRAM_ERROR = 14,
        NEWSNNTP_ERROR_NO_PERMISSION = 15,
        NEWSNNTP_ERROR_COMMAND_NOT_UNDERSTOOD = 16,
        NEWSNNTP_ERROR_COMMAND_NOT_SUPPORTED = 17,
        NEWSNNTP_ERROR_CONNECTION_REFUSED = 18,
        NEWSNNTP_ERROR_MEMORY = 19,
        NEWSNNTP_ERROR_AUTHENTICATION_REJECTED = 20,
        NEWSNNTP_ERROR_BAD_STATE = 21,
        NEWSNNTP_ERROR_SSL = 22,
        NEWSNNTP_ERROR_AUTHENTICATION_OUT_OF_SEQUENCE = 23,
    }
    enum NEWSNNTP_NO_ERROR = _Anonymous_38.NEWSNNTP_NO_ERROR;
    enum NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_USERNAME = _Anonymous_38.NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_USERNAME;
    enum NEWSNNTP_ERROR_REQUEST_AUTHORIZATION_USERNAME = _Anonymous_38.NEWSNNTP_ERROR_REQUEST_AUTHORIZATION_USERNAME;
    enum NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_PASSWORD = _Anonymous_38.NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_PASSWORD;
    enum NEWSNNTP_ERROR_STREAM = _Anonymous_38.NEWSNNTP_ERROR_STREAM;
    enum NEWSNNTP_ERROR_UNEXPECTED = _Anonymous_38.NEWSNNTP_ERROR_UNEXPECTED;
    enum NEWSNNTP_ERROR_NO_NEWSGROUP_SELECTED = _Anonymous_38.NEWSNNTP_ERROR_NO_NEWSGROUP_SELECTED;
    enum NEWSNNTP_ERROR_NO_ARTICLE_SELECTED = _Anonymous_38.NEWSNNTP_ERROR_NO_ARTICLE_SELECTED;
    enum NEWSNNTP_ERROR_INVALID_ARTICLE_NUMBER = _Anonymous_38.NEWSNNTP_ERROR_INVALID_ARTICLE_NUMBER;
    enum NEWSNNTP_ERROR_ARTICLE_NOT_FOUND = _Anonymous_38.NEWSNNTP_ERROR_ARTICLE_NOT_FOUND;
    enum NEWSNNTP_ERROR_UNEXPECTED_RESPONSE = _Anonymous_38.NEWSNNTP_ERROR_UNEXPECTED_RESPONSE;
    enum NEWSNNTP_ERROR_INVALID_RESPONSE = _Anonymous_38.NEWSNNTP_ERROR_INVALID_RESPONSE;
    enum NEWSNNTP_ERROR_NO_SUCH_NEWS_GROUP = _Anonymous_38.NEWSNNTP_ERROR_NO_SUCH_NEWS_GROUP;
    enum NEWSNNTP_ERROR_POSTING_NOT_ALLOWED = _Anonymous_38.NEWSNNTP_ERROR_POSTING_NOT_ALLOWED;
    enum NEWSNNTP_ERROR_POSTING_FAILED = _Anonymous_38.NEWSNNTP_ERROR_POSTING_FAILED;
    enum NEWSNNTP_ERROR_PROGRAM_ERROR = _Anonymous_38.NEWSNNTP_ERROR_PROGRAM_ERROR;
    enum NEWSNNTP_ERROR_NO_PERMISSION = _Anonymous_38.NEWSNNTP_ERROR_NO_PERMISSION;
    enum NEWSNNTP_ERROR_COMMAND_NOT_UNDERSTOOD = _Anonymous_38.NEWSNNTP_ERROR_COMMAND_NOT_UNDERSTOOD;
    enum NEWSNNTP_ERROR_COMMAND_NOT_SUPPORTED = _Anonymous_38.NEWSNNTP_ERROR_COMMAND_NOT_SUPPORTED;
    enum NEWSNNTP_ERROR_CONNECTION_REFUSED = _Anonymous_38.NEWSNNTP_ERROR_CONNECTION_REFUSED;
    enum NEWSNNTP_ERROR_MEMORY = _Anonymous_38.NEWSNNTP_ERROR_MEMORY;
    enum NEWSNNTP_ERROR_AUTHENTICATION_REJECTED = _Anonymous_38.NEWSNNTP_ERROR_AUTHENTICATION_REJECTED;
    enum NEWSNNTP_ERROR_BAD_STATE = _Anonymous_38.NEWSNNTP_ERROR_BAD_STATE;
    enum NEWSNNTP_ERROR_SSL = _Anonymous_38.NEWSNNTP_ERROR_SSL;
    enum NEWSNNTP_ERROR_AUTHENTICATION_OUT_OF_SEQUENCE = _Anonymous_38.NEWSNNTP_ERROR_AUTHENTICATION_OUT_OF_SEQUENCE;
    enum _Anonymous_39
    {
        MBOXDRIVER_SET_READ_ONLY = 1,
        MBOXDRIVER_SET_NO_UID = 2,
    }
    enum MBOXDRIVER_SET_READ_ONLY = _Anonymous_39.MBOXDRIVER_SET_READ_ONLY;
    enum MBOXDRIVER_SET_NO_UID = _Anonymous_39.MBOXDRIVER_SET_NO_UID;
    mailstream_low* mailstream_low_socket_open(int, );
    struct _Anonymous_40
    {
        void* data;
        uint len;
    }
    enum _Anonymous_41
    {
        MAILMH_NO_ERROR = 0,
        MAILMH_ERROR_FOLDER = 1,
        MAILMH_ERROR_MEMORY = 2,
        MAILMH_ERROR_FILE = 3,
        MAILMH_ERROR_COULD_NOT_ALLOC_MSG = 4,
        MAILMH_ERROR_RENAME = 5,
        MAILMH_ERROR_MSG_NOT_FOUND = 6,
    }
    enum MAILMH_NO_ERROR = _Anonymous_41.MAILMH_NO_ERROR;
    enum MAILMH_ERROR_FOLDER = _Anonymous_41.MAILMH_ERROR_FOLDER;
    enum MAILMH_ERROR_MEMORY = _Anonymous_41.MAILMH_ERROR_MEMORY;
    enum MAILMH_ERROR_FILE = _Anonymous_41.MAILMH_ERROR_FILE;
    enum MAILMH_ERROR_COULD_NOT_ALLOC_MSG = _Anonymous_41.MAILMH_ERROR_COULD_NOT_ALLOC_MSG;
    enum MAILMH_ERROR_RENAME = _Anonymous_41.MAILMH_ERROR_RENAME;
    enum MAILMH_ERROR_MSG_NOT_FOUND = _Anonymous_41.MAILMH_ERROR_MSG_NOT_FOUND;
    alias chashdatum = _Anonymous_40;




    mailstream_low* mailstream_low_new(void*, mailstream_low_driver*, );
    enum _Anonymous_42
    {
        MAIL_CHARCONV_NO_ERROR = 0,
        MAIL_CHARCONV_ERROR_UNKNOWN_CHARSET = 1,
        MAIL_CHARCONV_ERROR_MEMORY = 2,
        MAIL_CHARCONV_ERROR_CONV = 3,
    }
    enum MAIL_CHARCONV_NO_ERROR = _Anonymous_42.MAIL_CHARCONV_NO_ERROR;
    enum MAIL_CHARCONV_ERROR_UNKNOWN_CHARSET = _Anonymous_42.MAIL_CHARCONV_ERROR_UNKNOWN_CHARSET;
    enum MAIL_CHARCONV_ERROR_MEMORY = _Anonymous_42.MAIL_CHARCONV_ERROR_MEMORY;
    enum MAIL_CHARCONV_ERROR_CONV = _Anonymous_42.MAIL_CHARCONV_ERROR_CONV;
    char* mailmime_content_param_get(mailmime_content*, char*, );
    int mailmbox_append_message(mailmbox_folder*, const(char)*, size_t, );
    alias clistcell = clistcell_s;


    int mailpop3_login(mailpop3*, const(char)*, const(char)*, );


    int mailmime_content_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailmime_content*, );
    int mailsmtp_init(mailsmtp*, );
    mailimap_fetch_att* mailimap_fetch_att_new_xgmlabels();
    struct clistcell_s
    {
        void* data;
        clistcell_s* previous;
        clistcell_s* next;
    }
    int mailmime_fields_write_file(FILE*, int*, mailmime_fields*, );
    int newsfeed_item_set_summary(newsfeed_item*, const(char)*, );
    int mailimap_id(mailimap*, mailimap_id_params_list*, mailimap_id_params_list**, );
    struct feed_session_state_data
    {
        time_t feed_last_update;
        newsfeed* feed_session;
        int feed_error;
    }
    mailmime_disposition* mailmime_disposition_new_filename(int, char*, );
    int mailimap_uidplus_copy(mailimap*, mailimap_set*, const(char)*, uint32_t*, mailimap_set**, mailimap_set**, );
    int mailimap_has_enable(mailimap*, );
    enum _Anonymous_43
    {
        MAILPOP3_NO_ERROR = 0,
        MAILPOP3_ERROR_BAD_STATE = 1,
        MAILPOP3_ERROR_UNAUTHORIZED = 2,
        MAILPOP3_ERROR_STREAM = 3,
        MAILPOP3_ERROR_DENIED = 4,
        MAILPOP3_ERROR_BAD_USER = 5,
        MAILPOP3_ERROR_BAD_PASSWORD = 6,
        MAILPOP3_ERROR_CANT_LIST = 7,
        MAILPOP3_ERROR_NO_SUCH_MESSAGE = 8,
        MAILPOP3_ERROR_MEMORY = 9,
        MAILPOP3_ERROR_CONNECTION_REFUSED = 10,
        MAILPOP3_ERROR_APOP_NOT_SUPPORTED = 11,
        MAILPOP3_ERROR_CAPA_NOT_SUPPORTED = 12,
        MAILPOP3_ERROR_STLS_NOT_SUPPORTED = 13,
        MAILPOP3_ERROR_SSL = 14,
        MAILPOP3_ERROR_QUIT_FAILED = 15,
    }
    enum MAILPOP3_NO_ERROR = _Anonymous_43.MAILPOP3_NO_ERROR;
    enum MAILPOP3_ERROR_BAD_STATE = _Anonymous_43.MAILPOP3_ERROR_BAD_STATE;
    enum MAILPOP3_ERROR_UNAUTHORIZED = _Anonymous_43.MAILPOP3_ERROR_UNAUTHORIZED;
    enum MAILPOP3_ERROR_STREAM = _Anonymous_43.MAILPOP3_ERROR_STREAM;
    enum MAILPOP3_ERROR_DENIED = _Anonymous_43.MAILPOP3_ERROR_DENIED;
    enum MAILPOP3_ERROR_BAD_USER = _Anonymous_43.MAILPOP3_ERROR_BAD_USER;
    enum MAILPOP3_ERROR_BAD_PASSWORD = _Anonymous_43.MAILPOP3_ERROR_BAD_PASSWORD;
    enum MAILPOP3_ERROR_CANT_LIST = _Anonymous_43.MAILPOP3_ERROR_CANT_LIST;
    enum MAILPOP3_ERROR_NO_SUCH_MESSAGE = _Anonymous_43.MAILPOP3_ERROR_NO_SUCH_MESSAGE;
    enum MAILPOP3_ERROR_MEMORY = _Anonymous_43.MAILPOP3_ERROR_MEMORY;
    enum MAILPOP3_ERROR_CONNECTION_REFUSED = _Anonymous_43.MAILPOP3_ERROR_CONNECTION_REFUSED;
    enum MAILPOP3_ERROR_APOP_NOT_SUPPORTED = _Anonymous_43.MAILPOP3_ERROR_APOP_NOT_SUPPORTED;
    enum MAILPOP3_ERROR_CAPA_NOT_SUPPORTED = _Anonymous_43.MAILPOP3_ERROR_CAPA_NOT_SUPPORTED;
    enum MAILPOP3_ERROR_STLS_NOT_SUPPORTED = _Anonymous_43.MAILPOP3_ERROR_STLS_NOT_SUPPORTED;
    enum MAILPOP3_ERROR_SSL = _Anonymous_43.MAILPOP3_ERROR_SSL;
    enum MAILPOP3_ERROR_QUIT_FAILED = _Anonymous_43.MAILPOP3_ERROR_QUIT_FAILED;


    int mailmime_disposition_type_parse(const(char)*, size_t, size_t*, mailmime_disposition_type**, );
    struct db_session_state_data
    {
        char[4096] db_filename;
        mail_flags_store* db_flags_store;
    }
    struct carray_s
    {
        void** array;
        uint len;
        uint max;
    }
    int mime_message_set_tmpdir(mailmessage*, char*, );
    int mailpop3_ssl_connect(mailpop3*, const(char)*, uint16_t, );
    char* mailstream_read_line_remove_eol(mailstream*, MMAPString*, );
    void mailstream_socket_set_use_read(mailstream*, int, );
    int mailimap_quota_getquotaroot(mailimap*, const(char)*, mailimap_quota_complete_data**, );
    mailimap_quota_quota_resource* mailimap_quota_quota_resource_new(char*, uint32_t, uint32_t, );
    struct mailimap_uidplus_resp_code_apnd
    {
        uint32_t uid_uidvalidity;
        mailimap_set* uid_set;
    }
    int mailsmtp_ssl_connect(mailsmtp*, const(char)*, uint16_t, );
    enum _Anonymous_44
    {
        MAIL_THREAD_REFERENCES = 0,
        MAIL_THREAD_REFERENCES_NO_SUBJECT = 1,
        MAIL_THREAD_ORDEREDSUBJECT = 2,
        MAIL_THREAD_NONE = 3,
    }
    enum MAIL_THREAD_REFERENCES = _Anonymous_44.MAIL_THREAD_REFERENCES;
    enum MAIL_THREAD_REFERENCES_NO_SUBJECT = _Anonymous_44.MAIL_THREAD_REFERENCES_NO_SUBJECT;
    enum MAIL_THREAD_ORDEREDSUBJECT = _Anonymous_44.MAIL_THREAD_ORDEREDSUBJECT;
    enum MAIL_THREAD_NONE = _Anonymous_44.MAIL_THREAD_NONE;
    void mailsem_free(mailsem*, );


    int mailprivacy_get_tmp_filename(mailprivacy*, char*, size_t, );


    int newsfeed_set_description(newsfeed*, const(char)*, );






    int mailprivacy_msg_get_bodystructure(mailprivacy*, mailmessage*, mailmime**, );


    int mailpop3_socket_connect(mailpop3*, const(char)*, uint16_t, );
    int mailimap_has_namespace(mailimap*, );
    struct maildir_session_state_data
    {
        maildir* md_session;
        mail_flags_store* md_flags_store;
    }
    struct mailimap_id_param
    {
        char* idpa_name;
        char* idpa_value;
    }
    mailmessage* data_message_init(char*, size_t, );
    int mailimap_socket_connect_voip(mailimap*, const(char)*, uint16_t, int, );
    int mailimap_fetch_rfc822_header(mailimap*, uint32_t, char**, );
    int mailimap_ssl_connect(mailimap*, const(char)*, uint16_t, );
    int newsnntp_socket_connect(newsnntp*, const(char)*, uint16_t, );
    enum _Anonymous_45
    {
        MAILDIR_NO_ERROR = 0,
        MAILDIR_ERROR_CREATE = 1,
        MAILDIR_ERROR_DIRECTORY = 2,
        MAILDIR_ERROR_MEMORY = 3,
        MAILDIR_ERROR_FILE = 4,
        MAILDIR_ERROR_NOT_FOUND = 5,
        MAILDIR_ERROR_FOLDER = 6,
    }
    enum MAILDIR_NO_ERROR = _Anonymous_45.MAILDIR_NO_ERROR;
    enum MAILDIR_ERROR_CREATE = _Anonymous_45.MAILDIR_ERROR_CREATE;
    enum MAILDIR_ERROR_DIRECTORY = _Anonymous_45.MAILDIR_ERROR_DIRECTORY;
    enum MAILDIR_ERROR_MEMORY = _Anonymous_45.MAILDIR_ERROR_MEMORY;
    enum MAILDIR_ERROR_FILE = _Anonymous_45.MAILDIR_ERROR_FILE;
    enum MAILDIR_ERROR_NOT_FOUND = _Anonymous_45.MAILDIR_ERROR_NOT_FOUND;
    enum MAILDIR_ERROR_FOLDER = _Anonymous_45.MAILDIR_ERROR_FOLDER;




    int maildir_message_add(maildir*, const(char)*, size_t, );
    int mailsmtp_socket_starttls(mailsmtp*, );
    int mailmime_encoded_word_parse(const(char)*, size_t, size_t*, mailmime_encoded_word**, int*, int*, );
    struct mh_session_state_data
    {
        mailmh* mh_session;
        mailmh_folder* mh_cur_folder;
        clist* mh_subscribed_list;
    }
    struct timezone
    {
        int tz_minuteswest;
        int tz_dsttime;
    }
    int mailfolder_status(mailfolder*, uint32_t*, uint32_t*, uint32_t*, );


    alias mailstream = _mailstream;
    alias __quad_t = c_long;
    mailstream* mailstream_socket_open(int, );
    void mailimap_idle_set_delay(mailimap*, c_long, );




    int newsnntp_ssl_connect(newsnntp*, const(char)*, uint16_t, );
    int mailimap_select_qresync(mailimap*, const(char)*, uint32_t, uint64_t, mailimap_set*, mailimap_set*, mailimap_set*, clist**, mailimap_qresync_vanished**, uint64_t*, );
    struct mailimap_qresync_resptextcode
    {
        int qr_type;
    }


    int mailimap_compress(mailimap*, );
    int mailmime_content_write_mem(MMAPString*, int*, mailmime_content*, );
    const(char)* newsfeed_item_get_text(newsfeed_item*, );
    enum _Anonymous_46
    {
        MAILMBOX_NO_ERROR = 0,
        MAILMBOX_ERROR_PARSE = 1,
        MAILMBOX_ERROR_INVAL = 2,
        MAILMBOX_ERROR_FILE_NOT_FOUND = 3,
        MAILMBOX_ERROR_MEMORY = 4,
        MAILMBOX_ERROR_TEMPORARY_FILE = 5,
        MAILMBOX_ERROR_FILE = 6,
        MAILMBOX_ERROR_MSG_NOT_FOUND = 7,
        MAILMBOX_ERROR_READONLY = 8,
    }
    enum MAILMBOX_NO_ERROR = _Anonymous_46.MAILMBOX_NO_ERROR;
    enum MAILMBOX_ERROR_PARSE = _Anonymous_46.MAILMBOX_ERROR_PARSE;
    enum MAILMBOX_ERROR_INVAL = _Anonymous_46.MAILMBOX_ERROR_INVAL;
    enum MAILMBOX_ERROR_FILE_NOT_FOUND = _Anonymous_46.MAILMBOX_ERROR_FILE_NOT_FOUND;
    enum MAILMBOX_ERROR_MEMORY = _Anonymous_46.MAILMBOX_ERROR_MEMORY;
    enum MAILMBOX_ERROR_TEMPORARY_FILE = _Anonymous_46.MAILMBOX_ERROR_TEMPORARY_FILE;
    enum MAILMBOX_ERROR_FILE = _Anonymous_46.MAILMBOX_ERROR_FILE;
    enum MAILMBOX_ERROR_MSG_NOT_FOUND = _Anonymous_46.MAILMBOX_ERROR_MSG_NOT_FOUND;
    enum MAILMBOX_ERROR_READONLY = _Anonymous_46.MAILMBOX_ERROR_READONLY;
    const(char)* newsfeed_get_description(newsfeed*, );


    mailsmtp* mailsmtp_new(size_t, progress_function*, );


    struct imap_session_state_data
    {
        mailimap* imap_session;
        char* imap_mailbox;
        mail_flags_store* imap_flags_store;
        void function(mailstream_ssl_context*, void*) imap_ssl_callback;
        void* imap_ssl_cb_data;
    }


    int mailmime_content_type_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailmime_content*, );
    void mailprivacy_gnupg_encryption_id_list_clear(mailprivacy*, mailmessage*, );




    struct _xmmreg
    {
        __uint32_t[4] element;
    }
    alias pthread_once_t = int;
    int mailimap_xlist(mailimap*, const(char)*, const(char)*, clist**, );




    int mailsmtp_init_with_ip(mailsmtp*, int, );
    char* mailstream_read_multiline(mailstream*, size_t, MMAPString*, MMAPString*, size_t, progress_function*, mailprogress_function*, void*, );
    int newsfeed_item_set_text(newsfeed_item*, const(char)*, );


    int mailimap_uid_store_unchangedsince(mailimap*, mailimap_set*, uint64_t, mailimap_store_att_flags*, );
    void mailimap_namespace_response_extension_free(mailimap_namespace_response_extension*, );
    int mailimap_has_xgmlabels(mailimap*, );
    mailstream* mailstream_socket_open_timeout(int, time_t, );
    alias __u_quad_t = c_ulong;
    ssize_t mailstream_low_write(mailstream_low*, const(void)*, size_t, );




    int mailimap_extension_register(mailimap_extension_api*, );
    int mailmbox_append_message_uid(mailmbox_folder*, const(char)*, size_t, uint*, );




    int newsfeed_set_language(newsfeed*, const(char)*, );
    int mailmime_content_write_file(FILE*, int*, mailmime_content*, );
    int mailsem_up(mailsem*, );
    void data_message_detach_mime(mailmessage*, );
    enum _Anonymous_47
    {
        POP3DRIVER_SET_AUTH_TYPE = 1,
    }
    enum POP3DRIVER_SET_AUTH_TYPE = _Anonymous_47.POP3DRIVER_SET_AUTH_TYPE;
    enum _Anonymous_48
    {
        NNTPDRIVER_SET_MAX_ARTICLES = 1,
    }
    enum NNTPDRIVER_SET_MAX_ARTICLES = _Anonymous_48.NNTPDRIVER_SET_MAX_ARTICLES;
    mailmessage* mailmessage_new();
    mailmime_fields* mailmime_fields_new_empty();
    int mailpop3_header(mailpop3*, uint32_t, char**, size_t*, );
    alias uint_least8_t = ubyte;
    int mailimap_socket_connect(mailimap*, const(char)*, uint16_t, );
    int mailpop3_socket_starttls(mailpop3*, );


    int mailmime_parse(const(char)*, size_t, size_t*, mailmime**, );
    alias MMAPString = _MMAPString;




    mailpop3* mailpop3_new(size_t, progress_function*, );
    extern __gshared mailimap_extension_api mailimap_extension_acl;


    int mailimap_ssl_connect_voip(mailimap*, const(char)*, uint16_t, int, );
    enum _Anonymous_49
    {
        MAILMIME_COMPOSITE_TYPE_ERROR = 0,
        MAILMIME_COMPOSITE_TYPE_MESSAGE = 1,
        MAILMIME_COMPOSITE_TYPE_MULTIPART = 2,
        MAILMIME_COMPOSITE_TYPE_EXTENSION = 3,
    }
    enum MAILMIME_COMPOSITE_TYPE_ERROR = _Anonymous_49.MAILMIME_COMPOSITE_TYPE_ERROR;
    enum MAILMIME_COMPOSITE_TYPE_MESSAGE = _Anonymous_49.MAILMIME_COMPOSITE_TYPE_MESSAGE;
    enum MAILMIME_COMPOSITE_TYPE_MULTIPART = _Anonymous_49.MAILMIME_COMPOSITE_TYPE_MULTIPART;
    enum MAILMIME_COMPOSITE_TYPE_EXTENSION = _Anonymous_49.MAILMIME_COMPOSITE_TYPE_EXTENSION;
    int mailpop3_ssl_connect_with_callback(mailpop3*, const(char)*, uint16_t, void function(mailstream_ssl_context*, void*), void*, );


    int db_mailstorage_init(mailstorage*, char*, );
    struct mailimap_condstore_resptextcode
    {
        int cs_type;
        union _Anonymous_50
        {
            uint64_t cs_modseq_value;
            mailimap_set* cs_modified_set;
        }
        _Anonymous_50 cs_data;
    }
    struct chash
    {
        uint size;
        uint count;
        int copyvalue;
        int copykey;
        chashcell** cells;
    }
    int mailmime_content_parse(const(char)*, size_t, size_t*, mailmime_content**, );
    int maildir_message_add_file_uid(maildir*, int, char*, size_t, );
    int mailmime_disposition_guess_type(const(char)*, size_t, size_t, );
    c_long mailimap_idle_get_done_delay(mailimap*, );






    int mailsmtp_ssl_connect_with_callback(mailsmtp*, const(char)*, uint16_t, void function(mailstream_ssl_context*, void*), void*, );
    int mailsmtp_socket_starttls_with_callback(mailsmtp*, void function(mailstream_ssl_context*, void*), void*, );






    struct mbox_session_state_data
    {
        mailmbox_folder* mbox_folder;
        int mbox_force_read_only;
        int mbox_force_no_uid;
    }
    mailmime* mailprivacy_new_file_part(mailprivacy*, char*, char*, int, );


    struct mailimap_namespace_info
    {
        char* ns_prefix;
        char ns_delimiter;
        clist* ns_extensions;
    }
    alias uint_least16_t = ushort;
    int newsnntp_ssl_connect_with_callback(newsnntp*, const(char)*, uint16_t, void function(mailstream_ssl_context*, void*), void*, );


    int mailimap_fetch_envelope(mailimap*, uint32_t, uint32_t, clist**, );
    const(char)* newsfeed_get_language(newsfeed*, );
    const(char)* newsfeed_item_get_author(newsfeed_item*, );


    alias carray = carray_s;


    struct clist_s
    {
        clistcell* first;
        clistcell* last;
        int count;
    }
    ssize_t mailstream_low_read(mailstream_low*, void*, size_t, );
    int newsfeed_item_set_author(newsfeed_item*, const(char)*, );


    mailimap_msg_att_xgmlabels* mailimap_msg_att_xgmlabels_new(clist*, );
    alias mailstream_low = _mailstream_low;
    struct mailimap_uidplus_resp_code_copy
    {
        uint32_t uid_uidvalidity;
        mailimap_set* uid_source_set;
        mailimap_set* uid_dest_set;
    }


    struct _MMAPString
    {
        char* str;
        size_t len;
        size_t allocated_len;
        int fd;
        size_t mmapped_size;
    }
    void mailimap_quota_quota_resource_free(mailimap_quota_quota_resource*, );
    struct mailstream_ssl_context;
    struct feed_mailstorage
    {
        char* feed_url;
        int feed_cached;
        char* feed_cache_directory;
        char* feed_flags_directory;
    }
    alias uint_least32_t = uint;
    void mailprivacy_msg_flush(mailprivacy*, mailmessage*, );
    union pthread_attr_t
    {
        char[56] __size;
        c_long __align;
    }


    int mailmime_content_type_write_mem(MMAPString*, int*, mailmime_content*, );
    mailsession* mailsession_new(mailsession_driver*, );
    int mailmime_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailmime*, );


    enum _Anonymous_51
    {
        MAILDIRDRIVER_CACHED_SET_CACHE_DIRECTORY = 1,
        MAILDIRDRIVER_CACHED_SET_FLAGS_DIRECTORY = 2,
    }
    enum MAILDIRDRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_51.MAILDIRDRIVER_CACHED_SET_CACHE_DIRECTORY;
    enum MAILDIRDRIVER_CACHED_SET_FLAGS_DIRECTORY = _Anonymous_51.MAILDIRDRIVER_CACHED_SET_FLAGS_DIRECTORY;


    mailstream* mailstream_new(mailstream_low*, size_t, );
    void mailsmtp_free(mailsmtp*, );


    int mailesmtp_send(mailsmtp*, const(char)*, int, const(char)*, clist*, const(char)*, size_t, );


    int mailpop3_socket_starttls_with_callback(mailpop3*, void function(mailstream_ssl_context*, void*), void*, );
    void mailpop3_header_free(char*, );
    mailimap_qresync_vanished* mailimap_qresync_vanished_new(int, mailimap_set*, );
    int newsfeed_set_author(newsfeed*, const(char)*, );
    struct mailengine;
    int mailimap_id_basic(mailimap*, const(char)*, const(char)*, char**, char**, );
    int mailimap_has_xlist(mailimap*, );
    mailengine* libetpan_engine_new(mailprivacy*, );
    mailimap_id_param* mailimap_id_param_new(char*, char*, );
    int mailprivacy_gnupg_set_encryption_id(mailprivacy*, char*, char*, );




    int mailimap_uidplus_uid_copy(mailimap*, mailimap_set*, const(char)*, uint32_t*, mailimap_set**, mailimap_set**, );




    int mailimap_socket_starttls(mailimap*, );


    int mailimap_ssl_connect_with_callback(mailimap*, const(char)*, uint16_t, void function(mailstream_ssl_context*, void*), void*, );
    int mailsem_down(mailsem*, );
    int mailmime_fields_add(mailmime_fields*, mailmime_field*, );


    int mailfolder_append_message(mailfolder*, char*, size_t, );
    int mailimf_string_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, const(char)*, size_t, );


    void mailpop3_free(mailpop3*, );


    int mailmime_get_section(mailmime*, mailmime_section*, mailmime**, );
    int mailimf_string_write_mem(MMAPString*, int*, const(char)*, size_t, );
    struct mailprivacy_encryption
    {
        char* name;
        char* description;
        int function(mailprivacy*, mailmessage*, mailmime*, mailmime**) encrypt;
    }



    enum _Anonymous_52
    {
        MAILSTREAM_LOG_TYPE_INFO_RECEIVED = 0,
        MAILSTREAM_LOG_TYPE_INFO_SENT = 1,
        MAILSTREAM_LOG_TYPE_ERROR_PARSE = 2,
        MAILSTREAM_LOG_TYPE_ERROR_RECEIVED = 3,
        MAILSTREAM_LOG_TYPE_ERROR_SENT = 4,
        MAILSTREAM_LOG_TYPE_DATA_RECEIVED = 5,
        MAILSTREAM_LOG_TYPE_DATA_SENT = 6,
        MAILSTREAM_LOG_TYPE_DATA_SENT_PRIVATE = 7,
    }
    enum MAILSTREAM_LOG_TYPE_INFO_RECEIVED = _Anonymous_52.MAILSTREAM_LOG_TYPE_INFO_RECEIVED;
    enum MAILSTREAM_LOG_TYPE_INFO_SENT = _Anonymous_52.MAILSTREAM_LOG_TYPE_INFO_SENT;
    enum MAILSTREAM_LOG_TYPE_ERROR_PARSE = _Anonymous_52.MAILSTREAM_LOG_TYPE_ERROR_PARSE;
    enum MAILSTREAM_LOG_TYPE_ERROR_RECEIVED = _Anonymous_52.MAILSTREAM_LOG_TYPE_ERROR_RECEIVED;
    enum MAILSTREAM_LOG_TYPE_ERROR_SENT = _Anonymous_52.MAILSTREAM_LOG_TYPE_ERROR_SENT;
    enum MAILSTREAM_LOG_TYPE_DATA_RECEIVED = _Anonymous_52.MAILSTREAM_LOG_TYPE_DATA_RECEIVED;
    enum MAILSTREAM_LOG_TYPE_DATA_SENT = _Anonymous_52.MAILSTREAM_LOG_TYPE_DATA_SENT;
    enum MAILSTREAM_LOG_TYPE_DATA_SENT_PRIVATE = _Anonymous_52.MAILSTREAM_LOG_TYPE_DATA_SENT_PRIVATE;
    alias uint_least64_t = c_ulong;




    int mailmime_content_type_write_file(FILE*, int*, mailmime_content*, );
    int mailimf_string_write_file(FILE*, int*, const(char)*, size_t, );


    int maildir_message_add_file(maildir*, int, );
    int mailimap_has_idle(mailimap*, );


    int mailimap_fetch_changedsince(mailimap*, mailimap_set*, mailimap_fetch_type*, uint64_t, clist**, );
    struct nntp_session_state_data
    {
        newsnntp* nntp_session;
        char* nntp_userid;
        char* nntp_password;
        newsnntp_group_info* nntp_group_info;
        char* nntp_group_name;
        clist* nntp_subscribed_list;
        uint32_t nntp_max_articles;
        int nntp_mode_reader;
    }
    enum _Anonymous_53
    {
        POP3DRIVER_AUTH_TYPE_PLAIN = 0,
        POP3DRIVER_AUTH_TYPE_APOP = 1,
        POP3DRIVER_AUTH_TYPE_TRY_APOP = 2,
    }
    enum POP3DRIVER_AUTH_TYPE_PLAIN = _Anonymous_53.POP3DRIVER_AUTH_TYPE_PLAIN;
    enum POP3DRIVER_AUTH_TYPE_APOP = _Anonymous_53.POP3DRIVER_AUTH_TYPE_APOP;
    enum POP3DRIVER_AUTH_TYPE_TRY_APOP = _Anonymous_53.POP3DRIVER_AUTH_TYPE_TRY_APOP;
    alias __timezone_ptr_t = timezone*;
    int mailmbox_fetch_msg(mailmbox_folder*, uint32_t, char**, size_t*, );
    const(char)* newsfeed_item_get_id(newsfeed_item*, );
    void mailimap_extension_unregister_all();
    const(char)* newsfeed_get_author(newsfeed*, );
    int newsfeed_item_set_id(newsfeed_item*, const(char)*, );
    int mailmime_quoted_printable_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, int, const(char)*, size_t, );
    void mailprivacy_smime_set_CA_dir(mailprivacy*, char*, );
    void mailsmtp_set_timeout(mailsmtp*, time_t, );
    ssize_t mailstream_write(mailstream*, const(void)*, size_t, );
    mailstream_low* mailstream_low_ssl_open(int, );
    mailimap_msg_att_xgmlabels* mailimap_msg_att_xgmlabels_new_empty();
    int mailstream_low_close(mailstream_low*, );
    struct mailimap_sort_key
    {
        int sortk_type;
        int sortk_is_reverse;
        clist* sortk_multiple;
    }
    alias fd_set = _Anonymous_54;
    struct _Anonymous_54
    {
        __fd_mask[16] __fds_bits;
    }
    char* maildir_message_get(maildir*, const(char)*, );






    enum _Anonymous_55
    {
        MHDRIVER_CACHED_SET_CACHE_DIRECTORY = 1,
        MHDRIVER_CACHED_SET_FLAGS_DIRECTORY = 2,
    }
    enum MHDRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_55.MHDRIVER_CACHED_SET_CACHE_DIRECTORY;
    enum MHDRIVER_CACHED_SET_FLAGS_DIRECTORY = _Anonymous_55.MHDRIVER_CACHED_SET_FLAGS_DIRECTORY;
    carray* carray_new(uint, );
    void mailimap_qresync_vanished_free(mailimap_qresync_vanished*, );
    struct mailmh
    {
        mailmh_folder* mh_main;
    }



    int mailstream_is_end_multiline(const(char)*, );
    int mailmime_write_mem(MMAPString*, int*, mailmime*, );


    int newsfeed_set_generator(newsfeed*, const(char)*, );



    int mailprivacy_msg_fetch_section(mailprivacy*, mailmessage*, mailmime*, char**, size_t*, );
    int mailimap_append_simple(mailimap*, const(char)*, const(char)*, size_t, );


    int mailmime_description_parse(const(char)*, size_t, size_t*, char**, );


    void mailimap_id_param_free(mailimap_id_param*, );
    alias dev_t = c_ulong;
    int mail_flags_add_extension(mail_flags*, char*, );


    void libetpan_engine_free(mailengine*, );
    int mh_mailstorage_init(mailstorage*, const(char)*, int, const(char)*, const(char)*, );
    int mailimap_socket_starttls_with_callback(mailimap*, void function(mailstream_ssl_context*, void*), void*, );
    enum _Anonymous_56
    {
        MAILSTREAM_CFSTREAM_SSL_LEVEL_NONE = 0,
        MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv2 = 1,
        MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv3 = 2,
        MAILSTREAM_CFSTREAM_SSL_LEVEL_TLSv1 = 3,
        MAILSTREAM_CFSTREAM_SSL_LEVEL_NEGOCIATED_SSL = 4,
    }
    enum MAILSTREAM_CFSTREAM_SSL_LEVEL_NONE = _Anonymous_56.MAILSTREAM_CFSTREAM_SSL_LEVEL_NONE;
    enum MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv2 = _Anonymous_56.MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv2;
    enum MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv3 = _Anonymous_56.MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv3;
    enum MAILSTREAM_CFSTREAM_SSL_LEVEL_TLSv1 = _Anonymous_56.MAILSTREAM_CFSTREAM_SSL_LEVEL_TLSv1;
    enum MAILSTREAM_CFSTREAM_SSL_LEVEL_NEGOCIATED_SSL = _Anonymous_56.MAILSTREAM_CFSTREAM_SSL_LEVEL_NEGOCIATED_SSL;
    alias __intmax_t = c_long;
    struct mailmime_composite_type
    {
        int ct_type;
        char* ct_token;
    }
    int mailimap_ssl_connect_voip_with_callback(mailimap*, const(char)*, uint16_t, int, void function(mailstream_ssl_context*, void*), void*, );
    enum _Anonymous_57
    {
        IMAP_SECTION_MESSAGE = 0,
        IMAP_SECTION_HEADER = 1,
        IMAP_SECTION_MIME = 2,
        IMAP_SECTION_BODY = 3,
    }
    enum IMAP_SECTION_MESSAGE = _Anonymous_57.IMAP_SECTION_MESSAGE;
    enum IMAP_SECTION_HEADER = _Anonymous_57.IMAP_SECTION_HEADER;
    enum IMAP_SECTION_MIME = _Anonymous_57.IMAP_SECTION_MIME;
    enum IMAP_SECTION_BODY = _Anonymous_57.IMAP_SECTION_BODY;


    int mailimap_fetch_qresync(mailimap*, mailimap_set*, mailimap_fetch_type*, uint64_t, clist**, mailimap_qresync_vanished**, );
    time_t newsfeed_item_get_date_published(newsfeed_item*, );
    struct maildir_cached_session_state_data
    {
        mailsession* md_ancestor;
        char* md_quoted_mb;
        mail_flags_store* md_flags_store;
        char[4096] md_cache_directory;
        char[4096] md_flags_directory;
    }


    int mailfolder_append_message_flags(mailfolder*, char*, size_t, mail_flags*, );
    const(char)* newsfeed_get_generator(newsfeed*, );


    int mailmime_substitute(mailmime*, mailmime*, );


    struct mailimap_quota_quota_data
    {
        char* quotaroot;
        clist* quota_list;
    }
    void mailpop3_set_timeout(mailpop3*, time_t, );
    mailmime_fields* mailmime_fields_new_with_data(mailmime_mechanism*, char*, char*, mailmime_disposition*, mailmime_language*, );


    int mailmbox_fetch_msg_headers(mailmbox_folder*, uint32_t, char**, size_t*, );
    void newsfeed_item_set_date_published(newsfeed_item*, time_t, );
    int mailmime_write_file(FILE*, int*, mailmime*, );
    mailimf_mailbox_list* mailimf_mailbox_list_new_empty();
    void mailmessage_free(mailmessage*, );
    int mailmime_base64_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, const(char)*, size_t, );


    int mailstream_low_get_fd(mailstream_low*, );


    alias __uintmax_t = c_ulong;
    int maildir_mailstorage_init(mailstorage*, const(char)*, int, const(char)*, const(char)*, );


    time_t mailsmtp_get_timeout(mailsmtp*, );
    int mbox_mailstorage_init(mailstorage*, const(char)*, int, const(char)*, const(char)*, );
    ssize_t mailstream_read(mailstream*, void*, size_t, );
    mailstream_low* mailstream_low_ssl_open_timeout(int, time_t, );






    alias clist = clist_s;
    int mailimap_msg_att_xgmlabels_add(mailimap_msg_att_xgmlabels*, char*, );



    mailimap_namespace_info* mailimap_namespace_info_new(char*, char, clist*, );
    int maildir_message_remove(maildir*, const(char)*, );
    int mailstream_send_data_crlf(mailstream*, const(char)*, size_t, size_t, progress_function*, );


    enum _Anonymous_58
    {
        MBOXDRIVER_CACHED_SET_READ_ONLY = 1,
        MBOXDRIVER_CACHED_SET_NO_UID = 2,
        MBOXDRIVER_CACHED_SET_CACHE_DIRECTORY = 3,
        MBOXDRIVER_CACHED_SET_FLAGS_DIRECTORY = 4,
    }
    enum MBOXDRIVER_CACHED_SET_READ_ONLY = _Anonymous_58.MBOXDRIVER_CACHED_SET_READ_ONLY;
    enum MBOXDRIVER_CACHED_SET_NO_UID = _Anonymous_58.MBOXDRIVER_CACHED_SET_NO_UID;
    enum MBOXDRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_58.MBOXDRIVER_CACHED_SET_CACHE_DIRECTORY;
    enum MBOXDRIVER_CACHED_SET_FLAGS_DIRECTORY = _Anonymous_58.MBOXDRIVER_CACHED_SET_FLAGS_DIRECTORY;
    mailstorage* mailstorage_new(const(char)*, );
    mailimap_qresync_resptextcode* mailimap_qresync_resptextcode_new(int, );
    mailimap_set_item* mailimap_set_item_new_single(uint32_t, );


    mailprivacy* libetpan_engine_get_privacy(mailengine*, );
    struct mailimap_condstore_search
    {
        clist* cs_search_result;
        uint64_t cs_modseq_value;
    }


    struct db_mailstorage
    {
        char* db_pathname;
    }
    uint newsfeed_item_list_get_count(newsfeed*, );


    int feed_mailstorage_init(mailstorage*, const(char)*, int, const(char)*, const(char)*, );
    mailimap_id_params_list* mailimap_id_params_list_new_empty();
    int libetpan_get_version_major();
    mailimap_uidplus_resp_code_apnd* mailimap_uidplus_resp_code_apnd_new(uint32_t, mailimap_set*, );
    alias clistiter = clistcell_s;


    struct newsfeed
    {
        char* feed_url;
        char* feed_title;
        char* feed_description;
        char* feed_language;
        char* feed_author;
        char* feed_generator;
        time_t feed_date;
        carray* feed_item_list;
        int feed_response_code;
        uint feed_timeout;
    }


    void mailsession_free(mailsession*, );
    char* mailmime_extract_boundary(mailmime_content*, );
    int mailimap_login_simple(mailimap*, const(char)*, const(char)*, );
    int mailimap_uidplus_move(mailimap*, mailimap_set*, const(char)*, uint32_t*, mailimap_set**, mailimap_set**, );
    int mailesmtp_send_quit(mailsmtp*, const(char)*, int, const(char)*, clist*, const(char)*, size_t, );
    int libetpan_get_version_minor();
    int mailimap_uid_fetch_changedsince(mailimap*, mailimap_set*, mailimap_fetch_type*, uint64_t, clist**, );
    extern __gshared int function(const(char)*, const(char)*, const(char)*, c_ulong, char*, c_ulong*) extended_charconv;



    void mailimap_msg_att_xgmlabels_free(mailimap_msg_att_xgmlabels*, );
    struct pop3_session_state_data
    {
        int pop3_auth_type;
        mailpop3* pop3_session;
        void function(mailstream_ssl_context*, void*) pop3_ssl_callback;
        void* pop3_ssl_cb_data;
    }


    int maildir_message_change_flags(maildir*, const(char)*, int, );
    struct mailmh_msg_info
    {
        uint msg_array_index;
        uint32_t msg_index;
        size_t msg_size;
        time_t msg_mtime;
    }
    time_t newsfeed_item_get_date_modified(newsfeed_item*, );


    time_t mailpop3_get_timeout(mailpop3*, );




    int mailmime_quoted_printable_write_mem(MMAPString*, int*, int, const(char)*, size_t, );


    newsfeed_item* newsfeed_get_item(newsfeed*, uint, );
    struct_mailstream_cancel* mailstream_low_get_cancel(mailstream_low*, );
    int mailsmtp_connect(mailsmtp*, mailstream*, );


    mailstream_low* mailstream_low_tls_open(int, );
    struct mailmbox_folder
    {
        char[4096] mb_filename;
        time_t mb_mtime;
        int mb_fd;
        int mb_read_only;
        int mb_no_uid;
        int mb_changed;
        uint mb_deleted_count;
        char* mb_mapping;
        size_t mb_mapping_size;
        uint32_t mb_written_uid;
        uint32_t mb_max_uid;
        chash* mb_hash;
        carray* mb_tab;
    }
    int mailfolder_get_messages_list(mailfolder*, mailmessage_list**, );
    struct mh_cached_session_state_data
    {
        mailsession* mh_ancestor;
        char* mh_quoted_mb;
        char[4096] mh_cache_directory;
        char[4096] mh_flags_directory;
        mail_flags_store* mh_flags_store;
    }
    alias gid_t = uint;
    struct chashcell
    {
        uint func;
        chashdatum key;
        chashdatum value;
        chashcell* next;
    }
    int mailmime_data_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailmime_data*, int, );
    int mailstream_close(mailstream*, );


    int mailimap_sort(mailimap*, const(char)*, mailimap_sort_key*, mailimap_search_key*, clist**, );
    struct __pthread_rwlock_arch_t
    {
        uint __readers;
        uint __writers;
        uint __wrphase_futex;
        uint __writers_futex;
        uint __pad3;
        uint __pad4;
        int __cur_writer;
        int __shared;
        byte __rwelision;
        ubyte[7] __pad1;
        c_ulong __pad2;
        uint __flags;
    }
    int mailprivacy_fetch_mime_body_to_file(mailprivacy*, char*, size_t, mailmessage*, mailmime*, );




    int mailmime_location_parse(const(char)*, size_t, size_t*, char**, );
    int carray_add(carray*, void*, uint*, );
    void newsfeed_item_set_date_modified(newsfeed_item*, time_t, );


    void newsfeed_set_date(newsfeed*, time_t, );
    void mailmbox_fetch_result_free(char*, );
    int mailprivacy_msg_fetch_section_header(mailprivacy*, mailmessage*, mailmime*, char**, size_t*, );
    int mailmime_quoted_printable_write_file(FILE*, int*, int, const(char)*, size_t, );
    void mailstorage_free(mailstorage*, );
    int mailimap_annotatemore_getannotation(mailimap*, const(char)*, mailimap_annotatemore_entry_match_list*, mailimap_annotatemore_attrib_match_list*, clist**, );


    int mailimap_has_compress_deflate(mailimap*, );
    int mailimap_id_params_list_add_name_value(mailimap_id_params_list*, char*, char*, );






    void mailimap_namespace_info_free(mailimap_namespace_info*, );
    void mailimap_qresync_resptextcode_free(mailimap_qresync_resptextcode*, );






    clist* clist_new();


    time_t newsfeed_get_date(newsfeed*, );
    void mailpop3_set_progress_callback(mailpop3*, mailprogress_function*, void*, );
    int mailimap_uid_fetch_qresync(mailimap*, mailimap_set*, mailimap_fetch_type*, uint64_t, clist**, mailimap_qresync_vanished**, );
    mailimap_sort_key* mailimap_sort_key_new(int, int, clist*, );
    union _Anonymous_59
    {
        __pthread_mutex_s __data;
        char[40] __size;
        c_long __align;
    }
    void mailimap_uidplus_resp_code_apnd_free(mailimap_uidplus_resp_code_apnd*, );
    int mailimap_store_xgmlabels(mailimap*, mailimap_set*, int, int, mailimap_msg_att_xgmlabels*, );
    int mailstream_send_data_crlf_with_context(mailstream*, const(char)*, size_t, mailprogress_function*, void*, );




    enum _Anonymous_60
    {
        MAILIMAP_EXTENDED_PARSER_RESPONSE_DATA = 0,
        MAILIMAP_EXTENDED_PARSER_RESP_TEXT_CODE = 1,
        MAILIMAP_EXTENDED_PARSER_MAILBOX_DATA = 2,
        MAILIMAP_EXTENDED_PARSER_FETCH_DATA = 3,
        MAILIMAP_EXTENDED_PARSER_STATUS_ATT = 4,
    }
    enum MAILIMAP_EXTENDED_PARSER_RESPONSE_DATA = _Anonymous_60.MAILIMAP_EXTENDED_PARSER_RESPONSE_DATA;
    enum MAILIMAP_EXTENDED_PARSER_RESP_TEXT_CODE = _Anonymous_60.MAILIMAP_EXTENDED_PARSER_RESP_TEXT_CODE;
    enum MAILIMAP_EXTENDED_PARSER_MAILBOX_DATA = _Anonymous_60.MAILIMAP_EXTENDED_PARSER_MAILBOX_DATA;
    enum MAILIMAP_EXTENDED_PARSER_FETCH_DATA = _Anonymous_60.MAILIMAP_EXTENDED_PARSER_FETCH_DATA;
    enum MAILIMAP_EXTENDED_PARSER_STATUS_ATT = _Anonymous_60.MAILIMAP_EXTENDED_PARSER_STATUS_ATT;
    newsfeed_item_enclosure* newsfeed_item_get_enclosure(newsfeed_item*, );
    struct mailmime_content
    {
        mailmime_type* ct_type;
        char* ct_subtype;
        clist* ct_parameters;
    }
    struct mailprivacy_protocol
    {
        char* name;
        char* description;
        int function(mailprivacy*, mailmessage*, mailmime*) is_encrypted;
        int function(mailprivacy*, mailmessage*, mailmime*, mailmime**) decrypt;
        int encryption_count;
        mailprivacy_encryption* encryption_tab;
    }
    alias pthread_mutex_t = _Anonymous_59;


    int mailmime_base64_write_mem(MMAPString*, int*, const(char)*, size_t, );
    void mailstream_low_free(mailstream_low*, );
    int mailmbox_copy_msg_list(mailmbox_folder*, mailmbox_folder*, carray*, );
    mailstream_low* mailstream_low_tls_open_timeout(int, time_t, );
    enum _Anonymous_61
    {
        ILL_ILLOPC = 1,
        ILL_ILLOPN = 2,
        ILL_ILLADR = 3,
        ILL_ILLTRP = 4,
        ILL_PRVOPC = 5,
        ILL_PRVREG = 6,
        ILL_COPROC = 7,
        ILL_BADSTK = 8,
    }
    enum ILL_ILLOPC = _Anonymous_61.ILL_ILLOPC;
    enum ILL_ILLOPN = _Anonymous_61.ILL_ILLOPN;
    enum ILL_ILLADR = _Anonymous_61.ILL_ILLADR;
    enum ILL_ILLTRP = _Anonymous_61.ILL_ILLTRP;
    enum ILL_PRVOPC = _Anonymous_61.ILL_PRVOPC;
    enum ILL_PRVREG = _Anonymous_61.ILL_PRVREG;
    enum ILL_COPROC = _Anonymous_61.ILL_COPROC;
    enum ILL_BADSTK = _Anonymous_61.ILL_BADSTK;
    void newsfeed_item_set_enclosure(newsfeed_item*, newsfeed_item_enclosure*, );
    int mailimap_extension_data_parse(int, mailstream*, MMAPString*, mailimap_parser_context*, size_t*, mailimap_extension_data**, size_t, progress_function*, );
    int gettimeofday(timeval*, __timezone_ptr_t, );
    alias __sighandler_t = void function(int);
    alias int_fast8_t = byte;
    int charconv(const(char)*, const(char)*, const(char)*, size_t, char**, );
    struct maildir_msg
    {
        char* msg_uid;
        char* msg_filename;
        int msg_flags;
    }
    int mailstream_flush(mailstream*, );
    struct mailimap_condstore_status_info
    {
        uint64_t cs_highestmodseq_value;
    }
    struct mailimap_namespace_item
    {
        clist* ns_data_list;
    }
    int carray_set_size(carray*, uint, );


    mailimap_quota_quota_data* mailimap_quota_quota_data_new(char*, clist*, );
    int mailsmtp_quit(mailsmtp*, );
    mailmime_fields* mailmime_fields_new_with_version(mailmime_mechanism*, char*, char*, mailmime_disposition*, mailmime_language*, );


    void mailprivacy_smime_set_CA_check(mailprivacy*, int, );
    int mailfolder_get_envelopes_list(mailfolder*, mailmessage_list*, );
    void newsfeed_set_timeout(newsfeed*, uint, );


    int mailmime_encoding_parse(const(char)*, size_t, size_t*, mailmime_mechanism**, );
    enum _Anonymous_62
    {
        IMAPDRIVER_CACHED_SET_SSL_CALLBACK = 1,
        IMAPDRIVER_CACHED_SET_SSL_CALLBACK_DATA = 2,
        IMAPDRIVER_CACHED_SET_CACHE_DIRECTORY = 1001,
    }
    enum IMAPDRIVER_CACHED_SET_SSL_CALLBACK = _Anonymous_62.IMAPDRIVER_CACHED_SET_SSL_CALLBACK;
    enum IMAPDRIVER_CACHED_SET_SSL_CALLBACK_DATA = _Anonymous_62.IMAPDRIVER_CACHED_SET_SSL_CALLBACK_DATA;
    enum IMAPDRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_62.IMAPDRIVER_CACHED_SET_CACHE_DIRECTORY;
    alias mode_t = uint;


    alias int_fast16_t = c_long;


    int mailmime_base64_body_parse(const(char)*, size_t, size_t*, char**, size_t*, );
    int mailpop3_connect(mailpop3*, mailstream*, );
    int mailprivacy_get_part_from_file(mailprivacy*, int, int, char*, mailmime**, );
    extern __gshared mailstream_low_driver* mailstream_cfstream_driver;


    mailimap_fetch_att* mailimap_fetch_att_new_modseq();
    mailimap_uidplus_resp_code_copy* mailimap_uidplus_resp_code_copy_new(uint32_t, mailimap_set*, mailimap_set*, );


    int mailmime_base64_write_file(FILE*, int*, const(char)*, size_t, );
    int mail_build_thread(int, char*, mailmessage_list*, mailmessage_tree**, int function(mailmessage_tree**, mailmessage_tree**), );
    uint newsfeed_get_timeout(newsfeed*, );
    mailimap_set* mailimap_set_new_single_item(mailimap_set_item*, );


    newsnntp* newsnntp_new(size_t, progress_function*, );
    void clist_free(clist*, );
    int mailesmtp_send_quit_no_disconnect(mailsmtp*, const(char)*, int, const(char)*, clist*, const(char)*, size_t, );


    struct mailpop3
    {
        char* pop3_response;
        char* pop3_timestamp;
        mailstream* pop3_stream;
        size_t pop3_progr_rate;
        progress_function* pop3_progr_fun;
        MMAPString* pop3_stream_buffer;
        MMAPString* pop3_response_buffer;
        carray* pop3_msg_tab;
        int pop3_state;
        uint pop3_deleted_count;
        struct _Anonymous_63
        {
            void* sasl_conn;
            const(char)* sasl_server_fqdn;
            const(char)* sasl_login;
            const(char)* sasl_auth_name;
            const(char)* sasl_password;
            const(char)* sasl_realm;
            void* sasl_secret;
        }
        _Anonymous_63 pop3_sasl;
        time_t pop3_timeout;
        mailprogress_function* pop3_progress_fun;
        void* pop3_progress_context;
        void function(mailpop3*, int, const(char)*, c_ulong, void*) pop3_logger;
        void* pop3_logger_context;
    }
    void mailstream_low_cancel(mailstream_low*, );


    alias int_fast32_t = c_long;
    void mmap_string_set_tmpdir(const(char)*, );


    int mailimf_fields_write_file(FILE*, int*, mailimf_fields*, );
    ssize_t mailstream_feed_read_buffer(mailstream*, );


    int mailimap_uidplus_uid_move(mailimap*, mailimap_set*, const(char)*, uint32_t*, mailimap_set**, mailimap_set**, );




    mailstream* mailstream_ssl_open(int, );


    int mailimf_message_parse(const(char)*, size_t, size_t*, mailimf_message**, );
    struct mailmh_folder
    {
        char* fl_filename;
        uint fl_array_index;
        char* fl_name;
        time_t fl_mtime;
        mailmh_folder* fl_parent;
        uint32_t fl_max_index;
        carray* fl_msgs_tab;
        chash* fl_msgs_hash;
        carray* fl_subfolders_tab;
        chash* fl_subfolders_hash;
    }
    int mailimf_fields_write_mem(MMAPString*, int*, mailimf_fields*, );
    alias int_fast64_t = c_long;
    int mailstream_send_data(mailstream*, const(char)*, size_t, size_t, progress_function*, );
    void mailimap_quota_quota_data_free(mailimap_quota_quota_data*, );
    alias chashiter = chashcell;




    mailstream* mailstream_cfstream_open(const(char)*, int16_t, );
    int mailmime_data_write_mem(MMAPString*, int*, mailmime_data*, int, );


    int mailimf_fields_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailimf_fields*, );




    int newsfeed_add_item(newsfeed*, newsfeed_item*, );
    struct mbox_cached_session_state_data
    {
        mailsession* mbox_ancestor;
        char* mbox_quoted_mb;
        char[4096] mbox_cache_directory;
        char[4096] mbox_flags_directory;
        mail_flags_store* mbox_flags_store;
    }


    int mailmbox_copy_msg(mailmbox_folder*, mailmbox_folder*, uint32_t, );
    clock_t clock();




    int mailimap_acl_setacl(mailimap*, const(char)*, const(char)*, const(char)*, );
    mailstream* mailstream_cfstream_open_timeout(const(char)*, int16_t, time_t, );
    int mailimf_mailbox_list_add(mailimf_mailbox_list*, mailimf_mailbox*, );




    int mailpop3_quit(mailpop3*, );
    enum _Anonymous_64
    {
        POP3DRIVER_CACHED_SET_AUTH_TYPE = 1,
        POP3DRIVER_CACHED_SET_SSL_CALLBACK = 2,
        POP3DRIVER_CACHED_SET_SSL_CALLBACK_DATA = 3,
        POP3DRIVER_CACHED_SET_CACHE_DIRECTORY = 1001,
        POP3DRIVER_CACHED_SET_FLAGS_DIRECTORY = 1002,
    }
    enum POP3DRIVER_CACHED_SET_AUTH_TYPE = _Anonymous_64.POP3DRIVER_CACHED_SET_AUTH_TYPE;
    enum POP3DRIVER_CACHED_SET_SSL_CALLBACK = _Anonymous_64.POP3DRIVER_CACHED_SET_SSL_CALLBACK;
    enum POP3DRIVER_CACHED_SET_SSL_CALLBACK_DATA = _Anonymous_64.POP3DRIVER_CACHED_SET_SSL_CALLBACK_DATA;
    enum POP3DRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_64.POP3DRIVER_CACHED_SET_CACHE_DIRECTORY;
    enum POP3DRIVER_CACHED_SET_FLAGS_DIRECTORY = _Anonymous_64.POP3DRIVER_CACHED_SET_FLAGS_DIRECTORY;




    int mailimap_has_qresync(mailimap*, );
    int mailimap_search_modseq(mailimap*, const(char)*, mailimap_search_key*, clist**, uint64_t*, );
    mailimap_condstore_fetch_mod_resp* mailimap_condstore_fetch_mod_resp_new(uint64_t, );
    int mailstorage_connect(mailstorage*, );
    int carray_delete(carray*, uint, );
    int charconv_buffer(const(char)*, const(char)*, const(char)*, size_t, char**, size_t*, );
    mailimap_namespace_item* mailimap_namespace_item_new(clist*, );


    void mailimap_sort_key_free(mailimap_sort_key*, );


    int mailfolder_get_message(mailfolder*, uint32_t, mailmessage**, );
    int mailprivacy_msg_fetch_section_mime(mailprivacy*, mailmessage*, mailmime*, char**, size_t*, );
    uint gnu_dev_major(__dev_t, );
    __sighandler_t __sysv_signal(int, __sighandler_t, );


    int mailimap_uid_store_xgmlabels(mailimap*, mailimap_set*, int, int, mailimap_msg_att_xgmlabels*, );
    mailstream* mailstream_cfstream_open_voip(const(char)*, int16_t, int, );
    enum _Anonymous_65
    {
        MAILMIME_DISCRETE_TYPE_ERROR = 0,
        MAILMIME_DISCRETE_TYPE_TEXT = 1,
        MAILMIME_DISCRETE_TYPE_IMAGE = 2,
        MAILMIME_DISCRETE_TYPE_AUDIO = 3,
        MAILMIME_DISCRETE_TYPE_VIDEO = 4,
        MAILMIME_DISCRETE_TYPE_APPLICATION = 5,
        MAILMIME_DISCRETE_TYPE_EXTENSION = 6,
    }
    enum MAILMIME_DISCRETE_TYPE_ERROR = _Anonymous_65.MAILMIME_DISCRETE_TYPE_ERROR;
    enum MAILMIME_DISCRETE_TYPE_TEXT = _Anonymous_65.MAILMIME_DISCRETE_TYPE_TEXT;
    enum MAILMIME_DISCRETE_TYPE_IMAGE = _Anonymous_65.MAILMIME_DISCRETE_TYPE_IMAGE;
    enum MAILMIME_DISCRETE_TYPE_AUDIO = _Anonymous_65.MAILMIME_DISCRETE_TYPE_AUDIO;
    enum MAILMIME_DISCRETE_TYPE_VIDEO = _Anonymous_65.MAILMIME_DISCRETE_TYPE_VIDEO;
    enum MAILMIME_DISCRETE_TYPE_APPLICATION = _Anonymous_65.MAILMIME_DISCRETE_TYPE_APPLICATION;
    enum MAILMIME_DISCRETE_TYPE_EXTENSION = _Anonymous_65.MAILMIME_DISCRETE_TYPE_EXTENSION;
    int newsfeed_update(newsfeed*, time_t, );


    struct mailmessage_list
    {
        carray* msg_tab;
    }
    mailstream* mailstream_ssl_open_timeout(int, time_t, );
    void mailstream_log_error(mailstream*, char*, size_t, );


    void mailstream_low_log_error(mailstream_low*, const(void)*, size_t, );


    int settimeofday(const(timeval)*, const(timezone)*, );
    uint gnu_dev_minor(__dev_t, );
    int mailmime_data_write_file(FILE*, int*, mailmime_data*, int, );
    void mailimap_uidplus_resp_code_copy_free(mailimap_uidplus_resp_code_copy*, );
    struct _mailstream
    {
        size_t buffer_max_size;
        char* write_buffer;
        size_t write_buffer_len;
        char* read_buffer;
        size_t read_buffer_len;
        mailstream_low* low;
        struct_mailstream_cancel* idle;
        int idling;
        void function(_mailstream*, int, const(char)*, c_ulong, void*) logger;
        void* logger_context;
    }
    mailstream* mailstream_cfstream_open_voip_timeout(const(char)*, int16_t, int, time_t, );


    int mailmime_field_parse(mailimf_optional_field*, mailmime_field**, );
    union _Anonymous_66
    {
        __pthread_cond_s __data;
        char[48] __size;
        long __align;
    }
    enum _Anonymous_67
    {
        NNTPDRIVER_CACHED_SET_MAX_ARTICLES = 1,
        NNTPDRIVER_CACHED_SET_CACHE_DIRECTORY = 2,
        NNTPDRIVER_CACHED_SET_FLAGS_DIRECTORY = 3,
    }
    enum NNTPDRIVER_CACHED_SET_MAX_ARTICLES = _Anonymous_67.NNTPDRIVER_CACHED_SET_MAX_ARTICLES;
    enum NNTPDRIVER_CACHED_SET_CACHE_DIRECTORY = _Anonymous_67.NNTPDRIVER_CACHED_SET_CACHE_DIRECTORY;
    enum NNTPDRIVER_CACHED_SET_FLAGS_DIRECTORY = _Anonymous_67.NNTPDRIVER_CACHED_SET_FLAGS_DIRECTORY;


    __dev_t gnu_dev_makedev(uint, uint, );
    int mailmime_quoted_printable_body_parse(const(char)*, size_t, size_t*, char**, size_t*, int, );






    alias pthread_cond_t = _Anonymous_66;
    alias nlink_t = c_ulong;




    time_t time(time_t*, );




    MMAPString* mmap_string_new(const(char)*, );
    mailimap_sort_key* mailimap_sort_key_new_arrival(int, );


    int mail_flags_remove_extension(mail_flags*, char*, );


    void mailstorage_disconnect(mailstorage*, );
    void mailimap_condstore_fetch_mod_resp_free(mailimap_condstore_fetch_mod_resp*, );
    int mailmbox_expunge(mailmbox_folder*, );


    mailimap_extension_data* mailimap_extension_data_new(mailimap_extension_api*, int, void*, );
    int mailpop3_apop(mailpop3*, const(char)*, const(char)*, );


    int mail_quote_filename(char*, size_t, char*, );
    void mailimap_namespace_item_free(mailimap_namespace_item*, );


    struct imap_cached_session_state_data
    {
        mailsession* imap_ancestor;
        char* imap_quoted_mb;
        char[4096] imap_cache_directory;
        carray* imap_uid_list;
        uint32_t imap_uidvalidity;
    }
    int mailimap_uid_search_modseq(mailimap*, const(char)*, mailimap_search_key*, clist**, uint64_t*, );
    struct mailimap_quota_quotaroot_data
    {
        char* mailbox;
        clist* quotaroot_list;
    }


    struct newsfeed_item
    {
        char* fi_url;
        char* fi_title;
        char* fi_summary;
        char* fi_text;
        char* fi_author;
        char* fi_id;
        time_t fi_date_published;
        time_t fi_date_modified;
        newsfeed* fi_feed;
        newsfeed_item_enclosure* fi_enclosure;
    }
    mailmime_content* mailmime_get_content_message();


    mailstream_low* mailstream_get_low(mailstream*, );
    int mailsmtp_auth(mailsmtp*, const(char)*, const(char)*, );


    alias fd_mask = c_long;
    int mailstream_send_data_with_context(mailstream*, const(char)*, size_t, mailprogress_function*, void*, );


    void mailimap_uidplus_free(mailimap_extension_data*, );
    int mailfolder_get_message_by_uid(mailfolder*, const(char)*, mailmessage**, );






    mailstream* mailstream_ssl_open_with_callback(int, void function(mailstream_ssl_context*, void*), void*, );
    mailstream_low* mailstream_low_cfstream_open(const(char)*, int16_t, );


    void mailprivacy_smime_set_store_cert(mailprivacy*, int, );


    void mailstream_low_set_privacy(mailstream_low*, int, );
    double difftime(time_t, time_t, );


    int libetpan_message_ref(mailengine*, mailmessage*, );


    int mailmbox_delete_msg(mailmbox_folder*, uint32_t, );
    enum _Anonymous_68
    {
        MAILSMTP_AUTH_NOT_CHECKED = 0,
        MAILSMTP_AUTH_CHECKED = 1,
        MAILSMTP_AUTH_CRAM_MD5 = 2,
        MAILSMTP_AUTH_PLAIN = 4,
        MAILSMTP_AUTH_LOGIN = 8,
        MAILSMTP_AUTH_DIGEST_MD5 = 16,
        MAILSMTP_AUTH_GSSAPI = 32,
        MAILSMTP_AUTH_SRP = 64,
        MAILSMTP_AUTH_NTLM = 128,
        MAILSMTP_AUTH_KERBEROS_V4 = 256,
    }
    enum MAILSMTP_AUTH_NOT_CHECKED = _Anonymous_68.MAILSMTP_AUTH_NOT_CHECKED;
    enum MAILSMTP_AUTH_CHECKED = _Anonymous_68.MAILSMTP_AUTH_CHECKED;
    enum MAILSMTP_AUTH_CRAM_MD5 = _Anonymous_68.MAILSMTP_AUTH_CRAM_MD5;
    enum MAILSMTP_AUTH_PLAIN = _Anonymous_68.MAILSMTP_AUTH_PLAIN;
    enum MAILSMTP_AUTH_LOGIN = _Anonymous_68.MAILSMTP_AUTH_LOGIN;
    enum MAILSMTP_AUTH_DIGEST_MD5 = _Anonymous_68.MAILSMTP_AUTH_DIGEST_MD5;
    enum MAILSMTP_AUTH_GSSAPI = _Anonymous_68.MAILSMTP_AUTH_GSSAPI;
    enum MAILSMTP_AUTH_SRP = _Anonymous_68.MAILSMTP_AUTH_SRP;
    enum MAILSMTP_AUTH_NTLM = _Anonymous_68.MAILSMTP_AUTH_NTLM;
    enum MAILSMTP_AUTH_KERBEROS_V4 = _Anonymous_68.MAILSMTP_AUTH_KERBEROS_V4;
    struct mailimap_namespace_data
    {
        mailimap_namespace_item* ns_personal;
        mailimap_namespace_item* ns_other;
        mailimap_namespace_item* ns_shared;
    }
    int mailsession_parameters(mailsession*, int, void*, );
    void charconv_buffer_free(char*, );
    alias fpos_t = _G_fpos_t;
    int carray_delete_slow(carray*, uint, );
    mailimap_set* mailimap_set_new_interval(uint32_t, uint32_t, );


    int mailimap_uidplus_append(mailimap*, const(char)*, mailimap_flag_list*, mailimap_date_time*, const(char)*, size_t, uint32_t*, uint32_t*, );


    int mailstorage_noop(mailstorage*, );
    struct mailimf_date_time
    {
        int dt_day;
        int dt_month;
        int dt_year;
        int dt_hour;
        int dt_min;
        int dt_sec;
        int dt_zone;
    }
    MMAPString* mmap_string_new_len(const(char)*, size_t, );
    mailstream_low* mailstream_low_cfstream_open_timeout(const(char)*, int16_t, time_t, );
    mailmessage_list* mailmessage_list_new(carray*, );
    mailimap_condstore_resptextcode* mailimap_condstore_resptextcode_new(int, uint64_t, mailimap_set*, );


    int mailsmtp_send(mailsmtp*, const(char)*, clist*, const(char)*, size_t, );




    mailmime_content* mailmime_get_content_text();
    void mailprivacy_prepare_mime(mailmime*, );
    int mailpop3_user(mailpop3*, const(char)*, );






    alias uid_t = uint;
    void mailstream_set_low(mailstream*, mailstream_low*, );
    int mailprivacy_msg_fetch_section_body(mailprivacy*, mailmessage*, mailmime*, char**, size_t*, );
    int mailmbox_init(const(char)*, int, int, uint32_t, mailmbox_folder**, );


    mailimap_sort_key* mailimap_sort_key_new_cc(int, );
    struct newsnntp
    {
        mailstream* nntp_stream;
        int nntp_readonly;
        size_t nntp_progr_rate;
        progress_function* nntp_progr_fun;
        MMAPString* nntp_stream_buffer;
        MMAPString* nntp_response_buffer;
        char* nntp_response;
        time_t nntp_timeout;
        void function(newsnntp*, int, const(char)*, c_ulong, void*) nntp_logger;
        void* nntp_logger_context;
        mailprogress_function* nntp_progress_fun;
        void* nntp_progress_context;
    }
    int mailmime_id_parse(const(char)*, size_t, size_t*, char**, );
    int mailimap_search_literalplus_modseq(mailimap*, const(char)*, mailimap_search_key*, clist**, uint64_t*, );
    int mailmime_binary_body_parse(const(char)*, size_t, size_t*, char**, size_t*, );


    mailstream_low* mailstream_low_cfstream_open_voip(const(char)*, int16_t, int, );


    mailstream* mailstream_ssl_open_with_callback_timeout(int, time_t, void function(mailstream_ssl_context*, void*), void*, );
    int mailstream_low_set_identifier(mailstream_low*, char*, );


    int libetpan_message_unref(mailengine*, mailmessage*, );


    alias uint_fast8_t = ubyte;




    int carray_delete_fast(carray*, uint, );
    alias __pthread_list_t = __pthread_internal_list;
    char* mailprivacy_dup_imf_file(mailprivacy*, char*, );
    struct __pthread_internal_list
    {
        __pthread_internal_list* __prev;
        __pthread_internal_list* __next;
    }


    void mailmessage_list_free(mailmessage_list*, );
    mailstream_low* mailstream_low_cfstream_open_voip_timeout(const(char)*, int16_t, int, time_t, );
    struct maildir
    {
        pid_t mdir_pid;
        char[64] mdir_hostname;
        char[4096] mdir_path;
        uint32_t mdir_counter;
        time_t mdir_mtime_new;
        time_t mdir_mtime_cur;
        carray* mdir_msg_list;
        chash* mdir_msg_hash;
    }
    int adjtime(const(timeval)*, timeval*, );
    time_t mktime(tm*, );




    int imap_mailstorage_init(mailstorage*, const(char)*, uint16_t, const(char)*, int, int, const(char)*, const(char)*, int, const(char)*, );
    int mailpop3_pass(mailpop3*, const(char)*, );


    int nntp_mailstorage_init(mailstorage*, const(char)*, uint16_t, const(char)*, int, int, const(char)*, const(char)*, int, const(char)*, const(char)*, );


    size_t mailstream_get_data_crlf_size(const(char)*, size_t, );


    alias uint_fast16_t = c_ulong;
    struct nntp_cached_session_state_data
    {
        mailsession* nntp_ancestor;
        char[4096] nntp_cache_directory;
        char[4096] nntp_flags_directory;
        mail_flags_store* nntp_flags_store;
    }


    void mailimap_condstore_resptextcode_free(mailimap_condstore_resptextcode*, );


    void mailstream_cancel(mailstream*, );
    int mailmime_fields_write(FILE*, int*, mailmime_fields*, );


    MMAPString* mmap_string_sized_new(size_t, );


    struct pop3_cached_session_state_data
    {
        mailsession* pop3_ancestor;
        char[4096] pop3_cache_directory;
        char[4096] pop3_flags_directory;
        chash* pop3_flags_hash;
        carray* pop3_flags_array;
        mail_flags_store* pop3_flags_store;
    }






    mailimap_quota_quotaroot_data* mailimap_quota_quotaroot_data_new(char*, clist*, );


    alias uint_fast32_t = c_ulong;


    void newsnntp_free(newsnntp*, );
    struct maildir_mailstorage
    {
        char* md_pathname;
        int md_cached;
        char* md_cache_directory;
        char* md_flags_directory;
    }
    int pop3_mailstorage_init(mailstorage*, const(char)*, uint16_t, const(char)*, int, int, const(char)*, const(char)*, int, const(char)*, const(char)*, );
    int mailmime_fields_parse(mailimf_fields*, mailmime_fields**, );
    struct mailmime_discrete_type
    {
        int dt_type;
        char* dt_extension;
    }
    mailimap_sort_key* mailimap_sort_key_new_date(int, );


    int mailimf_envelope_fields_write_file(FILE*, int*, mailimf_fields*, );
    __sighandler_t signal(int, __sighandler_t, );
    int mailpop3_list(mailpop3*, carray**, );


    int mailimf_mailbox_list_add_parse(mailimf_mailbox_list*, char*, );
    mailimap_namespace_data* mailimap_namespace_data_new(mailimap_namespace_item*, mailimap_namespace_item*, mailimap_namespace_item*, );
    const(char)* mailstream_low_get_identifier(mailstream_low*, );
    clist* esmtp_address_list_new();
    mailfolder* mailfolder_new(mailstorage*, const(char)*, const(char)*, );
    void mailstream_gnutls_init_not_required();
    alias uint_fast64_t = c_ulong;
    mailimap_set* mailimap_set_new_single(uint32_t, );
    mailmime_data* mailmime_data_new_data(int, int, const(char)*, size_t, );




    int mailsmtp_auth_type(mailsmtp*, const(char)*, const(char)*, int, );
    int mailimap_uid_search_literalplus_modseq(mailimap*, const(char)*, mailimap_search_key*, clist**, uint64_t*, );
    void mailimap_extension_data_free(mailimap_extension_data*, );
    union _Anonymous_69
    {
        __pthread_rwlock_arch_t __data;
        char[56] __size;
        c_long __align;
    }
    int mailimap_uidplus_append_simple(mailimap*, const(char)*, const(char)*, size_t, uint32_t*, uint32_t*, );
    void mmap_string_free(MMAPString*, );


    alias pthread_rwlock_t = _Anonymous_69;
    int mailimf_envelope_fields_write_mem(MMAPString*, int*, mailimf_fields*, );
    void mailstream_cfstream_set_ssl_verification_mask(mailstream*, int, );
    void mailstream_set_privacy(mailstream*, int, );


    void mailmbox_done(mailmbox_folder*, );
    mailimap_condstore_search* mailimap_condstore_search_new(clist*, uint64_t, );




    struct mailimap_extension_api
    {
        char* ext_name;
        int ext_id;
        int function(int, _mailstream*, _MMAPString*, mailimap_parser_context*, c_ulong*, mailimap_extension_data**, c_ulong, void function(c_ulong, c_ulong)*) ext_parser;
        void function(mailimap_extension_data*) ext_free;
    }


    mailmime_fields* mailprivacy_mime_fields_dup(mailprivacy*, mailmime_fields*, );
    alias off_t = c_long;




    int mailimf_envelope_fields_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailimf_fields*, );




    void mailprivacy_msg_fetch_result_free(mailprivacy*, mailmessage*, char*, );
    mailmh* mailmh_new(const(char)*, );


    void mailstream_cfstream_set_ssl_peer_name(mailstream*, const(char)*, );


    int mailmime_content_write(FILE*, int*, mailmime_content*, );
    mailmbox_folder* mailmbox_folder_new(const(char)*, );
    void mailmbox_folder_free(mailmbox_folder*, );
    int esmtp_address_list_add(clist*, char*, int, char*, );
    mailimap_sort_key* mailimap_sort_key_new_from(int, );


    size_t strftime(char*, size_t, const(char)*, const(tm)*, );
    int mailmessage_init(mailmessage*, mailsession*, mailmessage_driver*, uint32_t, size_t, );
    int mailpop3_retr(mailpop3*, uint, char**, size_t*, );
    void mailstream_openssl_init_not_required();


    void mailimap_quota_quotaroot_data_free(mailimap_quota_quotaroot_data*, );


    void mailprivacy_smime_set_private_keys_dir(mailprivacy*, char*, );
    void mailstream_low_set_timeout(mailstream_low*, time_t, );
    void mailmh_free(mailmh*, );
    void mailstream_cfstream_set_ssl_is_server(mailstream*, int, );




    enum __itimer_which
    {
        ITIMER_REAL = 0,
        ITIMER_VIRTUAL = 1,
        ITIMER_PROF = 2,
    }
    enum ITIMER_REAL = __itimer_which.ITIMER_REAL;
    enum ITIMER_VIRTUAL = __itimer_which.ITIMER_VIRTUAL;
    enum ITIMER_PROF = __itimer_which.ITIMER_PROF;


    struct mh_mailstorage
    {
        char* mh_pathname;
        int mh_cached;
        char* mh_cache_directory;
        char* mh_flags_directory;
    }


    int mailimap_select_condstore(mailimap*, const(char)*, uint64_t*, );
    void mailimap_condstore_search_free(mailimap_condstore_search*, );
    int mailimap_connect(mailimap*, mailstream*, );
    chash* chash_new(uint, int, );
    int mailsmtp_helo(mailsmtp*, );
    int mailimf_body_parse(const(char)*, size_t, size_t*, mailimf_body**, );
    void mailfolder_free(mailfolder*, );
    enum _Anonymous_70
    {
        FPE_INTDIV = 1,
        FPE_INTOVF = 2,
        FPE_FLTDIV = 3,
        FPE_FLTOVF = 4,
        FPE_FLTUND = 5,
        FPE_FLTRES = 6,
        FPE_FLTINV = 7,
        FPE_FLTSUB = 8,
    }
    enum FPE_INTDIV = _Anonymous_70.FPE_INTDIV;
    enum FPE_INTOVF = _Anonymous_70.FPE_INTOVF;
    enum FPE_FLTDIV = _Anonymous_70.FPE_FLTDIV;
    enum FPE_FLTOVF = _Anonymous_70.FPE_FLTOVF;
    enum FPE_FLTUND = _Anonymous_70.FPE_FLTUND;
    enum FPE_FLTRES = _Anonymous_70.FPE_FLTRES;
    enum FPE_FLTINV = _Anonymous_70.FPE_FLTINV;
    enum FPE_FLTSUB = _Anonymous_70.FPE_FLTSUB;
    void mailstream_cfstream_set_ssl_level(mailstream*, int, );
    enum _Anonymous_71
    {
        MAILMIME_FIELD_NONE = 0,
        MAILMIME_FIELD_TYPE = 1,
        MAILMIME_FIELD_TRANSFER_ENCODING = 2,
        MAILMIME_FIELD_ID = 3,
        MAILMIME_FIELD_DESCRIPTION = 4,
        MAILMIME_FIELD_VERSION = 5,
        MAILMIME_FIELD_DISPOSITION = 6,
        MAILMIME_FIELD_LANGUAGE = 7,
        MAILMIME_FIELD_LOCATION = 8,
    }
    enum MAILMIME_FIELD_NONE = _Anonymous_71.MAILMIME_FIELD_NONE;
    enum MAILMIME_FIELD_TYPE = _Anonymous_71.MAILMIME_FIELD_TYPE;
    enum MAILMIME_FIELD_TRANSFER_ENCODING = _Anonymous_71.MAILMIME_FIELD_TRANSFER_ENCODING;
    enum MAILMIME_FIELD_ID = _Anonymous_71.MAILMIME_FIELD_ID;
    enum MAILMIME_FIELD_DESCRIPTION = _Anonymous_71.MAILMIME_FIELD_DESCRIPTION;
    enum MAILMIME_FIELD_VERSION = _Anonymous_71.MAILMIME_FIELD_VERSION;
    enum MAILMIME_FIELD_DISPOSITION = _Anonymous_71.MAILMIME_FIELD_DISPOSITION;
    enum MAILMIME_FIELD_LANGUAGE = _Anonymous_71.MAILMIME_FIELD_LANGUAGE;
    enum MAILMIME_FIELD_LOCATION = _Anonymous_71.MAILMIME_FIELD_LOCATION;
    MMAPString* mmap_string_assign(MMAPString*, const(char)*, );


    int imap_mailstorage_init_sasl(mailstorage*, const(char)*, uint16_t, const(char)*, int, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, int, const(char)*, );
    int mailimap_uid_sort(mailimap*, const(char)*, mailimap_sort_key*, mailimap_search_key*, clist**, );
    int mailmbox_write_lock(mailmbox_folder*, );
    mailmime_data* mailmime_data_new_file(int, int, char*, );
    struct newsfeed_item_enclosure
    {
        char* fie_url;
        char* fie_type;
        size_t fie_size;
    }


    mailimf_date_time* mailimf_date_time_new(int, int, int, int, int, int, int, );
    extern __gshared int mailstream_debug;
    struct mail_list
    {
        clist* mb_list;
    }
    mailmh_msg_info* mailmh_msg_info_new(uint32_t, size_t, time_t, );




    void mailstream_ssl_init_not_required();
    int mailimap_annotatemore_setannotation(mailimap*, const(char)*, mailimap_annotatemore_entry_att_list*, int*, );
    struct mailmbox_msg_info
    {
        uint msg_index;
        uint32_t msg_uid;
        int msg_written_uid;
        int msg_deleted;
        size_t msg_start;
        size_t msg_start_len;
        size_t msg_headers;
        size_t msg_headers_len;
        size_t msg_body;
        size_t msg_body_len;
        size_t msg_size;
        size_t msg_padding;
    }


    void mailimap_namespace_data_free(mailimap_namespace_data*, );
    int mailmime_content_type_write(FILE*, int*, mailmime_content*, );
    enum _Anonymous_72
    {
        MAILSMTP_ESMTP = 1,
        MAILSMTP_ESMTP_EXPN = 2,
        MAILSMTP_ESMTP_8BITMIME = 4,
        MAILSMTP_ESMTP_SIZE = 8,
        MAILSMTP_ESMTP_ETRN = 16,
        MAILSMTP_ESMTP_STARTTLS = 32,
        MAILSMTP_ESMTP_DSN = 64,
        MAILSMTP_ESMTP_PIPELINING = 128,
    }
    enum MAILSMTP_ESMTP = _Anonymous_72.MAILSMTP_ESMTP;
    enum MAILSMTP_ESMTP_EXPN = _Anonymous_72.MAILSMTP_ESMTP_EXPN;
    enum MAILSMTP_ESMTP_8BITMIME = _Anonymous_72.MAILSMTP_ESMTP_8BITMIME;
    enum MAILSMTP_ESMTP_SIZE = _Anonymous_72.MAILSMTP_ESMTP_SIZE;
    enum MAILSMTP_ESMTP_ETRN = _Anonymous_72.MAILSMTP_ESMTP_ETRN;
    enum MAILSMTP_ESMTP_STARTTLS = _Anonymous_72.MAILSMTP_ESMTP_STARTTLS;
    enum MAILSMTP_ESMTP_DSN = _Anonymous_72.MAILSMTP_ESMTP_DSN;
    enum MAILSMTP_ESMTP_PIPELINING = _Anonymous_72.MAILSMTP_ESMTP_PIPELINING;
    mailmime_parameter* mailmime_parameter_dup(mailmime_parameter*, );
    int mailmime_version_parse(const(char)*, size_t, size_t*, uint32_t*, );
    int nntp_mailstorage_init_with_local_address(mailstorage*, const(char)*, uint16_t, const(char)*, uint16_t, const(char)*, int, int, const(char)*, const(char)*, int, const(char)*, const(char)*, );
    int mailimap_oauth2_authenticate(mailimap*, const(char)*, const(char)*, );
    int mail_thread_sort(mailmessage_tree*, int function(mailmessage_tree**, mailmessage_tree**), int, );


    int mailprivacy_msg_fetch(mailprivacy*, mailmessage*, char**, size_t*, );
    int mailmbox_write_unlock(mailmbox_folder*, );


    time_t mailstream_low_get_timeout(mailstream_low*, );
    void esmtp_address_list_free(clist*, );


    int mailimap_examine_condstore(mailimap*, const(char)*, uint64_t*, );
    mailimap_condstore_status_info* mailimap_condstore_status_info_new(uint64_t, );
    int mailsmtp_helo_with_ip(mailsmtp*, int, );
    int mailimap_has_uidplus(mailimap*, );
    mailimap_set* mailimap_set_new_empty();
    int mailimap_acl_deleteacl(mailimap*, const(char)*, const(char)*, );
    int mailpop3_top(mailpop3*, uint, uint, char**, size_t*, );
    void mailmh_msg_info_free(mailmh_msg_info*, );


    int mail_flags_has_extension(mail_flags*, char*, );
    struct mailstream_low_driver
    {
        c_long function(_mailstream_low*, void*, c_ulong) mailstream_read;
        c_long function(_mailstream_low*, const(void)*, c_ulong) mailstream_write;
        int function(_mailstream_low*) mailstream_close;
        int function(_mailstream_low*) mailstream_get_fd;
        void function(_mailstream_low*) mailstream_free;
        void function(_mailstream_low*) mailstream_cancel;
        struct_mailstream_cancel* function(_mailstream_low*) mailstream_get_cancel;
        carray_s* function(_mailstream_low*) mailstream_get_certificate_chain;
        int function(_mailstream_low*) mailstream_setup_idle;
        int function(_mailstream_low*) mailstream_unsetup_idle;
        int function(_mailstream_low*) mailstream_interrupt_idle;
    }
    mailimap_sort_key* mailimap_sort_key_new_size(int, );
    int mailfolder_add_child(mailfolder*, mailfolder*, );


    clist* mailprivacy_smime_encryption_id_list(mailprivacy*, mailmessage*, );
    int mailstream_cfstream_set_ssl_enabled(mailstream*, int, );
    MMAPString* mmap_string_truncate(MMAPString*, size_t, );


    int pop3_mailstorage_init_sasl(mailstorage*, const(char)*, uint16_t, const(char)*, int, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, int, const(char)*, const(char)*, );
    void mailimap_extension_data_store(mailimap*, mailimap_extension_data**, );






    alias pthread_rwlockattr_t = _Anonymous_73;
    void chash_free(chash*, );
    union _Anonymous_73
    {
        char[8] __size;
        c_long __align;
    }






    int libetpan_message_mime_ref(mailengine*, mailmessage*, );
    extern __gshared void function(int, const(char)*, c_ulong) mailstream_logger;


    int mailstream_cfstream_is_ssl_enabled(mailstream*, );
    int mailmbox_read_lock(mailmbox_folder*, );
    mailmh_folder* mailmh_folder_new(mailmh_folder*, const(char)*, );
    enum _Anonymous_74
    {
        MAILIMAP_QUOTA_TYPE_QUOTA_DATA = 0,
        MAILIMAP_QUOTA_TYPE_QUOTAROOT_DATA = 1,
    }
    enum MAILIMAP_QUOTA_TYPE_QUOTA_DATA = _Anonymous_74.MAILIMAP_QUOTA_TYPE_QUOTA_DATA;
    enum MAILIMAP_QUOTA_TYPE_QUOTAROOT_DATA = _Anonymous_74.MAILIMAP_QUOTA_TYPE_QUOTAROOT_DATA;




    int mailsession_connect_stream(mailsession*, mailstream*, );
    ssize_t mailstream_ssl_get_certificate(mailstream*, ubyte**, );
    clist* smtp_address_list_new();




    struct mbox_mailstorage
    {
        char* mbox_pathname;
        int mbox_cached;
        char* mbox_cache_directory;
        char* mbox_flags_directory;
    }
    int mailmime_part_parse(const(char)*, size_t, size_t*, int, char**, size_t*, );
    int mailmime_write(FILE*, int*, mailmime*, );
    mail_list* mail_list_new(clist*, );
    int mailsmtp_mail(mailsmtp*, const(char)*, );
    int mailimap_has_condstore(mailimap*, );
    void mailstream_low_set_logger(mailstream_low*, void function(_mailstream_low*, int, const(char)*, c_ulong, void*), void*, );
    void mailimap_condstore_status_info_free(mailimap_condstore_status_info*, );
    void mailimf_date_time_free(mailimf_date_time*, );
    int mailimap_has_xoauth2(mailimap*, );


    mailmime_composite_type* mailmime_composite_type_dup(mailmime_composite_type*, );


    mailimap_sort_key* mailimap_sort_key_new_subject(int, );
    void mailimap_sort_result_free(clist*, );
    struct mailstorage_driver
    {
        char* sto_name;
        int function(mailstorage*) sto_connect;
        int function(mailstorage*, char*, mailsession**) sto_get_folder_session;
        void function(mailstorage*) sto_uninitialize;
    }




    int mailfolder_detach_parent(mailfolder*, );
    int mailmbox_read_unlock(mailmbox_folder*, );




    int mailmime_extension_token_parse(const(char)*, size_t, size_t*, char**, );
    void mailmh_folder_free(mailmh_folder*, );


    int mailpop3_dele(mailpop3*, uint, );
    void mailprivacy_smime_encryption_id_list_clear(mailprivacy*, mailmessage*, );
    void newsnntp_set_logger(newsnntp*, void function(newsnntp*, int, const(char)*, c_ulong, void*), void*, );
    int libetpan_message_mime_unref(mailengine*, mailmessage*, );
    mailstream_low* mailstream_low_ssl_open_with_callback(int, void function(mailstream_ssl_context*, void*), void*, );
    int mailimf_field_write_file(FILE*, int*, mailimf_field*, );


    alias intptr_t = c_long;
    void chash_clear(chash*, );






    int mailimap_has_annotatemore(mailimap*, );
    extern __gshared void function(_mailstream_low*, int, int, const(char)*, c_ulong) mailstream_logger_id;
    MMAPString* mmap_string_set_size(MMAPString*, size_t, );


    int smtp_address_list_add(clist*, char*, );
    int mailmh_folder_add_subfolder(mailmh_folder*, const(char)*, );


    int mailprivacy_msg_fetch_header(mailprivacy*, mailmessage*, char**, size_t*, );
    alias pid_t = int;




    void mail_list_free(mail_list*, );


    int mailsmtp_rcpt(mailsmtp*, const(char)*, );
    int mailfolder_connect(mailfolder*, );


    int mailmime_quoted_printable_write(FILE*, int*, int, const(char)*, size_t, );
    mailmime_discrete_type* mailmime_discrete_type_dup(mailmime_discrete_type*, );
    int mailstream_cfstream_wait_idle(mailstream*, int, );
    mailimap_sort_key* mailimap_sort_key_new_to(int, );
    alias uintptr_t = c_ulong;






    carray* mailstream_low_get_certificate_chain(mailstream_low*, );
    int mailimf_field_write_mem(MMAPString*, int*, mailimf_field*, );
    int mailpop3_noop(mailpop3*, );






    int mailstream_low_cfstream_wait_idle(mailstream_low*, int, );
    struct _libc_fpxreg
    {
        ushort[4] significand;
        ushort exponent;
        ushort[3] __glibc_reserved1;
    }
    int select(int, fd_set*, fd_set*, fd_set*, timeval*, );
    struct mailimap_quota_complete_data
    {
        mailimap_quota_quotaroot_data* quotaroot_data;
        clist* quota_list;
    }
    mailstream_low* mailstream_low_ssl_open_with_callback_timeout(int, time_t, void function(mailstream_ssl_context*, void*), void*, );
    enum _Anonymous_75
    {
        MAILIMF_ADDRESS_ERROR = 0,
        MAILIMF_ADDRESS_MAILBOX = 1,
        MAILIMF_ADDRESS_GROUP = 2,
    }
    enum MAILIMF_ADDRESS_ERROR = _Anonymous_75.MAILIMF_ADDRESS_ERROR;
    enum MAILIMF_ADDRESS_MAILBOX = _Anonymous_75.MAILIMF_ADDRESS_MAILBOX;
    enum MAILIMF_ADDRESS_GROUP = _Anonymous_75.MAILIMF_ADDRESS_GROUP;
    void smtp_address_list_free(clist*, );
    MMAPString* mmap_string_insert_len(MMAPString*, size_t, const(char)*, size_t, );
    struct mailmime_field
    {
        int fld_type;
        union _Anonymous_76
        {
            mailmime_content* fld_content;
            mailmime_mechanism* fld_encoding;
            char* fld_id;
            char* fld_description;
            uint32_t fld_version;
            mailmime_disposition* fld_disposition;
            mailmime_language* fld_language;
            char* fld_location;
        }
        _Anonymous_76 fld_data;
    }
    int mailsmtp_data(mailsmtp*, );
    int mailmime_parameter_parse(const(char)*, size_t, size_t*, mailmime_parameter**, );
    int mailprivacy_smime_set_encryption_id(mailprivacy*, char*, char*, );
    mailmh_folder* mailmh_folder_find(mailmh_folder*, const(char)*, );
    int mailmbox_map(mailmbox_folder*, );


    void mailstream_set_logger(mailstream*, void function(_mailstream*, int, const(char)*, c_ulong, void*), void*, );


    enum _Anonymous_77
    {
        MAILIMAP_ACL_TYPE_ACL_DATA = 0,
        MAILIMAP_ACL_TYPE_LISTRIGHTS_DATA = 1,
        MAILIMAP_ACL_TYPE_MYRIGHTS_DATA = 2,
    }
    enum MAILIMAP_ACL_TYPE_ACL_DATA = _Anonymous_77.MAILIMAP_ACL_TYPE_ACL_DATA;
    enum MAILIMAP_ACL_TYPE_LISTRIGHTS_DATA = _Anonymous_77.MAILIMAP_ACL_TYPE_LISTRIGHTS_DATA;
    enum MAILIMAP_ACL_TYPE_MYRIGHTS_DATA = _Anonymous_77.MAILIMAP_ACL_TYPE_MYRIGHTS_DATA;






    int mailimf_field_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailimf_field*, );


    int mailimap_set_add(mailimap_set*, mailimap_set_item*, );
    int mailimap_has_extension(mailimap*, const(char)*, );
    void mailfolder_disconnect(mailfolder*, );




    int mailmime_base64_write(FILE*, int*, const(char)*, size_t, );


    int mailpop3_rset(mailpop3*, );
    mailmime_type* mailmime_type_dup(mailmime_type*, );
    int imap_mailstorage_init_sasl_with_local_address(mailstorage*, const(char)*, uint16_t, const(char)*, uint16_t, const(char)*, int, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, int, const(char)*, );
    struct newsnntp_group_info
    {
        char* grp_name;
        uint32_t grp_first;
        uint32_t grp_last;
        uint32_t grp_count;
        char grp_type;
    }
    int mailstream_low_wait_idle(mailstream_low*, struct_mailstream_cancel*, int, );
    alias pthread_spinlock_t = int;




    void mailmbox_unmap(mailmbox_folder*, );


    mailmime* mailmime_new_message_data(mailmime*, );
    int mailimf_mailbox_list_add_mb(mailimf_mailbox_list*, char*, char*, );






    int mailthread_tree_timecomp(mailmessage_tree**, mailmessage_tree**, );


    int mailsmtp_data_message(mailsmtp*, const(char)*, size_t, );
    alias id_t = uint;
    struct mailsmtp
    {
        mailstream* stream;
        size_t progr_rate;
        progress_function* progr_fun;
        char* response;
        MMAPString* line_buffer;
        MMAPString* response_buffer;
        int esmtp;
        int auth;
        struct _Anonymous_78
        {
            void* sasl_conn;
            const(char)* sasl_server_fqdn;
            const(char)* sasl_login;
            const(char)* sasl_auth_name;
            const(char)* sasl_password;
            const(char)* sasl_realm;
            void* sasl_secret;
        }
        _Anonymous_78 smtp_sasl;
        size_t smtp_max_msg_size;
        mailprogress_function* smtp_progress_fun;
        void* smtp_progress_context;
        int response_code;
        time_t smtp_timeout;
        void function(mailsmtp*, int, const(char)*, c_ulong, void*) smtp_logger;
        void* smtp_logger_context;
    }
    int mailprivacy_register(mailprivacy*, mailprivacy_protocol*, );


    int mailmh_folder_remove_subfolder(mailmh_folder*, );


    mailimap_sort_key* mailimap_sort_key_new_multiple(clist*, );
    struct itimerval
    {
        timeval it_interval;
        timeval it_value;
    }
    size_t strftime_l(char*, size_t, const(char)*, const(tm)*, locale_t, );
    enum _Anonymous_79
    {
        MAIL_FLAG_NEW = 1,
        MAIL_FLAG_SEEN = 2,
        MAIL_FLAG_FLAGGED = 4,
        MAIL_FLAG_DELETED = 8,
        MAIL_FLAG_ANSWERED = 16,
        MAIL_FLAG_FORWARDED = 32,
        MAIL_FLAG_CANCELLED = 64,
    }
    enum MAIL_FLAG_NEW = _Anonymous_79.MAIL_FLAG_NEW;
    enum MAIL_FLAG_SEEN = _Anonymous_79.MAIL_FLAG_SEEN;
    enum MAIL_FLAG_FLAGGED = _Anonymous_79.MAIL_FLAG_FLAGGED;
    enum MAIL_FLAG_DELETED = _Anonymous_79.MAIL_FLAG_DELETED;
    enum MAIL_FLAG_ANSWERED = _Anonymous_79.MAIL_FLAG_ANSWERED;
    enum MAIL_FLAG_FORWARDED = _Anonymous_79.MAIL_FLAG_FORWARDED;
    enum MAIL_FLAG_CANCELLED = _Anonymous_79.MAIL_FLAG_CANCELLED;


    int mailimap_has_authentication(mailimap*, const(char)*, );
    mailstream_low* mailstream_low_tls_open_with_callback(int, void function(mailstream_ssl_context*, void*), void*, );
    int chash_set(chash*, chashdatum*, chashdatum*, chashdatum*, );
    int mailsession_connect_path(mailsession*, const(char)*, );




    void mailmbox_sync(mailmbox_folder*, );




    void mailpop3_top_free(char*, );


    int mailmh_folder_rename_subfolder(mailmh_folder*, mailmh_folder*, const(char)*, );






    mailmime_content* mailmime_content_dup(mailmime_content*, );
    int mailmime_value_parse(const(char)*, size_t, size_t*, char**, );


    MMAPString* mmap_string_append(MMAPString*, const(char)*, );
    int mailstream_wait_idle(mailstream*, int, );
    int mailmessage_flush(mailmessage*, );
    mailmime* mailmime_new_empty(mailmime_content*, mailmime_fields*, );
    int mailimf_fields_parse(const(char)*, size_t, size_t*, mailimf_fields**, );


    int mailmime_data_write(FILE*, int*, mailmime_data*, int, );






    int pop3_mailstorage_init_sasl_with_local_address(mailstorage*, const(char)*, uint16_t, const(char)*, uint16_t, const(char)*, int, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, int, const(char)*, const(char)*, );
    struct mailpop3_msg_info
    {
        uint msg_index;
        uint32_t msg_size;
        char* msg_uidl;
        int msg_deleted;
    }
    void newsnntp_set_progress_callback(newsnntp*, mailprogress_function*, void*, );
    struct mailimap_extension_data
    {
        mailimap_extension_api* ext_extension;
        int ext_type;
        void* ext_data;
    }


    mailimap_sort_key* mailimap_sort_key_new_multiple_empty();




    mailimap_quota_complete_data* mailimap_quota_complete_data_new(mailimap_quota_quotaroot_data*, clist*, );
    void mailimap_acl_identifier_free(char*, );
    int kill(__pid_t, int, );
    struct _libc_xmmreg
    {
        __uint32_t[4] element;
    }
    union _Anonymous_80
    {
        char[32] __size;
        c_long __align;
    }


    alias pthread_barrier_t = _Anonymous_80;
    void mailprivacy_unregister(mailprivacy*, mailprivacy_protocol*, );
    int maillmtp_data_message(mailsmtp*, const(char)*, size_t, clist*, int*, );
    mailstream_low* mailstream_low_tls_open_with_callback_timeout(int, time_t, void function(mailstream_ssl_context*, void*), void*, );






    int mailimap_append(mailimap*, const(char)*, mailimap_flag_list*, mailimap_date_time*, const(char)*, size_t, );


    alias ssize_t = c_long;


    void mailpop3_retr_free(char*, );


    int mailprivacy_fetch_decoded_to_file(mailprivacy*, char*, size_t, mailmessage*, mailmime*, );
    int mailmbox_open(mailmbox_folder*, );
    int mailmh_folder_get_message_filename(mailmh_folder*, uint32_t, char**, );
    void mailimap_acl_rights_free(char*, );
    struct _mailstream_low
    {
        void* data;
        mailstream_low_driver* driver;
        int privacy;
        char* identifier;
        c_ulong timeout;
        void function(_mailstream_low*, int, const(char)*, c_ulong, void*) logger;
        void* logger_context;
    }
    int mailmime_language_parse(const(char)*, size_t, size_t*, mailmime_language**, );






    enum _Anonymous_81
    {
        SEGV_MAPERR = 1,
        SEGV_ACCERR = 2,
    }
    enum SEGV_MAPERR = _Anonymous_81.SEGV_MAPERR;
    enum SEGV_ACCERR = _Anonymous_81.SEGV_ACCERR;
    int mailimf_quoted_string_write_file(FILE*, int*, const(char)*, size_t, );
    MMAPString* mmap_string_append_len(MMAPString*, const(char)*, size_t, );
    int mailstream_low_setup_idle(mailstream_low*, );
    enum _Anonymous_82
    {
        MAILIMAP_ANNOTATEMORE_TYPE_ANNOTATE_DATA = 0,
        MAILIMAP_ANNOTATEMORE_TYPE_RESP_TEXT_CODE = 1,
    }
    enum MAILIMAP_ANNOTATEMORE_TYPE_ANNOTATE_DATA = _Anonymous_82.MAILIMAP_ANNOTATEMORE_TYPE_ANNOTATE_DATA;
    enum MAILIMAP_ANNOTATEMORE_TYPE_RESP_TEXT_CODE = _Anonymous_82.MAILIMAP_ANNOTATEMORE_TYPE_RESP_TEXT_CODE;


    alias intmax_t = c_long;
    int mailstream_setup_idle(mailstream*, );
    int mailimap_sort_key_multiple_add(mailimap_sort_key*, mailimap_sort_key*, );




    char* mailprivacy_get_encryption_name(mailprivacy*, char*, char*, );
    struct mailimap_acl_identifier_rights
    {
        char* identifer;
        char* rights;
    }
    struct newsnntp_group_time
    {
        char* grp_name;
        time_t grp_date;
        char* grp_email;
    }




    mailimf_address_list* mailimf_address_list_new_empty();
    int mailmime_new_with_content(const(char)*, mailmime_fields*, mailmime**, );
    alias uintmax_t = c_ulong;
    int mailimap_acl_getacl(mailimap*, const(char)*, clist**, );
    void mailmbox_close(mailmbox_folder*, );
    int mailpop3_get_msg_info(mailpop3*, uint, mailpop3_msg_info**, );
    int mailmbox_msg_info_update(mailmbox_folder*, size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t, uint32_t, );
    int mailimap_set_add_interval(mailimap_set*, uint32_t, uint32_t, );






    int pselect(int, fd_set*, fd_set*, fd_set*, const(timespec)*, const(__sigset_t)*, );
    int mailstream_ssl_set_client_certicate(mailstream_ssl_context*, char*, );




    struct _libc_fpstate
    {
        __uint16_t cwd;
        __uint16_t swd;
        __uint16_t ftw;
        __uint16_t fop;
        __uint64_t rip;
        __uint64_t rdp;
        __uint32_t mxcsr;
        __uint32_t mxcr_mask;
        _libc_fpxreg[8] _st;
        _libc_xmmreg[16] _xmm;
        __uint32_t[24] __glibc_reserved1;
    }
    int chash_get(chash*, chashdatum*, chashdatum*, );
    int mailmh_folder_get_message_fd(mailmh_folder*, uint32_t, int, int*, );
    int mailstream_low_unsetup_idle(mailstream_low*, );
    void mailstream_unsetup_idle(mailstream*, );
    int mailimf_address_list_write_file(FILE*, int*, mailimf_address_list*, );
    int mailimf_quoted_string_write_mem(MMAPString*, int*, const(char)*, size_t, );
    union _Anonymous_83
    {
        char[4] __size;
        int __align;
    }
    alias pthread_barrierattr_t = _Anonymous_83;


    void mailimap_quota_complete_data_free(mailimap_quota_complete_data*, );




    alias daddr_t = int;
    int mailprivacy_get_mime(mailprivacy*, int, int, char*, size_t, mailmime**, );
    enum _Anonymous_84
    {
        MAILMIME_MECHANISM_ERROR = 0,
        MAILMIME_MECHANISM_7BIT = 1,
        MAILMIME_MECHANISM_8BIT = 2,
        MAILMIME_MECHANISM_BINARY = 3,
        MAILMIME_MECHANISM_QUOTED_PRINTABLE = 4,
        MAILMIME_MECHANISM_BASE64 = 5,
        MAILMIME_MECHANISM_TOKEN = 6,
    }
    enum MAILMIME_MECHANISM_ERROR = _Anonymous_84.MAILMIME_MECHANISM_ERROR;
    enum MAILMIME_MECHANISM_7BIT = _Anonymous_84.MAILMIME_MECHANISM_7BIT;
    enum MAILMIME_MECHANISM_8BIT = _Anonymous_84.MAILMIME_MECHANISM_8BIT;
    enum MAILMIME_MECHANISM_BINARY = _Anonymous_84.MAILMIME_MECHANISM_BINARY;
    enum MAILMIME_MECHANISM_QUOTED_PRINTABLE = _Anonymous_84.MAILMIME_MECHANISM_QUOTED_PRINTABLE;
    enum MAILMIME_MECHANISM_BASE64 = _Anonymous_84.MAILMIME_MECHANISM_BASE64;
    enum MAILMIME_MECHANISM_TOKEN = _Anonymous_84.MAILMIME_MECHANISM_TOKEN;
    int killpg(__pid_t, int, );
    int libetpan_folder_get_msg_list(mailengine*, mailfolder*, mailmessage_list**, mailmessage_list**, );


    int mailsmtp_data_message_quit(mailsmtp*, const(char)*, size_t, );
    int mailmh_folder_get_message_size(mailmh_folder*, uint32_t, size_t*, );
    struct mailpop3_capa
    {
        char* cap_name;
        clist* cap_param;
    }
    pragma(mangle, "mailpop3_capa") int mailpop3_capa_(mailpop3*, clist**, );
    MMAPString* mmap_string_append_c(MMAPString*, char, );


    alias caddr_t = char*;
    int mailsession_starttls(mailsession*, );


    alias __itimer_which_t = int;


    int mailprivacy_encrypt(mailprivacy*, char*, char*, mailmime*, mailmime**, );


    int clist_insert_before(clist*, clistiter*, void*, );


    mailimap_acl_identifier_rights* mailimap_acl_identifier_rights_new(char*, char*, );
    void mailstream_interrupt_idle(mailstream*, );
    int mailstream_ssl_set_client_certificate_data(mailstream_ssl_context*, ubyte*, size_t, );


    int mailimf_quoted_string_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, const(char)*, size_t, );
    int mailmbox_validate_write_lock(mailmbox_folder*, );
    int mailstream_low_interrupt_idle(mailstream_low*, );




    void newsnntp_set_timeout(newsnntp*, time_t, );


    struct __pthread_mutex_s
    {
        int __lock;
        uint __count;
        int __owner;
        uint __nusers;
        int __kind;
        short __spins;
        short __elision;
        __pthread_list_t __list;
    }
    int mailimf_mailbox_list_write_file(FILE*, int*, mailimf_mailbox_list*, );
    int mailmime_set_preamble_file(mailmime*, char*, );
    struct imap_mailstorage
    {
        char* imap_servername;
        uint16_t imap_port;
        char* imap_command;
        int imap_connection_type;
        int imap_auth_type;
        char* imap_login;
        char* imap_password;
        int imap_cached;
        char* imap_cache_directory;
        struct _Anonymous_85
        {
            int sasl_enabled;
            char* sasl_auth_type;
            char* sasl_server_fqdn;
            char* sasl_local_ip_port;
            char* sasl_remote_ip_port;
            char* sasl_login;
            char* sasl_auth_name;
            char* sasl_password;
            char* sasl_realm;
        }
        _Anonymous_85 imap_sasl;
        char* imap_local_address;
        uint16_t imap_local_port;
    }




    int mailimf_address_list_write_mem(MMAPString*, int*, mailimf_address_list*, );
    struct newsnntp_distrib_value_meaning
    {
        char* dst_value;
        char* dst_meaning;
    }
    int mailmbox_validate_read_lock(mailmbox_folder*, );
    enum _Anonymous_86
    {
        MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_UNSPECIFIED = 0,
        MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOBIG = 1,
        MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOMANY = 2,
    }
    enum MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_UNSPECIFIED = _Anonymous_86.MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_UNSPECIFIED;
    enum MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOBIG = _Anonymous_86.MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOBIG;
    enum MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOMANY = _Anonymous_86.MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOMANY;
    int mailstream_ssl_set_client_private_key_data(mailstream_ssl_context*, ubyte*, size_t, );
    void mailpop3_capa_resp_free(clist*, );
    tm* gmtime(const(time_t)*, );
    struct mailstorage
    {
        char* sto_id;
        void* sto_data;
        mailsession* sto_session;
        mailstorage_driver* sto_driver;
        clist* sto_shared_folders;
        void* sto_user_data;
    }


    struct mailimf_address
    {
        int ad_type;
        union _Anonymous_87
        {
            mailimf_mailbox* ad_mailbox;
            mailimf_group* ad_group;
        }
        _Anonymous_87 ad_data;
    }
    int mailmh_folder_add_message_uid(mailmh_folder*, const(char)*, size_t, uint32_t*, );
    mailmbox_msg_info* mailmbox_msg_info_new(size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t, uint32_t, );
    enum _Anonymous_88
    {
        BUS_ADRALN = 1,
        BUS_ADRERR = 2,
        BUS_OBJERR = 3,
        BUS_MCEERR_AR = 4,
        BUS_MCEERR_AO = 5,
    }
    enum BUS_ADRALN = _Anonymous_88.BUS_ADRALN;
    enum BUS_ADRERR = _Anonymous_88.BUS_ADRERR;
    enum BUS_OBJERR = _Anonymous_88.BUS_OBJERR;
    enum BUS_MCEERR_AR = _Anonymous_88.BUS_MCEERR_AR;
    enum BUS_MCEERR_AO = _Anonymous_88.BUS_MCEERR_AO;
    int raise(int, );






    int chash_delete(chash*, chashdatum*, chashdatum*, );
    MMAPString* mmap_string_prepend(MMAPString*, const(char)*, );




    int libetpan_folder_fetch_env_list(mailengine*, mailfolder*, mailmessage_list*, );
    void mailimap_acl_identifier_rights_free(mailimap_acl_identifier_rights*, );


    alias progress_function = void function(size_t, size_t);
    void** carray_data(carray*, );
    struct nntp_mailstorage
    {
        char* nntp_servername;
        uint16_t nntp_port;
        char* nntp_command;
        int nntp_connection_type;
        int nntp_auth_type;
        char* nntp_login;
        char* nntp_password;
        int nntp_cached;
        char* nntp_cache_directory;
        char* nntp_flags_directory;
        char* nntp_local_address;
        uint16_t nntp_local_port;
    }
    int mailsmtp_data_message_quit_no_disconnect(mailsmtp*, const(char)*, size_t, );
    int clist_insert_after(clist*, clistiter*, void*, );




    carray* mailstream_get_certificate_chain(mailstream*, );


    int getitimer(__itimer_which_t, itimerval*, );
    int mailimf_mailbox_list_write_mem(MMAPString*, int*, mailimf_mailbox_list*, );
    int mailpop3_stat(mailpop3*, mailpop3_stat_response**, );
    struct mailpop3_stat_response
    {
        uint msgs_count;
        size_t msgs_size;
    }
    struct pop3_mailstorage
    {
        char* pop3_servername;
        uint16_t pop3_port;
        char* pop3_command;
        int pop3_connection_type;
        int pop3_auth_type;
        char* pop3_login;
        char* pop3_password;
        int pop3_cached;
        char* pop3_cache_directory;
        char* pop3_flags_directory;
        struct _Anonymous_89
        {
            int sasl_enabled;
            char* sasl_auth_type;
            char* sasl_server_fqdn;
            char* sasl_local_ip_port;
            char* sasl_remote_ip_port;
            char* sasl_login;
            char* sasl_auth_name;
            char* sasl_password;
            char* sasl_realm;
        }
        _Anonymous_89 pop3_sasl;
        char* pop3_local_address;
        uint16_t pop3_local_port;
    }


    int mailmessage_check(mailmessage*, );


    int mailimf_address_list_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailimf_address_list*, );
    int mailmime_set_epilogue_file(mailmime*, char*, );
    alias key_t = int;
    int mailmh_folder_add_message(mailmh_folder*, const(char)*, size_t, );
    __sighandler_t ssignal(int, __sighandler_t, );


    struct _fpstate
    {
        __uint16_t cwd;
        __uint16_t swd;
        __uint16_t ftw;
        __uint16_t fop;
        __uint64_t rip;
        __uint64_t rdp;
        __uint32_t mxcsr;
        __uint32_t mxcr_mask;
        _fpxreg[8] _st;
        _xmmreg[16] _xmm;
        __uint32_t[24] __glibc_reserved1;
    }
    tm* localtime(const(time_t)*, );




    struct mail_flags
    {
        uint32_t fl_flags;
        clist* fl_extension;
    }
    int mailstream_ssl_set_server_certicate(mailstream_ssl_context*, char*, char*, );
    alias mailprogress_function = void function(size_t, size_t, void*);
    int mailimf_address_list_add(mailimf_address_list*, mailimf_address*, );
    struct newsnntp_distrib_default_value
    {
        uint32_t dst_weight;
        char* dst_group_pattern;
        char* dst_value;
    }
    struct mailimap_acl_acl_data
    {
        char* mailbox;
        clist* idrights_list;
    }
    int mailimap_set_add_single(mailimap_set*, uint32_t, );




    void mailstream_certificate_chain_free(carray*, );
    void libetpan_folder_free_msg_list(mailengine*, mailfolder*, mailmessage_list*, );




    MMAPString* mmap_string_prepend_c(MMAPString*, char, );


    int mailmbox_fetch_msg_no_lock(mailmbox_folder*, uint32_t, char**, size_t*, );
    int mailprivacy_encrypt_msg(mailprivacy*, char*, char*, mailmessage*, mailmime*, mailmime**, );
    enum _Anonymous_90
    {
        MAILSTREAM_IDLE_ERROR = 0,
        MAILSTREAM_IDLE_INTERRUPTED = 1,
        MAILSTREAM_IDLE_HASDATA = 2,
        MAILSTREAM_IDLE_TIMEOUT = 3,
        MAILSTREAM_IDLE_CANCELLED = 4,
    }
    enum MAILSTREAM_IDLE_ERROR = _Anonymous_90.MAILSTREAM_IDLE_ERROR;
    enum MAILSTREAM_IDLE_INTERRUPTED = _Anonymous_90.MAILSTREAM_IDLE_INTERRUPTED;
    enum MAILSTREAM_IDLE_HASDATA = _Anonymous_90.MAILSTREAM_IDLE_HASDATA;
    enum MAILSTREAM_IDLE_TIMEOUT = _Anonymous_90.MAILSTREAM_IDLE_TIMEOUT;
    enum MAILSTREAM_IDLE_CANCELLED = _Anonymous_90.MAILSTREAM_IDLE_CANCELLED;
    int gsignal(int, );
    int mailimf_mailbox_list_parse(const(char)*, size_t, size_t*, mailimf_mailbox_list**, );
    void mailpop3_stat_resp_free(mailpop3_stat_response*, );
    struct mailmime_mechanism
    {
        int enc_type;
        char* enc_token;
    }
    void mailimap_annotatemore_attrib_free(char*, );






    int mailesmtp_lhlo(mailsmtp*, const(char)*, );


    int mailmh_folder_add_message_file_uid(mailmh_folder*, int, uint32_t*, );
    int chash_resize(chash*, uint, );


    void mailmbox_msg_info_free(mailmbox_msg_info*, );
    int mailmime_set_preamble_text(mailmime*, char*, size_t, );


    clistiter* clist_delete(clist*, clistiter*, );


    uint carray_count(carray*, );


    void mailimap_annotatemore_value_free(char*, );


    int mailimap_noop(mailimap*, );
    void* mailstream_ssl_get_openssl_ssl_ctx(mailstream_ssl_context*, );
    int mailimf_mailbox_list_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, mailimf_mailbox_list*, );
    alias clist_func = void function(void*, void*);


    struct mailmbox_append_info
    {
        const(char)* ai_message;
        size_t ai_size;
        uint ai_uid;
    }


    mailimf_address* mailimf_address_new(int, mailimf_mailbox*, mailimf_group*, );


    int mailmbox_fetch_msg_headers_no_lock(mailmbox_folder*, uint32_t, char**, size_t*, );
    MMAPString* mmap_string_prepend_len(MMAPString*, const(char)*, size_t, );




    int mailpop3_stls(mailpop3*, );
    int setitimer(__itimer_which_t, const(itimerval)*, itimerval*, );


    extern __gshared timeval mailstream_network_delay;
    tm* gmtime_r(const(time_t)*, tm*, );


    struct newsnntp_group_description
    {
        char* grp_name;
        char* grp_description;
    }
    void mailimap_annotatemore_entry_free(char*, );
    int mailesmtp_ehlo(mailsmtp*, );
    mail_flags* mail_flags_new(uint32_t, clist*, );
    time_t newsnntp_get_timeout(newsnntp*, );
    int mailmh_folder_add_message_file(mailmh_folder*, int, );
    mailimap_acl_acl_data* mailimap_acl_acl_data_new(char*, clist*, );




    int mailstream_ssl_get_fd(mailstream_ssl_context*, );


    void psignal(int, const(char)*, );


    chashiter* chash_begin(chash*, );
    int mailmime_set_epilogue_text(mailmime*, char*, size_t, );




    alias fpregset_t = _libc_fpstate*;
    void* carray_get(carray*, uint, );
    void mailprivacy_debug(mailprivacy*, FILE*, );
    void clist_foreach(clist*, clist_func, void*, );
    int mailpop3_auth(mailpop3*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, );
    struct mailmime_fields
    {
        clist* fld_list;
    }


    struct mailimap_annotatemore_att_value
    {
        char* attrib;
        char* value;
    }




    int mailmh_folder_remove_message(mailmh_folder*, uint32_t, );




    void mail_flags_free(mail_flags*, );
    int mailesmtp_ehlo_with_ip(mailsmtp*, int, );




    int mailimf_header_string_write_file(FILE*, int*, const(char)*, size_t, );






    alias __dev_t = c_ulong;
    void mailimap_acl_acl_data_free(mailimap_acl_acl_data*, );
    int mailsession_login(mailsession*, const(char)*, const(char)*, );
    struct _Anonymous_91
    {
        gregset_t gregs;
        fpregset_t fpregs;
        ulong[8] __reserved1;
    }
    alias mcontext_t = _Anonymous_91;
    void psiginfo(const(siginfo_t)*, const(char)*, );
    int libetpan_storage_add(mailengine*, mailstorage*, );
    tm* localtime_r(const(time_t)*, tm*, );
    mailimap_section* mailimap_section_new_header();
    MMAPString* mmap_string_insert(MMAPString*, size_t, const(char)*, );
    void mailimf_address_free(mailimf_address*, );
    chashiter* chash_next(chash*, chashiter*, );
    carray* mailprivacy_get_protocols(mailprivacy*, );
    void clist_concat(clist*, clist*, );


    int mailmime_set_body_file(mailmime*, char*, );


    int mailimap_acl_listrights(mailimap*, const(char)*, const(char)*, mailimap_acl_listrights_data**, );
    struct newsnntp_xhdr_resp_item
    {
        uint32_t hdr_article;
        char* hdr_value;
    }






    mailmbox_append_info* mailmbox_append_info_new(const(char)*, size_t, );
    alias __uid_t = uint;
    int mailmbox_append_message_list_no_lock(mailmbox_folder*, carray*, );
    int mailmh_folder_move_message(mailmh_folder*, mailmh_folder*, uint32_t, );
    extern __gshared _IO_FILE* stdin;




    int utimes(const(char)*, const(timeval)*, );






    int mailimf_address_list_add_parse(mailimf_address_list*, char*, );
    alias __gid_t = uint;
    int mailesmtp_mail(mailsmtp*, const(char)*, int, const(char)*, );
    int mailimf_header_string_write_mem(MMAPString*, int*, const(char)*, size_t, );


    int mailmessage_fetch_result_free(mailmessage*, char*, );
    void libetpan_storage_remove(mailengine*, mailstorage*, );
    extern __gshared _IO_FILE* stdout;


    struct mailmime_parameter
    {
        char* pa_name;
        char* pa_value;
    }
    struct mailimap_acl_listrights_data
    {
        char* mailbox;
        char* identifier;
        clist* rights_list;
    }


    alias __ino_t = c_ulong;
    void carray_set(carray*, uint, void*, );


    void mailmbox_append_info_free(mailmbox_append_info*, );


    mailimap_annotatemore_att_value* mailimap_annotatemore_att_value_new(char*, char*, );




    int mailprivacy_is_encrypted(mailprivacy*, mailmessage*, mailmime*, );
    extern __gshared _IO_FILE* stderr;
    void* clist_nth_data(clist*, int, );
    alias __ino64_t = c_ulong;


    alias __mode_t = uint;
    int mailmime_set_body_text(mailmime*, char*, size_t, );
    MMAPString* mmap_string_insert_c(MMAPString*, size_t, char, );


    int mailmbox_expunge_no_lock(mailmbox_folder*, );
    int mailmh_folder_update(mailmh_folder*, );
    struct sigcontext
    {
        __uint64_t r8;
        __uint64_t r9;
        __uint64_t r10;
        __uint64_t r11;
        __uint64_t r12;
        __uint64_t r13;
        __uint64_t r14;
        __uint64_t r15;
        __uint64_t rdi;
        __uint64_t rsi;
        __uint64_t rbp;
        __uint64_t rbx;
        __uint64_t rdx;
        __uint64_t rax;
        __uint64_t rcx;
        __uint64_t rsp;
        __uint64_t rip;
        __uint64_t eflags;
        ushort cs;
        ushort gs;
        ushort fs;
        ushort __pad0;
        __uint64_t err;
        __uint64_t trapno;
        __uint64_t oldmask;
        __uint64_t cr2;
        union _Anonymous_92
        {
            _fpstate* fpstate;
            __uint64_t __fpstate_word;
        }
        __uint64_t[8] __reserved1;
    }
    alias __nlink_t = c_ulong;
    void mailpop3_set_logger(mailpop3*, void function(mailpop3*, int, const(char)*, c_ulong, void*), void*, );
    int libetpan_storage_connect(mailengine*, mailstorage*, );
    char* asctime(const(tm)*, );
    mail_flags* mail_flags_new_empty();
    struct newsnntp_xover_resp_item
    {
        uint32_t ovr_article;
        char* ovr_subject;
        char* ovr_author;
        char* ovr_date;
        char* ovr_message_id;
        char* ovr_references;
        size_t ovr_size;
        uint32_t ovr_line_count;
        clist* ovr_others;
    }




    clistiter* clist_nth(clist*, int, );
    alias __off_t = c_long;


    int lutimes(const(char)*, const(timeval)*, );






    void mailimap_annotatemore_att_value_free(mailimap_annotatemore_att_value*, );






    alias __off64_t = c_long;
    int mailimf_string_write(FILE*, int*, const(char)*, size_t, );
    int mailesmtp_mail_size(mailsmtp*, const(char)*, int, const(char)*, size_t, );






    enum _Anonymous_93
    {
        MAILMIME_TYPE_ERROR = 0,
        MAILMIME_TYPE_DISCRETE_TYPE = 1,
        MAILMIME_TYPE_COMPOSITE_TYPE = 2,
    }
    enum MAILMIME_TYPE_ERROR = _Anonymous_93.MAILMIME_TYPE_ERROR;
    enum MAILMIME_TYPE_DISCRETE_TYPE = _Anonymous_93.MAILMIME_TYPE_DISCRETE_TYPE;
    enum MAILMIME_TYPE_COMPOSITE_TYPE = _Anonymous_93.MAILMIME_TYPE_COMPOSITE_TYPE;
    uint mailmh_folder_get_message_number(mailmh_folder*, );
    enum _Anonymous_94
    {
        NNTP_AUTH_TYPE_PLAIN = 0,
    }
    enum NNTP_AUTH_TYPE_PLAIN = _Anonymous_94.NNTP_AUTH_TYPE_PLAIN;


    mailimap_section* mailimap_section_new_header_fields(mailimap_header_list*, );
    struct ucontext_t
    {
        c_ulong uc_flags;
        ucontext_t* uc_link;
        stack_t uc_stack;
        mcontext_t uc_mcontext;
        sigset_t uc_sigmask;
        _libc_fpstate __fpregs_mem;
    }
    void libetpan_storage_disconnect(mailengine*, mailstorage*, );


    mailimap_acl_listrights_data* mailimap_acl_listrights_data_new(char*, char*, clist*, );




    int mailimf_header_string_write_driver(int function(void*, const(char)*, c_ulong), void*, int*, const(char)*, size_t, );
    int mailimap_logout(mailimap*, );
    char* ctime(const(time_t)*, );
    alias __pid_t = int;
    void mailprivacy_recursive_unregister_mime(mailprivacy*, mailmime*, );


    int mailmime_add_part(mailmime*, mailmime*, );
    MMAPString* mmap_string_erase(MMAPString*, size_t, size_t, );


    void carray_free(carray*, );
    alias __fsid_t = _Anonymous_95;
    struct mailimap_annotatemore_entry_att
    {
        char* entry;
        clist* att_value_list;
    }
    struct _Anonymous_95
    {
        int[2] __val;
    }






    int futimes(int, const(timeval)*, );
    int newsnntp_connect(newsnntp*, mailstream*, );
    int remove(const(char)*, );


    alias __clock_t = c_long;
    int mailimf_address_list_parse(const(char)*, size_t, size_t*, mailimf_address_list**, );




    alias __rlim_t = c_ulong;
    struct _IO_jump_t;
    int mailimf_fields_write(FILE*, int*, mailimf_fields*, );


    int libetpan_storage_used(mailengine*, mailstorage*, );
    int rename(const(char)*, const(char)*, );
    struct esmtp_address
    {
        char* address;
        int notify;
        char* orcpt;
    }


    alias __rlim64_t = c_ulong;
    int mailsession_logout(mailsession*, );
    void mailmime_remove_part(mailmime*, );
    alias __id_t = uint;
    void mailimap_acl_listrights_data_free(mailimap_acl_listrights_data*, );
    struct mailmime_type
    {
        int tp_type;
        union _Anonymous_96
        {
            mailmime_discrete_type* tp_discrete_type;
            mailmime_composite_type* tp_composite_type;
        }
        _Anonymous_96 tp_data;
    }
    int mailesmtp_rcpt(mailsmtp*, const(char)*, int, const(char)*, );




    enum _Anonymous_97
    {
        CLD_EXITED = 1,
        CLD_KILLED = 2,
        CLD_DUMPED = 3,
        CLD_TRAPPED = 4,
        CLD_STOPPED = 5,
        CLD_CONTINUED = 6,
    }
    enum CLD_EXITED = _Anonymous_97.CLD_EXITED;
    enum CLD_KILLED = _Anonymous_97.CLD_KILLED;
    enum CLD_DUMPED = _Anonymous_97.CLD_DUMPED;
    enum CLD_TRAPPED = _Anonymous_97.CLD_TRAPPED;
    enum CLD_STOPPED = _Anonymous_97.CLD_STOPPED;
    enum CLD_CONTINUED = _Anonymous_97.CLD_CONTINUED;
    void mmap_string_set_ceil(size_t, );
    struct mailimf_mailbox
    {
        char* mb_display_name;
        char* mb_addr_spec;
    }


    alias __time_t = c_long;
    int mailimf_envelope_fields_write(FILE*, int*, mailimf_fields*, );
    enum _Anonymous_98
    {
        IMAP_AUTH_TYPE_PLAIN = 0,
        IMAP_AUTH_TYPE_SASL_ANONYMOUS = 1,
        IMAP_AUTH_TYPE_SASL_CRAM_MD5 = 2,
        IMAP_AUTH_TYPE_SASL_KERBEROS_V4 = 3,
        IMAP_AUTH_TYPE_SASL_PLAIN = 4,
        IMAP_AUTH_TYPE_SASL_SCRAM_MD5 = 5,
        IMAP_AUTH_TYPE_SASL_GSSAPI = 6,
        IMAP_AUTH_TYPE_SASL_DIGEST_MD5 = 7,
    }
    enum IMAP_AUTH_TYPE_PLAIN = _Anonymous_98.IMAP_AUTH_TYPE_PLAIN;
    enum IMAP_AUTH_TYPE_SASL_ANONYMOUS = _Anonymous_98.IMAP_AUTH_TYPE_SASL_ANONYMOUS;
    enum IMAP_AUTH_TYPE_SASL_CRAM_MD5 = _Anonymous_98.IMAP_AUTH_TYPE_SASL_CRAM_MD5;
    enum IMAP_AUTH_TYPE_SASL_KERBEROS_V4 = _Anonymous_98.IMAP_AUTH_TYPE_SASL_KERBEROS_V4;
    enum IMAP_AUTH_TYPE_SASL_PLAIN = _Anonymous_98.IMAP_AUTH_TYPE_SASL_PLAIN;
    enum IMAP_AUTH_TYPE_SASL_SCRAM_MD5 = _Anonymous_98.IMAP_AUTH_TYPE_SASL_SCRAM_MD5;
    enum IMAP_AUTH_TYPE_SASL_GSSAPI = _Anonymous_98.IMAP_AUTH_TYPE_SASL_GSSAPI;
    enum IMAP_AUTH_TYPE_SASL_DIGEST_MD5 = _Anonymous_98.IMAP_AUTH_TYPE_SASL_DIGEST_MD5;
    void mailmime_set_imf_fields(mailmime*, mailimf_fields*, );
    int32_t mailimf_date_time_comp(mailimf_date_time*, mailimf_date_time*, );


    char* asctime_r(const(tm)*, char*, );
    alias __useconds_t = uint;


    alias __suseconds_t = c_long;
    int mmap_string_ref(MMAPString*, );
    alias _IO_lock_t = void;
    mailimap_section* mailimap_section_new_header_fields_not(mailimap_header_list*, );
    int renameat(int, const(char)*, int, const(char)*, );
    mailimap_annotatemore_entry_att* mailimap_annotatemore_entry_att_new(char*, clist*, );


    struct mailimap_acl_myrights_data
    {
        char* mailbox;
        char* rights;
    }


    int mmap_string_unref(char*, );
    struct __pthread_cond_s
    {
        union _Anonymous_99
        {
            ulong __wseq;
            struct _Anonymous_100
            {
                uint __low;
                uint __high;
            }
            _Anonymous_100 __wseq32;
        }
        union _Anonymous_101
        {
            ulong __g1_start;
            struct _Anonymous_102
            {
                uint __low;
                uint __high;
            }
            _Anonymous_102 __g1_start32;
        }
        uint[2] __g_refs;
        uint[2] __g_size;
        uint __g1_orig_size;
        uint __wrefs;
        uint[2] __g_signals;
    }
    alias __daddr_t = int;
    char* ctime_r(const(time_t)*, char*, );
    int mailesmtp_starttls(mailsmtp*, );


    int newsnntp_quit(newsnntp*, );
    int mailimf_field_write(FILE*, int*, mailimf_field*, );
    alias __key_t = int;
    void mailimap_annotatemore_entry_att_free(mailimap_annotatemore_entry_att*, );
    enum _Anonymous_103
    {
        POP3_AUTH_TYPE_PLAIN = 0,
        POP3_AUTH_TYPE_APOP = 1,
        POP3_AUTH_TYPE_TRY_APOP = 2,
        POP3_AUTH_TYPE_SASL_ANONYMOUS = 3,
        POP3_AUTH_TYPE_SASL_CRAM_MD5 = 4,
        POP3_AUTH_TYPE_SASL_KERBEROS_V4 = 5,
        POP3_AUTH_TYPE_SASL_PLAIN = 6,
        POP3_AUTH_TYPE_SASL_SCRAM_MD5 = 7,
        POP3_AUTH_TYPE_SASL_GSSAPI = 8,
        POP3_AUTH_TYPE_SASL_DIGEST_MD5 = 9,
    }
    enum POP3_AUTH_TYPE_PLAIN = _Anonymous_103.POP3_AUTH_TYPE_PLAIN;
    enum POP3_AUTH_TYPE_APOP = _Anonymous_103.POP3_AUTH_TYPE_APOP;
    enum POP3_AUTH_TYPE_TRY_APOP = _Anonymous_103.POP3_AUTH_TYPE_TRY_APOP;
    enum POP3_AUTH_TYPE_SASL_ANONYMOUS = _Anonymous_103.POP3_AUTH_TYPE_SASL_ANONYMOUS;
    enum POP3_AUTH_TYPE_SASL_CRAM_MD5 = _Anonymous_103.POP3_AUTH_TYPE_SASL_CRAM_MD5;
    enum POP3_AUTH_TYPE_SASL_KERBEROS_V4 = _Anonymous_103.POP3_AUTH_TYPE_SASL_KERBEROS_V4;
    enum POP3_AUTH_TYPE_SASL_PLAIN = _Anonymous_103.POP3_AUTH_TYPE_SASL_PLAIN;
    enum POP3_AUTH_TYPE_SASL_SCRAM_MD5 = _Anonymous_103.POP3_AUTH_TYPE_SASL_SCRAM_MD5;
    enum POP3_AUTH_TYPE_SASL_GSSAPI = _Anonymous_103.POP3_AUTH_TYPE_SASL_GSSAPI;
    enum POP3_AUTH_TYPE_SASL_DIGEST_MD5 = _Anonymous_103.POP3_AUTH_TYPE_SASL_DIGEST_MD5;
    mailmime_disposition* mailmime_disposition_new_with_data(int, char*, char*, char*, char*, size_t, );
    int mailimap_acl_myrights(mailimap*, const(char)*, mailimap_acl_myrights_data**, );


    mailimf_mailbox* mailimf_mailbox_new(char*, char*, );


    int mailimf_address_list_add_mb(mailimf_address_list*, char*, char*, );




    mailimap_acl_myrights_data* mailimap_acl_myrights_data_new(char*, char*, );
    int mailmessage_fetch(mailmessage*, char**, size_t*, );


    alias __clockid_t = int;


    enum _Anonymous_104
    {
        MAIL_SEARCH_KEY_ALL = 0,
        MAIL_SEARCH_KEY_ANSWERED = 1,
        MAIL_SEARCH_KEY_BCC = 2,
        MAIL_SEARCH_KEY_BEFORE = 3,
        MAIL_SEARCH_KEY_BODY = 4,
        MAIL_SEARCH_KEY_CC = 5,
        MAIL_SEARCH_KEY_DELETED = 6,
        MAIL_SEARCH_KEY_FLAGGED = 7,
        MAIL_SEARCH_KEY_FROM = 8,
        MAIL_SEARCH_KEY_NEW = 9,
        MAIL_SEARCH_KEY_OLD = 10,
        MAIL_SEARCH_KEY_ON = 11,
        MAIL_SEARCH_KEY_RECENT = 12,
        MAIL_SEARCH_KEY_SEEN = 13,
        MAIL_SEARCH_KEY_SINCE = 14,
        MAIL_SEARCH_KEY_SUBJECT = 15,
        MAIL_SEARCH_KEY_TEXT = 16,
        MAIL_SEARCH_KEY_TO = 17,
        MAIL_SEARCH_KEY_UNANSWERED = 18,
        MAIL_SEARCH_KEY_UNDELETED = 19,
        MAIL_SEARCH_KEY_UNFLAGGED = 20,
        MAIL_SEARCH_KEY_UNSEEN = 21,
        MAIL_SEARCH_KEY_HEADER = 22,
        MAIL_SEARCH_KEY_LARGER = 23,
        MAIL_SEARCH_KEY_NOT = 24,
        MAIL_SEARCH_KEY_OR = 25,
        MAIL_SEARCH_KEY_SMALLER = 26,
        MAIL_SEARCH_KEY_MULTIPLE = 27,
    }
    enum MAIL_SEARCH_KEY_ALL = _Anonymous_104.MAIL_SEARCH_KEY_ALL;
    enum MAIL_SEARCH_KEY_ANSWERED = _Anonymous_104.MAIL_SEARCH_KEY_ANSWERED;
    enum MAIL_SEARCH_KEY_BCC = _Anonymous_104.MAIL_SEARCH_KEY_BCC;
    enum MAIL_SEARCH_KEY_BEFORE = _Anonymous_104.MAIL_SEARCH_KEY_BEFORE;
    enum MAIL_SEARCH_KEY_BODY = _Anonymous_104.MAIL_SEARCH_KEY_BODY;
    enum MAIL_SEARCH_KEY_CC = _Anonymous_104.MAIL_SEARCH_KEY_CC;
    enum MAIL_SEARCH_KEY_DELETED = _Anonymous_104.MAIL_SEARCH_KEY_DELETED;
    enum MAIL_SEARCH_KEY_FLAGGED = _Anonymous_104.MAIL_SEARCH_KEY_FLAGGED;
    enum MAIL_SEARCH_KEY_FROM = _Anonymous_104.MAIL_SEARCH_KEY_FROM;
    enum MAIL_SEARCH_KEY_NEW = _Anonymous_104.MAIL_SEARCH_KEY_NEW;
    enum MAIL_SEARCH_KEY_OLD = _Anonymous_104.MAIL_SEARCH_KEY_OLD;
    enum MAIL_SEARCH_KEY_ON = _Anonymous_104.MAIL_SEARCH_KEY_ON;
    enum MAIL_SEARCH_KEY_RECENT = _Anonymous_104.MAIL_SEARCH_KEY_RECENT;
    enum MAIL_SEARCH_KEY_SEEN = _Anonymous_104.MAIL_SEARCH_KEY_SEEN;
    enum MAIL_SEARCH_KEY_SINCE = _Anonymous_104.MAIL_SEARCH_KEY_SINCE;
    enum MAIL_SEARCH_KEY_SUBJECT = _Anonymous_104.MAIL_SEARCH_KEY_SUBJECT;
    enum MAIL_SEARCH_KEY_TEXT = _Anonymous_104.MAIL_SEARCH_KEY_TEXT;
    enum MAIL_SEARCH_KEY_TO = _Anonymous_104.MAIL_SEARCH_KEY_TO;
    enum MAIL_SEARCH_KEY_UNANSWERED = _Anonymous_104.MAIL_SEARCH_KEY_UNANSWERED;
    enum MAIL_SEARCH_KEY_UNDELETED = _Anonymous_104.MAIL_SEARCH_KEY_UNDELETED;
    enum MAIL_SEARCH_KEY_UNFLAGGED = _Anonymous_104.MAIL_SEARCH_KEY_UNFLAGGED;
    enum MAIL_SEARCH_KEY_UNSEEN = _Anonymous_104.MAIL_SEARCH_KEY_UNSEEN;
    enum MAIL_SEARCH_KEY_HEADER = _Anonymous_104.MAIL_SEARCH_KEY_HEADER;
    enum MAIL_SEARCH_KEY_LARGER = _Anonymous_104.MAIL_SEARCH_KEY_LARGER;
    enum MAIL_SEARCH_KEY_NOT = _Anonymous_104.MAIL_SEARCH_KEY_NOT;
    enum MAIL_SEARCH_KEY_OR = _Anonymous_104.MAIL_SEARCH_KEY_OR;
    enum MAIL_SEARCH_KEY_SMALLER = _Anonymous_104.MAIL_SEARCH_KEY_SMALLER;
    enum MAIL_SEARCH_KEY_MULTIPLE = _Anonymous_104.MAIL_SEARCH_KEY_MULTIPLE;
    void mailmime_attribute_free(char*, );
    const(char)* mailsmtp_strerror(int, );


    struct _IO_marker
    {
        _IO_marker* _next;
        _IO_FILE* _sbuf;
        int _pos;
    }


    int mailsession_noop(mailsession*, );
    int mailimf_quoted_string_write(FILE*, int*, const(char)*, size_t, );





    int libetpan_folder_connect(mailengine*, mailfolder*, );
    void mailimf_mailbox_free(mailimf_mailbox*, );
    mailimap_annotatemore_entry_att* mailimap_annotatemore_entry_att_new_empty(char*, );




    void mailimap_acl_myrights_data_free(mailimap_acl_myrights_data*, );
    mailmime_composite_type* mailmime_composite_type_new(int, char*, );
    extern __gshared char*[2] __tzname;
    mailimap_section* mailimap_section_new_text();
    alias __timer_t = void*;
pragma(mangle, "mailimap_capability") int mailimap_capability_(mailimap*, mailimap_capability_data**, );


    FILE* tmpfile();
    int mailimap_has_acl(mailimap*, );


    struct mailfolder
    {
        char* fld_pathname;
        char* fld_virtual_name;
        mailstorage* fld_storage;
        mailsession* fld_session;
        int fld_shared_session;
        clistiter* fld_pos;
        mailfolder* fld_parent;
        uint fld_sibling_index;
        carray* fld_children;
        void* fld_user_data;
    }
    int mailmime_part_parse_partial(const(char)*, size_t, size_t*, int, char**, size_t*, );


    void libetpan_folder_disconnect(mailengine*, mailfolder*, );
    extern __gshared int __daylight;


    void mailmime_single_fields_init(mailmime_single_fields*, mailmime_fields*, mailmime_content*, );
    int mailesmtp_auth_sasl(mailsmtp*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, );





    extern __gshared c_long __timezone;
    int mailimf_address_list_write(FILE*, int*, mailimf_address_list*, );






    alias __blksize_t = c_long;
    int mailimap_annotatemore_entry_att_add(mailimap_annotatemore_entry_att*, mailimap_annotatemore_att_value*, );
    void mailimap_acl_free(mailimap_extension_data*, );


    int mailimf_address_parse(const(char)*, size_t, size_t*, mailimf_address**, );


    void mailmime_composite_type_free(mailmime_composite_type*, );
    enum _Anonymous_105
    {
        POLL_IN = 1,
        POLL_OUT = 2,
        POLL_MSG = 3,
        POLL_ERR = 4,
        POLL_PRI = 5,
        POLL_HUP = 6,
    }
    enum POLL_IN = _Anonymous_105.POLL_IN;
    enum POLL_OUT = _Anonymous_105.POLL_OUT;
    enum POLL_MSG = _Anonymous_105.POLL_MSG;
    enum POLL_ERR = _Anonymous_105.POLL_ERR;
    enum POLL_PRI = _Anonymous_105.POLL_PRI;
    enum POLL_HUP = _Anonymous_105.POLL_HUP;






    mailfolder* libetpan_message_get_folder(mailengine*, mailmessage*, );
    int mailimf_mailbox_list_write(FILE*, int*, mailimf_mailbox_list*, );


    mailmime_single_fields* mailmime_single_fields_new(mailmime_fields*, mailmime_content*, );
    uint chash_size(chash*, );
    extern __gshared char*[2] tzname;
    mailmime_content* mailmime_content_new(mailmime_type*, char*, clist*, );
    int mailmime_get_section_id(mailmime*, mailmime_section**, );
    enum _Anonymous_106
    {
        MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ERROR = 0,
        MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_ATT_LIST = 1,
        MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_LIST = 2,
    }
    enum MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ERROR = _Anonymous_106.MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ERROR;
    enum MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_ATT_LIST = _Anonymous_106.MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_ATT_LIST;
    enum MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_LIST = _Anonymous_106.MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_LIST;
    int sigblock(int, );
    alias __blkcnt_t = c_long;
    mailimap_section* mailimap_section_new_part(mailimap_section_part*, );


    alias __blkcnt64_t = c_long;





    int newsnntp_head(newsnntp*, uint32_t, char**, size_t*, );
    int mailsmtp_noop(mailsmtp*, );
    mailstorage* libetpan_message_get_storage(mailengine*, mailmessage*, );




    int mailimf_header_string_write(FILE*, int*, const(char)*, size_t, );
    int sigsetmask(int, );
    void mailmime_single_fields_free(mailmime_single_fields*, );


    uint chash_count(chash*, );
    void tzset();






    int mailimf_resent_fields_add_data(mailimf_fields*, mailimf_date_time*, mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, char*, );
    alias __fsblkcnt_t = c_ulong;
    int mailsmtp_reset(mailsmtp*, );




    alias __fsblkcnt64_t = c_ulong;
    struct mailimap_annotatemore_entry_list
    {
        int en_list_type;
        clist* en_list_data;
    }
    int siggetmask();
    void mailmime_content_free(mailmime_content*, );




    char* tmpnam(char*, );
    struct mailimf_group
    {
        char* grp_display_name;
        mailimf_mailbox_list* grp_mb_list;
    }


    void mailsmtp_set_progress_callback(mailsmtp*, mailprogress_function*, void*, );
    extern __gshared int daylight;


    int mailmime_smart_add_part(mailmime*, mailmime*, );
    void chash_key(chashiter*, chashdatum*, );
    int mailmessage_fetch_header(mailmessage*, char**, size_t*, );
    alias __fsfilcnt_t = c_ulong;



    int mailimap_check(mailimap*, );
    pragma(mangle, "timezone") extern __gshared c_long timezone_;






    void mailmime_description_free(char*, );
    int mailsession_build_folder_name(mailsession*, const(char)*, const(char)*, char**, );
    enum __codecvt_result
    {
        __codecvt_ok = 0,
        __codecvt_partial = 1,
        __codecvt_error = 2,
        __codecvt_noconv = 3,
    }
    enum __codecvt_ok = __codecvt_result.__codecvt_ok;
    enum __codecvt_partial = __codecvt_result.__codecvt_partial;
    enum __codecvt_error = __codecvt_result.__codecvt_error;
    enum __codecvt_noconv = __codecvt_result.__codecvt_noconv;


    mailimap_section* mailimap_section_new_part_mime(mailimap_section_part*, );
    alias __fsfilcnt64_t = c_ulong;
    int libetpan_message_register(mailengine*, mailfolder*, mailmessage*, );







    struct _xsave_hdr
    {
        __uint64_t xstate_bv;
        __uint64_t[2] __glibc_reserved1;
        __uint64_t[5] __glibc_reserved2;
    }




    void mailmime_location_free(char*, );
    int mailmime_smart_remove_part(mailmime*, );
    alias u_int8_t = ubyte;
    char* tmpnam_r(char*, );


    void mailsmtp_set_logger(mailsmtp*, void function(mailsmtp*, int, const(char)*, c_ulong, void*), void*, );
    mailimap_annotatemore_entry_list* mailimap_annotatemore_entry_list_new(int, clist*, clist*, );



    alias u_int16_t = ushort;
    alias __fsword_t = c_long;
    mailimf_group* mailimf_group_new(char*, mailimf_mailbox_list*, );
    void chash_value(chashiter*, chashdatum*, );


    alias u_int32_t = uint;
    int stime(const(time_t)*, );
    void newsnntp_head_free(char*, );
    mailmime_discrete_type* mailmime_discrete_type_new(int, char*, );
    enum _Anonymous_107
    {
        CONNECTION_TYPE_PLAIN = 0,
        CONNECTION_TYPE_STARTTLS = 1,
        CONNECTION_TYPE_TRY_STARTTLS = 2,
        CONNECTION_TYPE_TLS = 3,
        CONNECTION_TYPE_COMMAND = 4,
        CONNECTION_TYPE_COMMAND_STARTTLS = 5,
        CONNECTION_TYPE_COMMAND_TRY_STARTTLS = 6,
        CONNECTION_TYPE_COMMAND_TLS = 7,
    }
    enum CONNECTION_TYPE_PLAIN = _Anonymous_107.CONNECTION_TYPE_PLAIN;
    enum CONNECTION_TYPE_STARTTLS = _Anonymous_107.CONNECTION_TYPE_STARTTLS;
    enum CONNECTION_TYPE_TRY_STARTTLS = _Anonymous_107.CONNECTION_TYPE_TRY_STARTTLS;
    enum CONNECTION_TYPE_TLS = _Anonymous_107.CONNECTION_TYPE_TLS;
    enum CONNECTION_TYPE_COMMAND = _Anonymous_107.CONNECTION_TYPE_COMMAND;
    enum CONNECTION_TYPE_COMMAND_STARTTLS = _Anonymous_107.CONNECTION_TYPE_COMMAND_STARTTLS;
    enum CONNECTION_TYPE_COMMAND_TRY_STARTTLS = _Anonymous_107.CONNECTION_TYPE_COMMAND_TRY_STARTTLS;
    enum CONNECTION_TYPE_COMMAND_TLS = _Anonymous_107.CONNECTION_TYPE_COMMAND_TLS;
    mailmime_content* mailmime_content_new_with_str(const(char)*, );


    int mailimf_mailbox_parse(const(char)*, size_t, size_t*, mailimf_mailbox**, );
    alias __ssize_t = c_long;
    alias u_int64_t = c_ulong;
    void libetpan_engine_debug(mailengine*, FILE*, );
    void mailimap_annotatemore_entry_list_free(mailimap_annotatemore_entry_list*, );
    alias register_t = c_long;


    struct _ymmh_state
    {
        __uint32_t[64] ymmh_space;
    }
    extern __gshared void* engine_app;


    void mailimf_group_free(mailimf_group*, );
    alias __syscall_slong_t = c_long;
    mailmime_fields* mailmime_fields_new_encoding(int, );
    mailimap_section* mailimap_section_new_part_header(mailimap_section_part*, );
    void mailmime_discrete_type_free(mailmime_discrete_type*, );
    struct mailimap_annotatemore_annotate_data
    {
        char* mailbox;
        mailimap_annotatemore_entry_list* entry_list;
    }




    alias sig_t = void function();
    alias __syscall_ulong_t = c_ulong;
    mailmime* mailmime_multiple_new(const(char)*, );
    struct _xstate
    {
        _fpstate fpstate;
        _xsave_hdr xstate_hdr;
        _ymmh_state ymmh;
    }
    void mailmime_encoding_free(mailmime_mechanism*, );


    char* tempnam(const(char)*, const(char)*, );
    alias __loff_t = c_long;


    mailmime_fields* mailmime_fields_new_filename(int, char*, int, );
    mailimap_annotatemore_annotate_data* mailimap_annotatemore_annotate_data_new(char*, mailimap_annotatemore_entry_list*, );
    int mailimap_close(mailimap*, );




    alias __qaddr_t = c_long*;




    alias __caddr_t = char*;
    void mailmime_extension_token_free(char*, );
    int sigemptyset(sigset_t*, );






    int mailsession_create_folder(mailsession*, const(char)*, );


    struct mailimf_mailbox_list
    {
        clist* mb_list;
    }


    mailmime_parameter* mailmime_param_new_with_data(char*, char*, );
    mailimap_section* mailimap_section_new_part_header_fields(mailimap_section_part*, mailimap_header_list*, );
    int mailmessage_fetch_body(mailmessage*, char**, size_t*, );




    mailimf_fields* mailimf_resent_fields_new_with_data_all(mailimf_date_time*, mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, char*, );
    void mailimap_annotatemore_annotate_data_free(mailimap_annotatemore_annotate_data*, );
    void mailmime_id_free(char*, );
    int sigfillset(sigset_t*, );
    alias __intptr_t = c_long;
    time_t timegm(tm*, );
    int newsnntp_article(newsnntp*, uint32_t, char**, size_t*, );
    int sigaddset(sigset_t*, int, );




    mailmime_mechanism* mailmime_mechanism_new(int, char*, );
    struct mailimap_annotatemore_entry_match_list
    {
        clist* entry_match_list;
    }
    alias __socklen_t = uint;
    char* mailmime_generate_boundary();


    int mailimf_date_time_parse(const(char)*, size_t, size_t*, mailimf_date_time**, );
    time_t timelocal(tm*, );
    int fclose(FILE*, );


    mailimf_mailbox_list* mailimf_mailbox_list_new(clist*, );
    void mailmime_mechanism_free(mailmime_mechanism*, );
    int sigdelset(sigset_t*, int, );
    int dysize(int, );


    mailimap_annotatemore_entry_match_list* mailimap_annotatemore_entry_match_list_new(clist*, );
    alias __sig_atomic_t = int;


    void mailimf_mailbox_list_free(mailimf_mailbox_list*, );
    int sigismember(const(sigset_t)*, int, );
    mailmime_parameter* mailmime_parameter_new(char*, char*, );
    int fflush(FILE*, );






    int mailimap_expunge(mailimap*, );






    mailimap_section* mailimap_section_new_part_header_fields_not(mailimap_section_part*, mailimap_header_list*, );
    void mailimap_annotatemore_entry_match_list_free(mailimap_annotatemore_entry_match_list*, );


    void mailmime_parameter_free(mailmime_parameter*, );




    int mailsession_delete_folder(mailsession*, const(char)*, );


    int mailmessage_fetch_size(mailmessage*, size_t*, );
    struct mailimap_annotatemore_attrib_match_list
    {
        clist* attrib_match_list;
    }


    int nanosleep(const(timespec)*, timespec*, );


    void mailmime_subtype_free(char*, );


    alias blksize_t = c_long;
    int newsnntp_article_by_message_id(newsnntp*, char*, char**, size_t*, );


    struct mailimf_address_list
    {
        clist* ad_list;
    }
    int fflush_unlocked(FILE*, );


    void mailmime_token_free(char*, );






    mailimap_annotatemore_attrib_match_list* mailimap_annotatemore_attrib_match_list_new(clist*, );
    alias size_t = c_ulong;


    int clock_getres(clockid_t, timespec*, );
    mailimf_fields* mailimf_resent_fields_new_with_data(mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, );
    mailmime_type* mailmime_type_new(int, mailmime_discrete_type*, mailmime_composite_type*, );
    mailimf_address_list* mailimf_address_list_new(clist*, );
    int clock_gettime(clockid_t, timespec*, );
    int mailimf_envelope_fields_parse(const(char)*, size_t, size_t*, mailimf_fields**, );


    void mailimap_annotatemore_attrib_match_list_free(mailimap_annotatemore_attrib_match_list*, );


    alias blkcnt_t = c_long;
    mailimap_section* mailimap_section_new_part_text(mailimap_section_part*, );
    int clock_settime(clockid_t, const(timespec)*, );


    int mailimap_copy(mailimap*, mailimap_set*, const(char)*, );
    void mailimf_address_list_free(mailimf_address_list*, );
    alias fsblkcnt_t = c_ulong;
    void mailmime_type_free(mailmime_type*, );
    mailimap_annotatemore_entry_match_list* mailimap_annotatemore_entry_match_list_new_empty();






    int sigprocmask(int, const(sigset_t)*, sigset_t*, );


    int mailsession_rename_folder(mailsession*, const(char)*, const(char)*, );
    void mailmime_value_free(char*, );


    void newsnntp_article_free(char*, );


    alias fsfilcnt_t = c_ulong;
    int mailimap_annotatemore_entry_match_list_add(mailimap_annotatemore_entry_match_list*, char*, );
    int mailmessage_get_bodystructure(mailmessage*, mailmime**, );


    mailimap_fetch_att* mailimap_fetch_att_new_envelope();
    mailimf_fields* mailimf_fields_new_empty();




    int clock_nanosleep(clockid_t, int, const(timespec)*, timespec*, );


    struct mailmime_language
    {
        clist* lg_list;
    }




    mailimap_annotatemore_attrib_match_list* mailimap_annotatemore_attrib_match_list_new_empty();


    FILE* fopen(const(char)*, const(char)*, );




    int sigsuspend(const(sigset_t)*, );
    int clock_getcpuclockid(pid_t, clockid_t*, );


    mailmime_language* mailmime_language_new(clist*, );
    int mailimf_ignore_field_parse(const(char)*, size_t, size_t*, );
    pragma(mangle, "sigaction") int sigaction_(int, const(sigaction)*, sigaction*, );
    int mailimap_annotatemore_attrib_match_list_add(mailimap_annotatemore_attrib_match_list*, char*, );






    struct mailimf_body
    {
        const(char)* bd_text;
        size_t bd_size;
    }
    void mailmime_language_free(mailmime_language*, );




    FILE* freopen(const(char)*, const(char)*, FILE*, );


    int mailsession_check_folder(mailsession*, );


    mailimap_fetch_att* mailimap_fetch_att_new_flags();
    int sigpending(sigset_t*, );
    int mailimap_uid_copy(mailimap*, mailimap_set*, const(char)*, );


    int timer_create(clockid_t, sigevent*, timer_t*, );
    struct mailimap_annotatemore_entry_att_list
    {
        clist* entry_att_list;
    }


    int newsnntp_body(newsnntp*, uint32_t, char**, size_t*, );
    int mailimf_fields_add(mailimf_fields*, mailimf_field*, );
    struct _IO_FILE
    {
        int _flags;
        char* _IO_read_ptr;
        char* _IO_read_end;
        char* _IO_read_base;
        char* _IO_write_base;
        char* _IO_write_ptr;
        char* _IO_write_end;
        char* _IO_buf_base;
        char* _IO_buf_end;
        char* _IO_save_base;
        char* _IO_backup_base;
        char* _IO_save_end;
        _IO_marker* _markers;
        _IO_FILE* _chain;
        int _fileno;
        int _flags2;
        __off_t _old_offset;
        ushort _cur_column;
        byte _vtable_offset;
        char[1] _shortbuf;
        _IO_lock_t* _lock;
        __off64_t _offset;
        void* __pad1;
        void* __pad2;
        void* __pad3;
        void* __pad4;
        size_t __pad5;
        int _mode;
        char[20] _unused2;
    }


    mailimf_body* mailimf_body_new(const(char)*, size_t, );






    int timer_delete(timer_t, );
    mailimap_annotatemore_entry_att_list* mailimap_annotatemore_entry_att_list_new(clist*, );


    mailmime_field* mailmime_field_new(int, mailmime_content*, mailmime_mechanism*, char*, char*, uint32_t, mailmime_disposition*, mailmime_language*, char*, );
    void mailimf_body_free(mailimf_body*, );




    int timer_settime(timer_t, int, const(itimerspec)*, itimerspec*, );
    int sigwait(const(sigset_t)*, int*, );


    mailimap_fetch_att* mailimap_fetch_att_new_internaldate();


    int mailmessage_fetch_section(mailmessage*, mailmime*, char**, size_t*, );
    void mailimap_annotatemore_entry_att_list_free(mailimap_annotatemore_entry_att_list*, );




    int mailsession_examine_folder(mailsession*, const(char)*, );


    int timer_gettime(timer_t, itimerspec*, );
    mailimap_annotatemore_entry_att_list* mailimap_annotatemore_entry_att_list_new_empty();




    void newsnntp_body_free(char*, );
    int mailimap_annotatemore_entry_att_list_add(mailimap_annotatemore_entry_att_list*, mailimap_annotatemore_entry_att*, );
    int sigwaitinfo(const(sigset_t)*, siginfo_t*, );
    int mailimf_envelope_and_optional_fields_parse(const(char)*, size_t, size_t*, mailimf_fields**, );
    int timer_getoverrun(timer_t, );
    mailimap_fetch_att* mailimap_fetch_att_new_rfc822();


    void mailmime_field_free(mailmime_field*, );


    int mailimap_move(mailimap*, mailimap_set*, const(char)*, );
    struct mailimf_message
    {
        mailimf_fields* msg_fields;
        mailimf_body* msg_body;
    }
    mailmime_fields* mailmime_fields_new(clist*, );
    void mailimap_annotatemore_free(mailimap_extension_data*, );
    int timespec_get(timespec*, int, );
    int mailsession_select_folder(mailsession*, const(char)*, );
    int mailimf_fields_add_data(mailimf_fields*, mailimf_date_time*, mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, char*, clist*, clist*, char*, );
    void mailmime_fields_free(mailmime_fields*, );
    mailimf_message* mailimf_message_new(mailimf_fields*, mailimf_body*, );
    FILE* fdopen(int, const(char)*, );
    int sigtimedwait(const(sigset_t)*, siginfo_t*, const(timespec)*, );
    struct mailmime_multipart_body
    {
        clist* bd_list;
    }
    int newsnntp_mode_reader(newsnntp*, );


    mailimap_fetch_att* mailimap_fetch_att_new_rfc822_header();


    void mailimf_message_free(mailimf_message*, );




    struct _Anonymous_108
    {
        c_long quot;
        c_long rem;
    }
    alias imaxdiv_t = _Anonymous_108;
    int mailmessage_fetch_section_header(mailmessage*, mailmime*, char**, size_t*, );


    int sigqueue(__pid_t, int, const(sigval), );


    mailmime_multipart_body* mailmime_multipart_body_new(clist*, );
    int mailsession_expunge_folder(mailsession*, );
    int mailimap_uid_move(mailimap*, mailimap_set*, const(char)*, );
    void mailmime_multipart_body_free(mailmime_multipart_body*, );
    mailimap_fetch_att* mailimap_fetch_att_new_rfc822_size();
    int mailimf_optional_fields_parse(const(char)*, size_t, size_t*, mailimf_fields**, );
    FILE* fmemopen(void*, size_t, const(char)*, );
    enum _Anonymous_109
    {
        MAILMIME_DATA_TEXT = 0,
        MAILMIME_DATA_FILE = 1,
    }
    enum MAILMIME_DATA_TEXT = _Anonymous_109.MAILMIME_DATA_TEXT;
    enum MAILMIME_DATA_FILE = _Anonymous_109.MAILMIME_DATA_FILE;







    struct mailimf_fields
    {
        clist* fld_list;
    }
    int newsnntp_date(newsnntp*, tm*, );
    extern __gshared const(const(char)*)[65] _sys_siglist;
    extern __gshared const(const(char)*)[65] sys_siglist;
    FILE* open_memstream(char**, size_t*, );
    struct mailmime_data
    {
        int dt_type;
        int dt_encoding;
        int dt_encoded;
        union _Anonymous_110
        {
            struct _Anonymous_111
            {
                const(char)* dt_data;
                size_t dt_length;
            }
            _Anonymous_111 dt_text;
            char* dt_filename;
        }
        _Anonymous_110 dt_data;
    }
    mailimap_fetch_att* mailimap_fetch_att_new_rfc822_text();
    int mailimf_fws_parse(const(char)*, size_t, size_t*, );
    mailimf_fields* mailimf_fields_new(clist*, );
    int mailimf_cfws_parse(const(char)*, size_t, size_t*, );


    void mailimf_fields_free(mailimf_fields*, );
    intmax_t imaxabs(intmax_t, );
    int sigreturn(sigcontext*, );
    void setbuf(FILE*, char*, );
    int mailimap_create(mailimap*, const(char)*, );
    int mailimf_char_parse(const(char)*, size_t, size_t*, char, );
    imaxdiv_t imaxdiv(intmax_t, intmax_t, );
    int setvbuf(FILE*, char*, int, size_t, );
    int newsnntp_authinfo_username(newsnntp*, const(char)*, );


    enum _Anonymous_112
    {
        MAILIMF_FIELD_NONE = 0,
        MAILIMF_FIELD_RETURN_PATH = 1,
        MAILIMF_FIELD_RESENT_DATE = 2,
        MAILIMF_FIELD_RESENT_FROM = 3,
        MAILIMF_FIELD_RESENT_SENDER = 4,
        MAILIMF_FIELD_RESENT_TO = 5,
        MAILIMF_FIELD_RESENT_CC = 6,
        MAILIMF_FIELD_RESENT_BCC = 7,
        MAILIMF_FIELD_RESENT_MSG_ID = 8,
        MAILIMF_FIELD_ORIG_DATE = 9,
        MAILIMF_FIELD_FROM = 10,
        MAILIMF_FIELD_SENDER = 11,
        MAILIMF_FIELD_REPLY_TO = 12,
        MAILIMF_FIELD_TO = 13,
        MAILIMF_FIELD_CC = 14,
        MAILIMF_FIELD_BCC = 15,
        MAILIMF_FIELD_MESSAGE_ID = 16,
        MAILIMF_FIELD_IN_REPLY_TO = 17,
        MAILIMF_FIELD_REFERENCES = 18,
        MAILIMF_FIELD_SUBJECT = 19,
        MAILIMF_FIELD_COMMENTS = 20,
        MAILIMF_FIELD_KEYWORDS = 21,
        MAILIMF_FIELD_OPTIONAL_FIELD = 22,
    }
    enum MAILIMF_FIELD_NONE = _Anonymous_112.MAILIMF_FIELD_NONE;
    enum MAILIMF_FIELD_RETURN_PATH = _Anonymous_112.MAILIMF_FIELD_RETURN_PATH;
    enum MAILIMF_FIELD_RESENT_DATE = _Anonymous_112.MAILIMF_FIELD_RESENT_DATE;
    enum MAILIMF_FIELD_RESENT_FROM = _Anonymous_112.MAILIMF_FIELD_RESENT_FROM;
    enum MAILIMF_FIELD_RESENT_SENDER = _Anonymous_112.MAILIMF_FIELD_RESENT_SENDER;
    enum MAILIMF_FIELD_RESENT_TO = _Anonymous_112.MAILIMF_FIELD_RESENT_TO;
    enum MAILIMF_FIELD_RESENT_CC = _Anonymous_112.MAILIMF_FIELD_RESENT_CC;
    enum MAILIMF_FIELD_RESENT_BCC = _Anonymous_112.MAILIMF_FIELD_RESENT_BCC;
    enum MAILIMF_FIELD_RESENT_MSG_ID = _Anonymous_112.MAILIMF_FIELD_RESENT_MSG_ID;
    enum MAILIMF_FIELD_ORIG_DATE = _Anonymous_112.MAILIMF_FIELD_ORIG_DATE;
    enum MAILIMF_FIELD_FROM = _Anonymous_112.MAILIMF_FIELD_FROM;
    enum MAILIMF_FIELD_SENDER = _Anonymous_112.MAILIMF_FIELD_SENDER;
    enum MAILIMF_FIELD_REPLY_TO = _Anonymous_112.MAILIMF_FIELD_REPLY_TO;
    enum MAILIMF_FIELD_TO = _Anonymous_112.MAILIMF_FIELD_TO;
    enum MAILIMF_FIELD_CC = _Anonymous_112.MAILIMF_FIELD_CC;
    enum MAILIMF_FIELD_BCC = _Anonymous_112.MAILIMF_FIELD_BCC;
    enum MAILIMF_FIELD_MESSAGE_ID = _Anonymous_112.MAILIMF_FIELD_MESSAGE_ID;
    enum MAILIMF_FIELD_IN_REPLY_TO = _Anonymous_112.MAILIMF_FIELD_IN_REPLY_TO;
    enum MAILIMF_FIELD_REFERENCES = _Anonymous_112.MAILIMF_FIELD_REFERENCES;
    enum MAILIMF_FIELD_SUBJECT = _Anonymous_112.MAILIMF_FIELD_SUBJECT;
    enum MAILIMF_FIELD_COMMENTS = _Anonymous_112.MAILIMF_FIELD_COMMENTS;
    enum MAILIMF_FIELD_KEYWORDS = _Anonymous_112.MAILIMF_FIELD_KEYWORDS;
    enum MAILIMF_FIELD_OPTIONAL_FIELD = _Anonymous_112.MAILIMF_FIELD_OPTIONAL_FIELD;
    int mailsession_status_folder(mailsession*, const(char)*, uint32_t*, uint32_t*, uint32_t*, );
    int mailmessage_fetch_section_mime(mailmessage*, mailmime*, char**, size_t*, );
    mailimap_fetch_att* mailimap_fetch_att_new_body();
    mailimf_fields* mailimf_fields_new_with_data_all(mailimf_date_time*, mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, char*, clist*, clist*, char*, );
    int mailimf_unstrict_char_parse(const(char)*, size_t, size_t*, char, );



    intmax_t strtoimax(const(char)*, char**, int, );
    mailmime_data* mailmime_data_new(int, int, int, const(char)*, size_t, char*, );


    void setbuffer(FILE*, char*, size_t, );
    int mailimf_crlf_parse(const(char)*, size_t, size_t*, );
    uintmax_t strtoumax(const(char)*, char**, int, );
    void mailmime_data_free(mailmime_data*, );


    mailimap_fetch_att* mailimap_fetch_att_new_bodystructure();
    void setlinebuf(FILE*, );
    int mailimf_custom_string_parse(const(char)*, size_t, size_t*, char**, int function(char), );
    intmax_t wcstoimax(const(__gwchar_t)*, __gwchar_t**, int, );
    enum _Anonymous_113
    {
        MAILMIME_NONE = 0,
        MAILMIME_SINGLE = 1,
        MAILMIME_MULTIPLE = 2,
        MAILMIME_MESSAGE = 3,
    }
    enum MAILMIME_NONE = _Anonymous_113.MAILMIME_NONE;
    enum MAILMIME_SINGLE = _Anonymous_113.MAILMIME_SINGLE;
    enum MAILMIME_MULTIPLE = _Anonymous_113.MAILMIME_MULTIPLE;
    enum MAILMIME_MESSAGE = _Anonymous_113.MAILMIME_MESSAGE;


    int newsnntp_authinfo_password(newsnntp*, const(char)*, );
    int mailimap_delete(mailimap*, const(char)*, );


    uintmax_t wcstoumax(const(__gwchar_t)*, __gwchar_t**, int, );
    int siginterrupt(int, int, );
    int mailimf_token_case_insensitive_len_parse(const(char)*, size_t, size_t*, char*, size_t, );


    int mailsession_messages_number(mailsession*, const(char)*, uint32_t*, );
    int fprintf(FILE*, const(char)*, ...);
    struct _IO_FILE_plus;
    mailimap_fetch_att* mailimap_fetch_att_new_uid();
    struct mailmime
    {
        int mm_parent_type;
        mailmime* mm_parent;
        clistiter* mm_multipart_pos;
        int mm_type;
        const(char)* mm_mime_start;
        size_t mm_length;
        mailmime_fields* mm_mime_fields;
        mailmime_content* mm_content_type;
        mailmime_data* mm_body;
        union _Anonymous_114
        {
            mailmime_data* mm_single;
            struct _Anonymous_115
            {
                mailmime_data* mm_preamble;
                mailmime_data* mm_epilogue;
                clist* mm_mp_list;
            }
            _Anonymous_115 mm_multipart;
            struct _Anonymous_116
            {
                mailimf_fields* mm_fields;
                mailmime* mm_msg_mime;
            }
            _Anonymous_116 mm_message;
        }
        _Anonymous_114 mm_data;
    }






    int sigaltstack(const(stack_t)*, stack_t*, );
    int printf(const(char)*, ...);




    int mailmessage_fetch_section_body(mailmessage*, mailmime*, char**, size_t*, );


    int mailimf_quoted_string_parse(const(char)*, size_t, size_t*, char**, );
    int sprintf(char*, const(char)*, ...);




    int newsnntp_post(newsnntp*, const(char)*, size_t, );
    mailimap_fetch_att* mailimap_fetch_att_new_body_section(mailimap_section*, );
    int mailimap_examine(mailimap*, const(char)*, );
    int mailimf_number_parse(const(char)*, size_t, size_t*, uint32_t*, );


    int vfprintf(FILE*, const(char)*, va_list, );
    int mailsession_recent_number(mailsession*, const(char)*, uint32_t*, );
    mailimf_fields* mailimf_fields_new_with_data(mailimf_mailbox_list*, mailimf_mailbox*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, mailimf_address_list*, clist*, clist*, char*, );
    int mailimf_msg_id_parse(const(char)*, size_t, size_t*, char**, );
    mailimap_fetch_att* mailimap_fetch_att_new_body_peek_section(mailimap_section*, );
    pragma(mangle, "sigstack") int sigstack_(sigstack*, sigstack*, );
    alias __io_read_fn = c_long function(void*, char*, size_t);
    int vprintf(const(char)*, va_list, );
    int mailimf_msg_id_list_parse(const(char)*, size_t, size_t*, clist**, );
    int vsprintf(char*, const(char)*, va_list, );
    int mailimf_word_parse(const(char)*, size_t, size_t*, char**, );
    int mailmessage_fetch_envelope(mailmessage*, mailimf_fields**, );
    int newsnntp_group(newsnntp*, const(char)*, newsnntp_group_info**, );
    int snprintf(char*, size_t, const(char)*, ...);
    mailimap_fetch_att* mailimap_fetch_att_new_body_section_partial(mailimap_section*, uint32_t, uint32_t, );
    alias __io_write_fn = c_long function(void*, const(char)*, size_t);


    int mailimap_fetch(mailimap*, mailimap_set*, mailimap_fetch_type*, clist**, );
    int mailimf_atom_parse(const(char)*, size_t, size_t*, char**, );
    int mailsession_unseen_number(mailsession*, const(char)*, uint32_t*, );



    int vsnprintf(char*, size_t, const(char)*, va_list, );
    char* mailimf_get_message_id();
    int mailimf_fws_atom_parse(const(char)*, size_t, size_t*, char**, );
    mailmime* mailmime_new(int, const(char)*, size_t, mailmime_fields*, mailmime_content*, mailmime_data*, mailmime_data*, mailmime_data*, clist*, mailimf_fields*, mailmime*, );
    int mailimf_fws_word_parse(const(char)*, size_t, size_t*, char**, int*, );
    alias __io_seek_fn = int function(void*, __off64_t*, int);
    mailimap_fetch_att* mailimap_fetch_att_new_body_peek_section_partial(mailimap_section*, uint32_t, uint32_t, );
    void newsnntp_group_free(newsnntp_group_info*, );


    alias __io_close_fn = int function(void*);
    mailimf_date_time* mailimf_get_current_date();
    int mailimf_fws_quoted_string_parse(const(char)*, size_t, size_t*, char**, );
    mailimf_date_time* mailimf_get_date(time_t, );
    int mailmessage_get_flags(mailmessage*, mail_flags**, );
    mailimap_fetch_att* mailimap_fetch_att_new_extension(char*, );
    int mailimf_references_parse(const(char)*, size_t, size_t*, mailimf_references**, );
    void mailmime_free(mailmime*, );
    int mailsession_list_folders(mailsession*, const(char)*, mail_list**, );
    int __libc_current_sigrtmin();
    struct mailmime_encoded_word
    {
        char* wd_charset;
        char* wd_text;
    }


    void mailimf_single_fields_init(mailimf_single_fields*, mailimf_fields*, );
    int mailimap_uid_fetch(mailimap*, mailimap_set*, mailimap_fetch_type*, clist**, );
    int __libc_current_sigrtmax();
    int vdprintf(int, const(char)*, va_list, );
    int newsnntp_list(newsnntp*, clist**, );






    mailmime_encoded_word* mailmime_encoded_word_new(char*, char*, );
    int dprintf(int, const(char)*, ...);
    mailimap_fetch_type* mailimap_fetch_type_new_all();
    void mailmime_encoded_word_free(mailmime_encoded_word*, );
    mailimf_single_fields* mailimf_single_fields_new(mailimf_fields*, );
    void mailmessage_resolve_single_fields(mailmessage*, );


    void mailmime_charset_free(char*, );
    struct mailimf_field
    {
        int fld_type;
        union _Anonymous_117
        {
            mailimf_return* fld_return_path;
            mailimf_orig_date* fld_resent_date;
            mailimf_from* fld_resent_from;
            mailimf_sender* fld_resent_sender;
            mailimf_to* fld_resent_to;
            mailimf_cc* fld_resent_cc;
            mailimf_bcc* fld_resent_bcc;
            mailimf_message_id* fld_resent_msg_id;
            mailimf_orig_date* fld_orig_date;
            mailimf_from* fld_from;
            mailimf_sender* fld_sender;
            mailimf_reply_to* fld_reply_to;
            mailimf_to* fld_to;
            mailimf_cc* fld_cc;
            mailimf_bcc* fld_bcc;
            mailimf_message_id* fld_message_id;
            mailimf_in_reply_to* fld_in_reply_to;
            mailimf_references* fld_references;
            mailimf_subject* fld_subject;
            mailimf_comments* fld_comments;
            mailimf_keywords* fld_keywords;
            mailimf_optional_field* fld_optional_field;
        }
        _Anonymous_117 fld_data;
    }
    void newsnntp_list_free(clist*, );
    mailimap_fetch_type* mailimap_fetch_type_new_full();
    int fscanf(FILE*, const(char)*, ...);
    void mailimf_single_fields_free(mailimf_single_fields*, );
    void mailmime_encoded_text_free(char*, );


    void mailimap_fetch_list_free(clist*, );
    int mailsession_lsub_folders(mailsession*, const(char)*, mail_list**, );
    struct mailmime_disposition
    {
        mailmime_disposition_type* dsp_type;
        clist* dsp_parms;
    }
    int sscanf(const(char)*, const(char)*, ...);
    int __underflow(_IO_FILE*, );


    mailimap_fetch_type* mailimap_fetch_type_new_fast();
    int __uflow(_IO_FILE*, );
    int __overflow(_IO_FILE*, int, );
    enum _Anonymous_118
    {
        MAILMIME_DISPOSITION_TYPE_ERROR = 0,
        MAILMIME_DISPOSITION_TYPE_INLINE = 1,
        MAILMIME_DISPOSITION_TYPE_ATTACHMENT = 2,
        MAILMIME_DISPOSITION_TYPE_EXTENSION = 3,
    }
    enum MAILMIME_DISPOSITION_TYPE_ERROR = _Anonymous_118.MAILMIME_DISPOSITION_TYPE_ERROR;
    enum MAILMIME_DISPOSITION_TYPE_INLINE = _Anonymous_118.MAILMIME_DISPOSITION_TYPE_INLINE;
    enum MAILMIME_DISPOSITION_TYPE_ATTACHMENT = _Anonymous_118.MAILMIME_DISPOSITION_TYPE_ATTACHMENT;
    enum MAILMIME_DISPOSITION_TYPE_EXTENSION = _Anonymous_118.MAILMIME_DISPOSITION_TYPE_EXTENSION;
    mailimf_field* mailimf_field_new_custom(char*, char*, );
    int newsnntp_list_overview_fmt(newsnntp*, clist**, );
    struct mailmime_disposition_type
    {
        int dsp_type;
        char* dsp_extension;
    }




    mailimap_fetch_type* mailimap_fetch_type_new_fetch_att(mailimap_fetch_att*, );




    int mailsession_subscribe_folder(mailsession*, const(char)*, );
    int scanf(const(char)*, ...);
    int mailimap_list(mailimap*, const(char)*, const(char)*, clist**, );




    enum _Anonymous_119
    {
        MAILMIME_DISPOSITION_PARM_FILENAME = 0,
        MAILMIME_DISPOSITION_PARM_CREATION_DATE = 1,
        MAILMIME_DISPOSITION_PARM_MODIFICATION_DATE = 2,
        MAILMIME_DISPOSITION_PARM_READ_DATE = 3,
        MAILMIME_DISPOSITION_PARM_SIZE = 4,
        MAILMIME_DISPOSITION_PARM_PARAMETER = 5,
    }
    enum MAILMIME_DISPOSITION_PARM_FILENAME = _Anonymous_119.MAILMIME_DISPOSITION_PARM_FILENAME;
    enum MAILMIME_DISPOSITION_PARM_CREATION_DATE = _Anonymous_119.MAILMIME_DISPOSITION_PARM_CREATION_DATE;
    enum MAILMIME_DISPOSITION_PARM_MODIFICATION_DATE = _Anonymous_119.MAILMIME_DISPOSITION_PARM_MODIFICATION_DATE;
    enum MAILMIME_DISPOSITION_PARM_READ_DATE = _Anonymous_119.MAILMIME_DISPOSITION_PARM_READ_DATE;
    enum MAILMIME_DISPOSITION_PARM_SIZE = _Anonymous_119.MAILMIME_DISPOSITION_PARM_SIZE;
    enum MAILMIME_DISPOSITION_PARM_PARAMETER = _Anonymous_119.MAILMIME_DISPOSITION_PARM_PARAMETER;
    void newsnntp_list_overview_fmt_free(clist*, );





    mailimap_fetch_type* mailimap_fetch_type_new_fetch_att_list(clist*, );
    mailimf_field* mailimf_field_new(int, mailimf_return*, mailimf_orig_date*, mailimf_from*, mailimf_sender*, mailimf_to*, mailimf_cc*, mailimf_bcc*, mailimf_message_id*, mailimf_orig_date*, mailimf_from*, mailimf_sender*, mailimf_reply_to*, mailimf_to*, mailimf_cc*, mailimf_bcc*, mailimf_message_id*, mailimf_in_reply_to*, mailimf_references*, mailimf_subject*, mailimf_comments*, mailimf_keywords*, mailimf_optional_field*, );







    struct mailmime_disposition_parm
    {
        int pa_type;
        union _Anonymous_120
        {
            char* pa_filename;
            char* pa_creation_date;
            char* pa_modification_date;
            char* pa_read_date;
            size_t pa_size;
            mailmime_parameter* pa_parameter;
        }
        _Anonymous_120 pa_data;
    }


    int mailsession_unsubscribe_folder(mailsession*, const(char)*, );
    mailimap_fetch_type* mailimap_fetch_type_new_fetch_att_list_empty();




    int mailimap_login(mailimap*, const(char)*, const(char)*, );



    int newsnntp_list_active(newsnntp*, const(char)*, clist**, );
    mailmime_disposition* mailmime_disposition_new(mailmime_disposition_type*, clist*, );
    int mailimap_fetch_type_new_fetch_att_list_add(mailimap_fetch_type*, mailimap_fetch_att*, );


    int mailsession_append_message(mailsession*, const(char)*, size_t, );
    int mailimap_authenticate(mailimap*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, );


    void mailmime_disposition_free(mailmime_disposition*, );
    int _IO_getc(_IO_FILE*, );
    void newsnntp_list_active_free(clist*, );
    mailmime_disposition_type* mailmime_disposition_type_new(int, char*, );
    int mailsession_append_message_flags(mailsession*, const(char)*, size_t, mail_flags*, );
    int _IO_putc(int, _IO_FILE*, );
    int _IO_feof(_IO_FILE*, );
    void mailimf_field_free(mailimf_field*, );
    int _IO_ferror(_IO_FILE*, );
    int vsscanf(const(char)*, const(char)*, va_list, );
    void mailmime_disposition_type_free(mailmime_disposition_type*, );
    int _IO_peekc_locked(_IO_FILE*, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_set_flags(mailimap_flag_list*, );



    mailmime_disposition_parm* mailmime_disposition_parm_new(int, char*, char*, char*, char*, size_t, mailmime_parameter*, );
    void _IO_flockfile(_IO_FILE*, );
    struct mailimf_orig_date
    {
        mailimf_date_time* dt_date_time;
    }
    void _IO_funlockfile(_IO_FILE*, );


    int _IO_ftrylockfile(_IO_FILE*, );
    int vfscanf(FILE*, const(char)*, va_list, );


    int newsnntp_list_active_times(newsnntp*, clist**, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_set_flags_silent(mailimap_flag_list*, );
    mailimf_orig_date* mailimf_orig_date_new(mailimf_date_time*, );


    void mailmime_disposition_parm_free(mailmime_disposition_parm*, );


    int mailsession_copy_message(mailsession*, uint32_t, const(char)*, );
    int vscanf(const(char)*, va_list, );





    void mailimf_orig_date_free(mailimf_orig_date*, );
    void mailmime_filename_parm_free(char*, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_add_flags(mailimap_flag_list*, );
    int mailimap_lsub(mailimap*, const(char)*, const(char)*, clist**, );


    void mailmime_creation_date_parm_free(char*, );
    void newsnntp_list_active_times_free(clist*, );



    void mailmime_modification_date_parm_free(char*, );
    int _IO_vfscanf(_IO_FILE*, const(char)*, va_list, int*, );
    int _IO_vfprintf(_IO_FILE*, const(char)*, va_list, );
    void mailmime_read_date_parm_free(char*, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_add_flags_silent(mailimap_flag_list*, );


    struct mailimf_from
    {
        mailimf_mailbox_list* frm_mb_list;
    }



    __ssize_t _IO_padn(_IO_FILE*, int, __ssize_t, );
    size_t _IO_sgetn(_IO_FILE*, void*, size_t, );
    void mailmime_quoted_date_time_free(char*, );
    void mailimap_list_result_free(clist*, );
    __off64_t _IO_seekoff(_IO_FILE*, __off64_t, int, int, );
    struct mailmime_section
    {
        clist* sec_list;
    }
    __off64_t _IO_seekpos(_IO_FILE*, __off64_t, int, );
    int mailsession_move_message(mailsession*, uint32_t, const(char)*, );
    mailimf_from* mailimf_from_new(mailimf_mailbox_list*, );
    void _IO_free_backup_area(_IO_FILE*, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_remove_flags(mailimap_flag_list*, );
    int newsnntp_list_distribution(newsnntp*, clist**, );
    mailmime_section* mailmime_section_new(clist*, );
    void mailimf_from_free(mailimf_from*, );
    void mailmime_section_free(mailmime_section*, );
    struct mailsession_driver
    {
        char* sess_name;
        int function(mailsession*) sess_initialize;
        void function(mailsession*) sess_uninitialize;
        int function(mailsession*, int, void*) sess_parameters;
        int function(mailsession*, _mailstream*) sess_connect_stream;
        int function(mailsession*, const(char)*) sess_connect_path;
        int function(mailsession*) sess_starttls;
        int function(mailsession*, const(char)*, const(char)*) sess_login;
        int function(mailsession*) sess_logout;
        int function(mailsession*) sess_noop;
        int function(mailsession*, const(char)*, const(char)*, char**) sess_build_folder_name;
        int function(mailsession*, const(char)*) sess_create_folder;
        int function(mailsession*, const(char)*) sess_delete_folder;
        int function(mailsession*, const(char)*, const(char)*) sess_rename_folder;
        int function(mailsession*) sess_check_folder;
        int function(mailsession*, const(char)*) sess_examine_folder;
        int function(mailsession*, const(char)*) sess_select_folder;
        int function(mailsession*) sess_expunge_folder;
        int function(mailsession*, const(char)*, uint*, uint*, uint*) sess_status_folder;
        int function(mailsession*, const(char)*, uint*) sess_messages_number;
        int function(mailsession*, const(char)*, uint*) sess_recent_number;
        int function(mailsession*, const(char)*, uint*) sess_unseen_number;
        int function(mailsession*, const(char)*, mail_list**) sess_list_folders;
        int function(mailsession*, const(char)*, mail_list**) sess_lsub_folders;
        int function(mailsession*, const(char)*) sess_subscribe_folder;
        int function(mailsession*, const(char)*) sess_unsubscribe_folder;
        int function(mailsession*, const(char)*, c_ulong) sess_append_message;
        int function(mailsession*, const(char)*, c_ulong, mail_flags*) sess_append_message_flags;
        int function(mailsession*, uint, const(char)*) sess_copy_message;
        int function(mailsession*, uint, const(char)*) sess_move_message;
        int function(mailsession*, uint, mailmessage**) sess_get_message;
        int function(mailsession*, const(char)*, mailmessage**) sess_get_message_by_uid;
        int function(mailsession*, mailmessage_list**) sess_get_messages_list;
        int function(mailsession*, mailmessage_list*) sess_get_envelopes_list;
        int function(mailsession*, uint) sess_remove_message;
        int function(mailsession*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*) sess_login_sasl;
    }
    void mailmime_decoded_part_free(char*, );
    int fgetc(FILE*, );
    mailimap_store_att_flags* mailimap_store_att_flags_new_remove_flags_silent(mailimap_flag_list*, );
    int getc(FILE*, );


    struct mailmime_single_fields
    {
        mailmime_content* fld_content;
        char* fld_content_charset;
        char* fld_content_boundary;
        char* fld_content_name;
        mailmime_mechanism* fld_encoding;
        char* fld_id;
        char* fld_description;
        uint32_t fld_version;
        mailmime_disposition* fld_disposition;
        char* fld_disposition_filename;
        char* fld_disposition_creation_date;
        char* fld_disposition_modification_date;
        char* fld_disposition_read_date;
        size_t fld_disposition_size;
        mailmime_language* fld_language;
        char* fld_location;
    }
    int mailimap_rename(mailimap*, const(char)*, const(char)*, );
    struct mailimf_sender
    {
        mailimf_mailbox* snd_mb;
    }
    void newsnntp_list_distribution_free(clist*, );
    int mailsession_get_messages_list(mailsession*, mailmessage_list**, );
    int getchar();
    mailimf_sender* mailimf_sender_new(mailimf_mailbox*, );
    mailimap_search_key* mailimap_search_key_new_all();


    void mailimf_sender_free(mailimf_sender*, );
    int getc_unlocked(FILE*, );
    int getchar_unlocked();
    int newsnntp_list_distrib_pats(newsnntp*, clist**, );
    int mailsession_get_envelopes_list(mailsession*, mailmessage_list*, );
    mailimap_search_key* mailimap_search_key_new_bcc(char*, );
    struct mailimf_reply_to
    {
        mailimf_address_list* rt_addr_list;
    }
    int mailimap_search(mailimap*, const(char)*, mailimap_search_key*, clist**, );


    mailimf_reply_to* mailimf_reply_to_new(mailimf_address_list*, );
    int fgetc_unlocked(FILE*, );
    mailimap_search_key* mailimap_search_key_new_before(mailimap_date*, );
    void newsnntp_list_distrib_pats_free(clist*, );
    void mailimf_reply_to_free(mailimf_reply_to*, );
    int mailsession_remove_message(mailsession*, uint32_t, );
    int fputc(int, FILE*, );
    int putc(int, FILE*, );
    mailimap_search_key* mailimap_search_key_new_body(char*, );
    struct mailimf_to
    {
        mailimf_address_list* to_addr_list;
    }
    int newsnntp_list_newsgroups(newsnntp*, const(char)*, clist**, );
    mailimf_to* mailimf_to_new(mailimf_address_list*, );
    int mailimap_uid_search(mailimap*, const(char)*, mailimap_search_key*, clist**, );
    int putchar(int, );
    void mailimf_to_free(mailimf_to*, );


    mailimap_search_key* mailimap_search_key_new_cc(char*, );
    void newsnntp_list_newsgroups_free(clist*, );
    int fputc_unlocked(int, FILE*, );
    struct mailimf_cc
    {
        mailimf_address_list* cc_addr_list;
    }
    mailimf_cc* mailimf_cc_new(mailimf_address_list*, );
    mailimap_search_key* mailimap_search_key_new_from(char*, );
    int putc_unlocked(int, FILE*, );
    int putchar_unlocked(int, );
    int mailimap_search_literalplus(mailimap*, const(char)*, mailimap_search_key*, clist**, );
    void mailimf_cc_free(mailimf_cc*, );
    struct mailimap_address
    {
        char* ad_personal_name;
        char* ad_source_route;
        char* ad_mailbox_name;
        char* ad_host_name;
    }
    int newsnntp_list_subscriptions(newsnntp*, clist**, );
    mailimap_search_key* mailimap_search_key_new_keyword(char*, );
    int getw(FILE*, );
    int mailsession_get_message(mailsession*, uint32_t, mailmessage**, );
    int putw(int, FILE*, );
    mailimap_address* mailimap_address_new(char*, char*, char*, char*, );
    struct mailimf_bcc
    {
        mailimf_address_list* bcc_addr_list;
    }
    void newsnntp_list_subscriptions_free(clist*, );
    mailimf_bcc* mailimf_bcc_new(mailimf_address_list*, );
    mailimap_search_key* mailimap_search_key_new_on(mailimap_date*, );
    void mailimap_address_free(mailimap_address*, );
    char* fgets(char*, int, FILE*, );
    struct mailsession
    {
        void* sess_data;
        mailsession_driver* sess_driver;
    }
    void mailimf_bcc_free(mailimf_bcc*, );
    enum _Anonymous_121
    {
        MAILIMAP_BODY_ERROR = 0,
        MAILIMAP_BODY_1PART = 1,
        MAILIMAP_BODY_MPART = 2,
    }
    enum MAILIMAP_BODY_ERROR = _Anonymous_121.MAILIMAP_BODY_ERROR;
    enum MAILIMAP_BODY_1PART = _Anonymous_121.MAILIMAP_BODY_1PART;
    enum MAILIMAP_BODY_MPART = _Anonymous_121.MAILIMAP_BODY_MPART;
    int mailimap_uid_search_literalplus(mailimap*, const(char)*, mailimap_search_key*, clist**, );
    mailimap_search_key* mailimap_search_key_new_since(mailimap_date*, );
    int mailsession_get_message_by_uid(mailsession*, const(char)*, mailmessage**, );
    struct mailimf_message_id
    {
        char* mid_value;
    }
    int newsnntp_listgroup(newsnntp*, const(char)*, clist**, );
    void mailimap_search_result_free(clist*, );
    mailimf_message_id* mailimf_message_id_new(char*, );
    struct mailimap_body
    {
        int bd_type;
        union _Anonymous_122
        {
            mailimap_body_type_1part* bd_body_1part;
            mailimap_body_type_mpart* bd_body_mpart;
        }
        _Anonymous_122 bd_data;
    }
    mailimap_search_key* mailimap_search_key_new_subject(char*, );
    void mailimf_message_id_free(mailimf_message_id*, );
    void newsnntp_listgroup_free(clist*, );
    mailimap_body* mailimap_body_new(int, mailimap_body_type_1part*, mailimap_body_type_mpart*, );
    mailimap_search_key* mailimap_search_key_new_text(char*, );
    struct mailimf_in_reply_to
    {
        clist* mid_list;
    }
    int mailsession_login_sasl(mailsession*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, const(char)*, );
    int mailimap_select(mailimap*, const(char)*, );
    void mailimap_body_free(mailimap_body*, );
    mailimf_in_reply_to* mailimf_in_reply_to_new(clist*, );
    void mailimf_in_reply_to_free(mailimf_in_reply_to*, );
    __ssize_t __getdelim(char**, size_t*, int, FILE*, );
    int newsnntp_xhdr_single(newsnntp*, const(char)*, uint32_t, clist**, );
    __ssize_t getdelim(char**, size_t*, int, FILE*, );
    mailimap_search_key* mailimap_search_key_new_to(char*, );
    enum _Anonymous_123
    {
        MAILIMAP_BODY_EXTENSION_ERROR = 0,
        MAILIMAP_BODY_EXTENSION_NSTRING = 1,
        MAILIMAP_BODY_EXTENSION_NUMBER = 2,
        MAILIMAP_BODY_EXTENSION_LIST = 3,
    }
    enum MAILIMAP_BODY_EXTENSION_ERROR = _Anonymous_123.MAILIMAP_BODY_EXTENSION_ERROR;
    enum MAILIMAP_BODY_EXTENSION_NSTRING = _Anonymous_123.MAILIMAP_BODY_EXTENSION_NSTRING;
    enum MAILIMAP_BODY_EXTENSION_NUMBER = _Anonymous_123.MAILIMAP_BODY_EXTENSION_NUMBER;
    enum MAILIMAP_BODY_EXTENSION_LIST = _Anonymous_123.MAILIMAP_BODY_EXTENSION_LIST;
    int mailimap_custom_command(mailimap*, const(char)*, );
    struct mailimf_references
    {
        clist* mid_list;
    }
    mailimap_search_key* mailimap_search_key_new_unkeyword(char*, );
    __ssize_t getline(char**, size_t*, FILE*, );
    mailimf_references* mailimf_references_new(clist*, );
    void mailimf_references_free(mailimf_references*, );


    int newsnntp_xhdr_range(newsnntp*, const(char)*, uint32_t, uint32_t, clist**, );
    struct mailmessage_driver
    {
        char* msg_name;
        int function(mailmessage*) msg_initialize;
        void function(mailmessage*) msg_uninitialize;
        void function(mailmessage*) msg_flush;
        void function(mailmessage*) msg_check;
        void function(mailmessage*, char*) msg_fetch_result_free;
        int function(mailmessage*, char**, c_ulong*) msg_fetch;
        int function(mailmessage*, char**, c_ulong*) msg_fetch_header;
        int function(mailmessage*, char**, c_ulong*) msg_fetch_body;
        int function(mailmessage*, c_ulong*) msg_fetch_size;
        int function(mailmessage*, mailmime**) msg_get_bodystructure;
        int function(mailmessage*, mailmime*, char**, c_ulong*) msg_fetch_section;
        int function(mailmessage*, mailmime*, char**, c_ulong*) msg_fetch_section_header;
        int function(mailmessage*, mailmime*, char**, c_ulong*) msg_fetch_section_mime;
        int function(mailmessage*, mailmime*, char**, c_ulong*) msg_fetch_section_body;
        int function(mailmessage*, mailimf_fields**) msg_fetch_envelope;
        int function(mailmessage*, mail_flags**) msg_get_flags;
    }
    int fputs(const(char)*, FILE*, );
    int mailimap_status(mailimap*, const(char)*, mailimap_status_att_list*, mailimap_mailbox_data_status**, );
    struct mailimap_body_extension
    {
        int ext_type;
        union _Anonymous_124
        {
            char* ext_nstring;
            uint32_t ext_number;
            clist* ext_body_extension_list;
        }
        _Anonymous_124 ext_data;
    }
    mailimap_search_key* mailimap_search_key_new_header(char*, char*, );
    int puts(const(char)*, );
    struct mailimf_subject
    {
        char* sbj_value;
    }
    mailimf_subject* mailimf_subject_new(char*, );
    void newsnntp_xhdr_free(clist*, );
    int ungetc(int, FILE*, );
    mailimap_search_key* mailimap_search_key_new_larger(uint32_t, );
    void mailimf_subject_free(mailimf_subject*, );
    mailimap_body_extension* mailimap_body_extension_new(int, char*, uint32_t, clist*, );
    size_t fread(void*, size_t, size_t, FILE*, );
    int mailimap_store(mailimap*, mailimap_set*, mailimap_store_att_flags*, );
    mailimap_search_key* mailimap_search_key_new_not(mailimap_search_key*, );
    struct mailimf_comments
    {
        char* cm_value;
    }
    void mailimap_body_extension_free(mailimap_body_extension*, );
    int newsnntp_xover_single(newsnntp*, uint32_t, newsnntp_xover_resp_item**, );
    size_t fwrite(const(void)*, size_t, size_t, FILE*, );
    mailimf_comments* mailimf_comments_new(char*, );
    mailimap_search_key* mailimap_search_key_new_or(mailimap_search_key*, mailimap_search_key*, );
    void mailimf_comments_free(mailimf_comments*, );
    struct mailimf_keywords
    {
        clist* kw_list;
    }
    mailimap_search_key* mailimap_search_key_new_sentbefore(mailimap_date*, );
    struct mailimap_body_ext_1part
    {
        char* bd_md5;
        mailimap_body_fld_dsp* bd_disposition;
        mailimap_body_fld_lang* bd_language;
        char* bd_loc;
        clist* bd_extension_list;
    }
    int mailimap_uid_store(mailimap*, mailimap_set*, mailimap_store_att_flags*, );
    int newsnntp_xover_range(newsnntp*, uint32_t, uint32_t, clist**, );
    mailimf_keywords* mailimf_keywords_new(clist*, );
    void xover_resp_item_free(newsnntp_xover_resp_item*, );
    size_t fread_unlocked(void*, size_t, size_t, FILE*, );
    void mailimf_keywords_free(mailimf_keywords*, );
    size_t fwrite_unlocked(const(void)*, size_t, size_t, FILE*, );
    mailimap_search_key* mailimap_search_key_new_senton(mailimap_date*, );
    mailimap_body_ext_1part* mailimap_body_ext_1part_new(char*, mailimap_body_fld_dsp*, mailimap_body_fld_lang*, char*, clist*, );
    struct mailimf_return
    {
        mailimf_path* ret_path;
    }
    void newsnntp_xover_resp_list_free(clist*, );
    int fseek(FILE*, c_long, int, );
    mailimap_search_key* mailimap_search_key_new_sentsince(mailimap_date*, );
    mailimf_return* mailimf_return_new(mailimf_path*, );
    void mailimap_body_ext_1part_free(mailimap_body_ext_1part*, );
    int mailimap_subscribe(mailimap*, const(char)*, );
    int newsnntp_authinfo_generic(newsnntp*, const(char)*, const(char)*, );
    c_long ftell(FILE*, );
    void mailimf_return_free(mailimf_return*, );
    mailimap_search_key* mailimap_search_key_new_smaller(uint32_t, );
    void rewind(FILE*, );
    struct mailimf_path
    {
        char* pt_addr_spec;
    }
    mailimap_search_key* mailimap_search_key_new_uid(mailimap_set*, );
    int mailimap_unsubscribe(mailimap*, const(char)*, );
    struct mailimap_body_ext_mpart
    {
        mailimap_body_fld_param* bd_parameter;
        mailimap_body_fld_dsp* bd_disposition;
        mailimap_body_fld_lang* bd_language;
        char* bd_loc;
        clist* bd_extension_list;
    }
    mailimf_path* mailimf_path_new(char*, );
    int fseeko(FILE*, __off_t, int, );
    void mailimf_path_free(mailimf_path*, );
    mailimap_search_key* mailimap_search_key_new_set(mailimap_set*, );
    __off_t ftello(FILE*, );
    mailimap_body_ext_mpart* mailimap_body_ext_mpart_new(mailimap_body_fld_param*, mailimap_body_fld_dsp*, mailimap_body_fld_lang*, char*, clist*, );
    struct mailmessage
    {
        mailsession* msg_session;
        mailmessage_driver* msg_driver;
        uint32_t msg_index;
        char* msg_uid;
        size_t msg_size;
        mailimf_fields* msg_fields;
        mail_flags* msg_flags;
        int msg_resolved;
        mailimf_single_fields msg_single_fields;
        mailmime* msg_mime;
        int msg_cached;
        void* msg_data;
        void* msg_folder;
        void* msg_user_data;
    }
    struct mailimf_optional_field
    {
        char* fld_name;
        char* fld_value;
    }
    mailimap_search_key* mailimap_search_key_new_multiple(clist*, );
    int mailimap_starttls(mailimap*, );
    void mailimap_body_ext_mpart_free(mailimap_body_ext_mpart*, );
    mailimf_optional_field* mailimf_optional_field_new(char*, char*, );
    mailimap_search_key* mailimap_search_key_new_multiple_empty();
    void mailimf_optional_field_free(mailimf_optional_field*, );
    int fgetpos(FILE*, fpos_t*, );
    int fsetpos(FILE*, const(fpos_t)*, );
    mailimap* mailimap_new(size_t, progress_function*, );
    int mailimap_search_key_multiple_add(mailimap_search_key*, mailimap_search_key*, );
    struct mailimap_body_fields
    {
        mailimap_body_fld_param* bd_parameter;
        char* bd_id;
        char* bd_description;
        mailimap_body_fld_enc* bd_encoding;
        uint32_t bd_size;
    }
    void mailimap_free(mailimap*, );
    mailimap_flag_list* mailimap_flag_list_new_empty();
    mailimap_body_fields* mailimap_body_fields_new(mailimap_body_fld_param*, char*, char*, mailimap_body_fld_enc*, uint32_t, );
    void clearerr(FILE*, );
    int feof(FILE*, );
    int ferror(FILE*, );
    int mailimap_send_current_tag(mailimap*, );
    void mailimap_body_fields_free(mailimap_body_fields*, );
    int mailimap_flag_list_add(mailimap_flag_list*, mailimap_flag*, );
    void clearerr_unlocked(FILE*, );
    int feof_unlocked(FILE*, );
    struct mailimf_single_fields
    {
        mailimf_orig_date* fld_orig_date;
        mailimf_from* fld_from;
        mailimf_sender* fld_sender;
        mailimf_reply_to* fld_reply_to;
        mailimf_to* fld_to;
        mailimf_cc* fld_cc;
        mailimf_bcc* fld_bcc;
        mailimf_message_id* fld_message_id;
        mailimf_in_reply_to* fld_in_reply_to;
        mailimf_references* fld_references;
        mailimf_subject* fld_subject;
        mailimf_comments* fld_comments;
        mailimf_keywords* fld_keywords;
    }
    int ferror_unlocked(FILE*, );
    struct mailmessage_tree
    {
        mailmessage_tree* node_parent;
        char* node_msgid;
        time_t node_date;
        mailmessage* node_msg;
        carray* node_children;
        int node_is_reply;
        char* node_base_subject;
    }
    mailimap_flag* mailimap_flag_new_answered();
    char* mailimap_read_line(mailimap*, );
    void perror(const(char)*, );
    struct mailimap_body_fld_dsp
    {
        char* dsp_type;
        mailimap_body_fld_param* dsp_attributes;
    }
    mailimap_flag* mailimap_flag_new_flagged();
    mailimap_body_fld_dsp* mailimap_body_fld_dsp_new(char*, mailimap_body_fld_param*, );
    mailmessage_tree* mailmessage_tree_new(char*, time_t, mailmessage*, );
    mailimap_flag* mailimap_flag_new_deleted();
    int fileno(FILE*, );
    int mailimap_parse_response(mailimap*, mailimap_response**, );
    void mailimap_body_fld_dsp_free(mailimap_body_fld_dsp*, );
    void mailmessage_tree_free(mailmessage_tree*, );
    void mailimf_atom_free(char*, );
    int fileno_unlocked(FILE*, );
    mailimap_flag* mailimap_flag_new_seen();
    enum _Anonymous_125
    {
        MAILIMAP_BODY_FLD_ENC_7BIT = 0,
        MAILIMAP_BODY_FLD_ENC_8BIT = 1,
        MAILIMAP_BODY_FLD_ENC_BINARY = 2,
        MAILIMAP_BODY_FLD_ENC_BASE64 = 3,
        MAILIMAP_BODY_FLD_ENC_QUOTED_PRINTABLE = 4,
        MAILIMAP_BODY_FLD_ENC_OTHER = 5,
    }
    enum MAILIMAP_BODY_FLD_ENC_7BIT = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_7BIT;
    enum MAILIMAP_BODY_FLD_ENC_8BIT = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_8BIT;
    enum MAILIMAP_BODY_FLD_ENC_BINARY = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_BINARY;
    enum MAILIMAP_BODY_FLD_ENC_BASE64 = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_BASE64;
    enum MAILIMAP_BODY_FLD_ENC_QUOTED_PRINTABLE = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_QUOTED_PRINTABLE;
    enum MAILIMAP_BODY_FLD_ENC_OTHER = _Anonymous_125.MAILIMAP_BODY_FLD_ENC_OTHER;
    void mailimf_dot_atom_free(char*, );
    void mailmessage_tree_free_recursive(mailmessage_tree*, );
    void mailimf_dot_atom_text_free(char*, );
    mailimap_flag* mailimap_flag_new_draft();
    struct generic_message_t
    {
        int function(mailmessage*) msg_prefetch;
        void function(generic_message_t*) msg_prefetch_free;
        int msg_fetched;
        char* msg_message;
        size_t msg_length;
        void* msg_data;
    }
    FILE* popen(const(char)*, const(char)*, );
    void mailimf_quoted_string_free(char*, );
    void mailimap_set_progress_callback(mailimap*, mailprogress_function*, mailprogress_function*, void*, );
    void mailimf_word_free(char*, );
    int pclose(FILE*, );
    void mailimf_phrase_free(char*, );
    mailimap_flag* mailimap_flag_new_flag_keyword(char*, );
    void mailimf_unstructured_free(char*, );
    const(char)* maildriver_strerror(int, );
    void mailimf_angle_addr_free(char*, );
    char* ctermid(char*, );
    void* libetpan_malloc(size_t, );
    struct mailimap_body_fld_enc
    {
        int enc_type;
        char* enc_value;
    }
    void mailimf_display_name_free(char*, );
    void libetpan_free(void*, );
    void mailimap_set_msg_att_handler(mailimap*, mailimap_msg_att_handler*, void*, );
    mailimap_flag* mailimap_flag_new_flag_extension(char*, );
    void mailimf_addr_spec_free(char*, );
    mailimap_body_fld_enc* mailimap_body_fld_enc_new(int, char*, );
    void mailimf_local_part_free(char*, );
    void mailimap_body_fld_enc_free(mailimap_body_fld_enc*, );
    void mailimf_domain_free(char*, );
    mailimap_status_att_list* mailimap_status_att_list_new_empty();
    void mailimf_domain_literal_free(char*, );
    enum _Anonymous_126
    {
        MAILIMAP_BODY_FLD_LANG_ERROR = 0,
        MAILIMAP_BODY_FLD_LANG_SINGLE = 1,
        MAILIMAP_BODY_FLD_LANG_LIST = 2,
    }
    enum MAILIMAP_BODY_FLD_LANG_ERROR = _Anonymous_126.MAILIMAP_BODY_FLD_LANG_ERROR;
    enum MAILIMAP_BODY_FLD_LANG_SINGLE = _Anonymous_126.MAILIMAP_BODY_FLD_LANG_SINGLE;
    enum MAILIMAP_BODY_FLD_LANG_LIST = _Anonymous_126.MAILIMAP_BODY_FLD_LANG_LIST;
    void mailimf_msg_id_free(char*, );
    void mailimf_id_left_free(char*, );
    int mailimap_status_att_list_add(mailimap_status_att_list*, int, );
    void mailimap_set_msg_body_handler(mailimap*, mailimap_msg_body_handler*, void*, );
    void mailimf_id_right_free(char*, );
    void mailimf_no_fold_quote_free(char*, );
    void flockfile(FILE*, );
    int mailimap_get_section_part_from_body(mailimap_body*, mailimap_body*, mailimap_section_part**, );
    void mailimf_no_fold_literal_free(char*, );
    int ftrylockfile(FILE*, );
    void mailimf_field_name_free(char*, );
    void funlockfile(FILE*, );
    void mailimap_set_timeout(mailimap*, time_t, );
    struct mailimap_body_fld_lang
    {
        int lg_type;
        union _Anonymous_127
        {
            char* lg_single;
            clist* lg_list;
        }
        _Anonymous_127 lg_data;
    }
    enum _Anonymous_128
    {
        MAILIMF_NO_ERROR = 0,
        MAILIMF_ERROR_PARSE = 1,
        MAILIMF_ERROR_MEMORY = 2,
        MAILIMF_ERROR_INVAL = 3,
        MAILIMF_ERROR_FILE = 4,
    }
    enum MAILIMF_NO_ERROR = _Anonymous_128.MAILIMF_NO_ERROR;
    enum MAILIMF_ERROR_PARSE = _Anonymous_128.MAILIMF_ERROR_PARSE;
    enum MAILIMF_ERROR_MEMORY = _Anonymous_128.MAILIMF_ERROR_MEMORY;
    enum MAILIMF_ERROR_INVAL = _Anonymous_128.MAILIMF_ERROR_INVAL;
    enum MAILIMF_ERROR_FILE = _Anonymous_128.MAILIMF_ERROR_FILE;
    time_t mailimap_get_timeout(mailimap*, );
    mailimap_body_fld_lang* mailimap_body_fld_lang_new(int, char*, clist*, );
    void mailimap_body_fld_lang_free(mailimap_body_fld_lang*, );
    void mailimap_set_logger(mailimap*, void function(mailimap*, int, const(char)*, c_ulong, void*), void*, );


    struct mailimap_single_body_fld_param
    {
        char* pa_name;
        char* pa_value;
    }
    int mailimap_is_163_workaround_enabled(mailimap*, );
    void mailimap_set_163_workaround_enabled(mailimap*, int, );
    mailimap_single_body_fld_param* mailimap_single_body_fld_param_new(char*, char*, );


    void mailimap_single_body_fld_param_free(mailimap_single_body_fld_param*, );
    struct mailimap_body_fld_param
    {
        clist* pa_list;
    }
    mailimap_body_fld_param* mailimap_body_fld_param_new(clist*, );
    void mailimap_body_fld_param_free(mailimap_body_fld_param*, );
    int mailimap_is_rambler_workaround_enabled(mailimap*, );
    void mailimap_set_rambler_workaround_enabled(mailimap*, int, );


    enum _Anonymous_129
    {
        MAILIMAP_BODY_TYPE_1PART_ERROR = 0,
        MAILIMAP_BODY_TYPE_1PART_BASIC = 1,
        MAILIMAP_BODY_TYPE_1PART_MSG = 2,
        MAILIMAP_BODY_TYPE_1PART_TEXT = 3,
    }
    enum MAILIMAP_BODY_TYPE_1PART_ERROR = _Anonymous_129.MAILIMAP_BODY_TYPE_1PART_ERROR;
    enum MAILIMAP_BODY_TYPE_1PART_BASIC = _Anonymous_129.MAILIMAP_BODY_TYPE_1PART_BASIC;
    enum MAILIMAP_BODY_TYPE_1PART_MSG = _Anonymous_129.MAILIMAP_BODY_TYPE_1PART_MSG;
    enum MAILIMAP_BODY_TYPE_1PART_TEXT = _Anonymous_129.MAILIMAP_BODY_TYPE_1PART_TEXT;
    int mailimap_is_qip_workaround_enabled(mailimap*, );
    void mailimap_set_qip_workaround_enabled(mailimap*, int, );
    struct mailimap_body_type_1part
    {
        int bd_type;
        union _Anonymous_130
        {
            mailimap_body_type_basic* bd_type_basic;
            mailimap_body_type_msg* bd_type_msg;
            mailimap_body_type_text* bd_type_text;
        }
        _Anonymous_130 bd_data;
        mailimap_body_ext_1part* bd_ext_1part;
    }
    mailimap_body_type_1part* mailimap_body_type_1part_new(int, mailimap_body_type_basic*, mailimap_body_type_msg*, mailimap_body_type_text*, mailimap_body_ext_1part*, );
    void mailimap_body_type_1part_free(mailimap_body_type_1part*, );
    struct mailimap_body_type_basic
    {
        mailimap_media_basic* bd_media_basic;
        mailimap_body_fields* bd_fields;
    }
    mailimap_body_type_basic* mailimap_body_type_basic_new(mailimap_media_basic*, mailimap_body_fields*, );
    void mailimap_body_type_basic_free(mailimap_body_type_basic*, );
    struct mailimap_body_type_mpart
    {
        clist* bd_list;
        char* bd_media_subtype;
        mailimap_body_ext_mpart* bd_ext_mpart;
    }
    mailimap_body_type_mpart* mailimap_body_type_mpart_new(clist*, char*, mailimap_body_ext_mpart*, );
    void mailimap_body_type_mpart_free(mailimap_body_type_mpart*, );
    struct mailimap_body_type_msg
    {
        mailimap_body_fields* bd_fields;
        mailimap_envelope* bd_envelope;
        mailimap_body* bd_body;
        uint32_t bd_lines;
    }
    mailimap_body_type_msg* mailimap_body_type_msg_new(mailimap_body_fields*, mailimap_envelope*, mailimap_body*, uint32_t, );
    void mailimap_body_type_msg_free(mailimap_body_type_msg*, );
    struct mailimap_body_type_text
    {
        char* bd_media_text;
        mailimap_body_fields* bd_fields;
        uint32_t bd_lines;
    }
    mailimap_body_type_text* mailimap_body_type_text_new(char*, mailimap_body_fields*, uint32_t, );
    void mailimap_body_type_text_free(mailimap_body_type_text*, );
    enum _Anonymous_131
    {
        MAILIMAP_CAPABILITY_AUTH_TYPE = 0,
        MAILIMAP_CAPABILITY_NAME = 1,
    }
    enum MAILIMAP_CAPABILITY_AUTH_TYPE = _Anonymous_131.MAILIMAP_CAPABILITY_AUTH_TYPE;
    enum MAILIMAP_CAPABILITY_NAME = _Anonymous_131.MAILIMAP_CAPABILITY_NAME;
    struct mailimap_capability
    {
        int cap_type;
        union _Anonymous_132
        {
            char* cap_auth_type;
            char* cap_name;
        }
        _Anonymous_132 cap_data;
    }
    mailimap_capability* mailimap_capability_new(int, char*, char*, );
    void mailimap_capability_free(mailimap_capability*, );
    struct mailimap_capability_data
    {
        clist* cap_list;
    }
    mailimap_capability_data* mailimap_capability_data_new(clist*, );
    void mailimap_capability_data_free(mailimap_capability_data*, );
    enum _Anonymous_133
    {
        MAILIMAP_CONTINUE_REQ_ERROR = 0,
        MAILIMAP_CONTINUE_REQ_TEXT = 1,
        MAILIMAP_CONTINUE_REQ_BASE64 = 2,
    }
    enum MAILIMAP_CONTINUE_REQ_ERROR = _Anonymous_133.MAILIMAP_CONTINUE_REQ_ERROR;
    enum MAILIMAP_CONTINUE_REQ_TEXT = _Anonymous_133.MAILIMAP_CONTINUE_REQ_TEXT;
    enum MAILIMAP_CONTINUE_REQ_BASE64 = _Anonymous_133.MAILIMAP_CONTINUE_REQ_BASE64;
    struct mailimap_continue_req
    {
        int cr_type;
        union _Anonymous_134
        {
            mailimap_resp_text* cr_text;
            char* cr_base64;
        }
        _Anonymous_134 cr_data;
    }
    mailimap_continue_req* mailimap_continue_req_new(int, mailimap_resp_text*, char*, );
    void mailimap_continue_req_free(mailimap_continue_req*, );
    struct mailimap_date_time
    {
        int dt_day;
        int dt_month;
        int dt_year;
        int dt_hour;
        int dt_min;
        int dt_sec;
        int dt_zone;
    }
    mailimap_date_time* mailimap_date_time_new(int, int, int, int, int, int, int, );
    void mailimap_date_time_free(mailimap_date_time*, );
    struct mailimap_envelope
    {
        char* env_date;
        char* env_subject;
        mailimap_env_from* env_from;
        mailimap_env_sender* env_sender;
        mailimap_env_reply_to* env_reply_to;
        mailimap_env_to* env_to;
        mailimap_env_cc* env_cc;
        mailimap_env_bcc* env_bcc;
        char* env_in_reply_to;
        char* env_message_id;
    }
    mailimap_envelope* mailimap_envelope_new(char*, char*, mailimap_env_from*, mailimap_env_sender*, mailimap_env_reply_to*, mailimap_env_to*, mailimap_env_cc*, mailimap_env_bcc*, char*, char*, );
    void mailimap_envelope_free(mailimap_envelope*, );
    struct mailimap_env_bcc
    {
        clist* bcc_list;
    }
    mailimap_env_bcc* mailimap_env_bcc_new(clist*, );
    void mailimap_env_bcc_free(mailimap_env_bcc*, );
    struct mailimap_env_cc
    {
        clist* cc_list;
    }
    mailimap_env_cc* mailimap_env_cc_new(clist*, );
    void mailimap_env_cc_free(mailimap_env_cc*, );
    struct mailimap_env_from
    {
        clist* frm_list;
    }
    mailimap_env_from* mailimap_env_from_new(clist*, );
    void mailimap_env_from_free(mailimap_env_from*, );
    struct mailimap_env_reply_to
    {
        clist* rt_list;
    }
    mailimap_env_reply_to* mailimap_env_reply_to_new(clist*, );
    void mailimap_env_reply_to_free(mailimap_env_reply_to*, );
    struct mailimap_env_sender
    {
        clist* snd_list;
    }
    mailimap_env_sender* mailimap_env_sender_new(clist*, );
    void mailimap_env_sender_free(mailimap_env_sender*, );
    struct mailimap_env_to
    {
        clist* to_list;
    }
    mailimap_env_to* mailimap_env_to_new(clist*, );
    void mailimap_env_to_free(mailimap_env_to*, );
    enum _Anonymous_135
    {
        MAILIMAP_FLAG_ANSWERED = 0,
        MAILIMAP_FLAG_FLAGGED = 1,
        MAILIMAP_FLAG_DELETED = 2,
        MAILIMAP_FLAG_SEEN = 3,
        MAILIMAP_FLAG_DRAFT = 4,
        MAILIMAP_FLAG_KEYWORD = 5,
        MAILIMAP_FLAG_EXTENSION = 6,
    }
    enum MAILIMAP_FLAG_ANSWERED = _Anonymous_135.MAILIMAP_FLAG_ANSWERED;
    enum MAILIMAP_FLAG_FLAGGED = _Anonymous_135.MAILIMAP_FLAG_FLAGGED;
    enum MAILIMAP_FLAG_DELETED = _Anonymous_135.MAILIMAP_FLAG_DELETED;
    enum MAILIMAP_FLAG_SEEN = _Anonymous_135.MAILIMAP_FLAG_SEEN;
    enum MAILIMAP_FLAG_DRAFT = _Anonymous_135.MAILIMAP_FLAG_DRAFT;
    enum MAILIMAP_FLAG_KEYWORD = _Anonymous_135.MAILIMAP_FLAG_KEYWORD;
    enum MAILIMAP_FLAG_EXTENSION = _Anonymous_135.MAILIMAP_FLAG_EXTENSION;
    struct mailimap_flag
    {
        int fl_type;
        union _Anonymous_136
        {
            char* fl_keyword;
            char* fl_extension;
        }
        _Anonymous_136 fl_data;
    }
    mailimap_flag* mailimap_flag_new(int, char*, char*, );
    void mailimap_flag_free(mailimap_flag*, );
    enum _Anonymous_137
    {
        MAILIMAP_FLAG_FETCH_ERROR = 0,
        MAILIMAP_FLAG_FETCH_RECENT = 1,
        MAILIMAP_FLAG_FETCH_OTHER = 2,
    }
    enum MAILIMAP_FLAG_FETCH_ERROR = _Anonymous_137.MAILIMAP_FLAG_FETCH_ERROR;
    enum MAILIMAP_FLAG_FETCH_RECENT = _Anonymous_137.MAILIMAP_FLAG_FETCH_RECENT;
    enum MAILIMAP_FLAG_FETCH_OTHER = _Anonymous_137.MAILIMAP_FLAG_FETCH_OTHER;
    struct mailimap_flag_fetch
    {
        int fl_type;
        mailimap_flag* fl_flag;
    }
    mailimap_flag_fetch* mailimap_flag_fetch_new(int, mailimap_flag*, );
    void mailimap_flag_fetch_free(mailimap_flag_fetch*, );
    enum _Anonymous_138
    {
        MAILIMAP_FLAG_PERM_ERROR = 0,
        MAILIMAP_FLAG_PERM_FLAG = 1,
        MAILIMAP_FLAG_PERM_ALL = 2,
    }
    enum MAILIMAP_FLAG_PERM_ERROR = _Anonymous_138.MAILIMAP_FLAG_PERM_ERROR;
    enum MAILIMAP_FLAG_PERM_FLAG = _Anonymous_138.MAILIMAP_FLAG_PERM_FLAG;
    enum MAILIMAP_FLAG_PERM_ALL = _Anonymous_138.MAILIMAP_FLAG_PERM_ALL;
    struct mailimap_flag_perm
    {
        int fl_type;
        mailimap_flag* fl_flag;
    }
    mailimap_flag_perm* mailimap_flag_perm_new(int, mailimap_flag*, );
    void mailimap_flag_perm_free(mailimap_flag_perm*, );
    struct mailimap_flag_list
    {
        clist* fl_list;
    }
    mailimap_flag_list* mailimap_flag_list_new(clist*, );
    void mailimap_flag_list_free(mailimap_flag_list*, );
    enum _Anonymous_139
    {
        MAILIMAP_GREETING_RESP_COND_ERROR = 0,
        MAILIMAP_GREETING_RESP_COND_AUTH = 1,
        MAILIMAP_GREETING_RESP_COND_BYE = 2,
    }
    enum MAILIMAP_GREETING_RESP_COND_ERROR = _Anonymous_139.MAILIMAP_GREETING_RESP_COND_ERROR;
    enum MAILIMAP_GREETING_RESP_COND_AUTH = _Anonymous_139.MAILIMAP_GREETING_RESP_COND_AUTH;
    enum MAILIMAP_GREETING_RESP_COND_BYE = _Anonymous_139.MAILIMAP_GREETING_RESP_COND_BYE;
    struct mailimap_greeting
    {
        int gr_type;
        union _Anonymous_140
        {
            mailimap_resp_cond_auth* gr_auth;
            mailimap_resp_cond_bye* gr_bye;
        }
        _Anonymous_140 gr_data;
    }
    mailimap_greeting* mailimap_greeting_new(int, mailimap_resp_cond_auth*, mailimap_resp_cond_bye*, );
    void mailimap_greeting_free(mailimap_greeting*, );
    struct mailimap_header_list
    {
        clist* hdr_list;
    }
    mailimap_header_list* mailimap_header_list_new(clist*, );
    void mailimap_header_list_free(mailimap_header_list*, );
    enum _Anonymous_141
    {
        MAILIMAP_STATUS_ATT_MESSAGES = 0,
        MAILIMAP_STATUS_ATT_RECENT = 1,
        MAILIMAP_STATUS_ATT_UIDNEXT = 2,
        MAILIMAP_STATUS_ATT_UIDVALIDITY = 3,
        MAILIMAP_STATUS_ATT_UNSEEN = 4,
        MAILIMAP_STATUS_ATT_HIGHESTMODSEQ = 5,
        MAILIMAP_STATUS_ATT_EXTENSION = 6,
    }
    enum MAILIMAP_STATUS_ATT_MESSAGES = _Anonymous_141.MAILIMAP_STATUS_ATT_MESSAGES;
    enum MAILIMAP_STATUS_ATT_RECENT = _Anonymous_141.MAILIMAP_STATUS_ATT_RECENT;
    enum MAILIMAP_STATUS_ATT_UIDNEXT = _Anonymous_141.MAILIMAP_STATUS_ATT_UIDNEXT;
    enum MAILIMAP_STATUS_ATT_UIDVALIDITY = _Anonymous_141.MAILIMAP_STATUS_ATT_UIDVALIDITY;
    enum MAILIMAP_STATUS_ATT_UNSEEN = _Anonymous_141.MAILIMAP_STATUS_ATT_UNSEEN;
    enum MAILIMAP_STATUS_ATT_HIGHESTMODSEQ = _Anonymous_141.MAILIMAP_STATUS_ATT_HIGHESTMODSEQ;
    enum MAILIMAP_STATUS_ATT_EXTENSION = _Anonymous_141.MAILIMAP_STATUS_ATT_EXTENSION;
    struct mailimap_status_info
    {
        int st_att;
        uint32_t st_value;
        mailimap_extension_data* st_ext_data;
    }
    mailimap_status_info* mailimap_status_info_new(int, uint32_t, mailimap_extension_data*, );
    void mailimap_status_info_free(mailimap_status_info*, );
    struct mailimap_mailbox_data_status
    {
        char* st_mailbox;
        clist* st_info_list;
    }
    mailimap_mailbox_data_status* mailimap_mailbox_data_status_new(char*, clist*, );
    void mailimap_mailbox_data_status_free(mailimap_mailbox_data_status*, );
    enum _Anonymous_142
    {
        MAILIMAP_MAILBOX_DATA_ERROR = 0,
        MAILIMAP_MAILBOX_DATA_FLAGS = 1,
        MAILIMAP_MAILBOX_DATA_LIST = 2,
        MAILIMAP_MAILBOX_DATA_LSUB = 3,
        MAILIMAP_MAILBOX_DATA_SEARCH = 4,
        MAILIMAP_MAILBOX_DATA_STATUS = 5,
        MAILIMAP_MAILBOX_DATA_EXISTS = 6,
        MAILIMAP_MAILBOX_DATA_RECENT = 7,
        MAILIMAP_MAILBOX_DATA_EXTENSION_DATA = 8,
    }
    enum MAILIMAP_MAILBOX_DATA_ERROR = _Anonymous_142.MAILIMAP_MAILBOX_DATA_ERROR;
    enum MAILIMAP_MAILBOX_DATA_FLAGS = _Anonymous_142.MAILIMAP_MAILBOX_DATA_FLAGS;
    enum MAILIMAP_MAILBOX_DATA_LIST = _Anonymous_142.MAILIMAP_MAILBOX_DATA_LIST;
    enum MAILIMAP_MAILBOX_DATA_LSUB = _Anonymous_142.MAILIMAP_MAILBOX_DATA_LSUB;
    enum MAILIMAP_MAILBOX_DATA_SEARCH = _Anonymous_142.MAILIMAP_MAILBOX_DATA_SEARCH;
    enum MAILIMAP_MAILBOX_DATA_STATUS = _Anonymous_142.MAILIMAP_MAILBOX_DATA_STATUS;
    enum MAILIMAP_MAILBOX_DATA_EXISTS = _Anonymous_142.MAILIMAP_MAILBOX_DATA_EXISTS;
    enum MAILIMAP_MAILBOX_DATA_RECENT = _Anonymous_142.MAILIMAP_MAILBOX_DATA_RECENT;
    enum MAILIMAP_MAILBOX_DATA_EXTENSION_DATA = _Anonymous_142.MAILIMAP_MAILBOX_DATA_EXTENSION_DATA;
    struct mailimap_mailbox_data
    {
        int mbd_type;
        union _Anonymous_143
        {
            mailimap_flag_list* mbd_flags;
            mailimap_mailbox_list* mbd_list;
            mailimap_mailbox_list* mbd_lsub;
            clist* mbd_search;
            mailimap_mailbox_data_status* mbd_status;
            uint32_t mbd_exists;
            uint32_t mbd_recent;
            mailimap_extension_data* mbd_extension;
        }
        _Anonymous_143 mbd_data;
    }
    mailimap_mailbox_data* mailimap_mailbox_data_new(int, mailimap_flag_list*, mailimap_mailbox_list*, mailimap_mailbox_list*, clist*, mailimap_mailbox_data_status*, uint32_t, uint32_t, mailimap_extension_data*, );
    void mailimap_mailbox_data_free(mailimap_mailbox_data*, );
    enum _Anonymous_144
    {
        MAILIMAP_MBX_LIST_FLAGS_SFLAG = 0,
        MAILIMAP_MBX_LIST_FLAGS_NO_SFLAG = 1,
    }
    enum MAILIMAP_MBX_LIST_FLAGS_SFLAG = _Anonymous_144.MAILIMAP_MBX_LIST_FLAGS_SFLAG;
    enum MAILIMAP_MBX_LIST_FLAGS_NO_SFLAG = _Anonymous_144.MAILIMAP_MBX_LIST_FLAGS_NO_SFLAG;
    enum _Anonymous_145
    {
        MAILIMAP_MBX_LIST_SFLAG_ERROR = 0,
        MAILIMAP_MBX_LIST_SFLAG_MARKED = 1,
        MAILIMAP_MBX_LIST_SFLAG_NOSELECT = 2,
        MAILIMAP_MBX_LIST_SFLAG_UNMARKED = 3,
    }
    enum MAILIMAP_MBX_LIST_SFLAG_ERROR = _Anonymous_145.MAILIMAP_MBX_LIST_SFLAG_ERROR;
    enum MAILIMAP_MBX_LIST_SFLAG_MARKED = _Anonymous_145.MAILIMAP_MBX_LIST_SFLAG_MARKED;
    enum MAILIMAP_MBX_LIST_SFLAG_NOSELECT = _Anonymous_145.MAILIMAP_MBX_LIST_SFLAG_NOSELECT;
    enum MAILIMAP_MBX_LIST_SFLAG_UNMARKED = _Anonymous_145.MAILIMAP_MBX_LIST_SFLAG_UNMARKED;
    struct mailimap_mbx_list_flags
    {
        int mbf_type;
        clist* mbf_oflags;
        int mbf_sflag;
    }
    mailimap_mbx_list_flags* mailimap_mbx_list_flags_new(int, clist*, int, );
    void mailimap_mbx_list_flags_free(mailimap_mbx_list_flags*, );
    enum _Anonymous_146
    {
        MAILIMAP_MBX_LIST_OFLAG_ERROR = 0,
        MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS = 1,
        MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT = 2,
    }
    enum MAILIMAP_MBX_LIST_OFLAG_ERROR = _Anonymous_146.MAILIMAP_MBX_LIST_OFLAG_ERROR;
    enum MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS = _Anonymous_146.MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS;
    enum MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT = _Anonymous_146.MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT;
    struct mailimap_mbx_list_oflag
    {
        int of_type;
        char* of_flag_ext;
    }
    mailimap_mbx_list_oflag* mailimap_mbx_list_oflag_new(int, char*, );
    void mailimap_mbx_list_oflag_free(mailimap_mbx_list_oflag*, );
    struct mailimap_mailbox_list
    {
        mailimap_mbx_list_flags* mb_flag;
        char mb_delimiter;
        char* mb_name;
    }
    mailimap_mailbox_list* mailimap_mailbox_list_new(mailimap_mbx_list_flags*, char, char*, );
    void mailimap_mailbox_list_free(mailimap_mailbox_list*, );
    enum _Anonymous_147
    {
        MAILIMAP_MEDIA_BASIC_APPLICATION = 0,
        MAILIMAP_MEDIA_BASIC_AUDIO = 1,
        MAILIMAP_MEDIA_BASIC_IMAGE = 2,
        MAILIMAP_MEDIA_BASIC_MESSAGE = 3,
        MAILIMAP_MEDIA_BASIC_VIDEO = 4,
        MAILIMAP_MEDIA_BASIC_OTHER = 5,
    }
    enum MAILIMAP_MEDIA_BASIC_APPLICATION = _Anonymous_147.MAILIMAP_MEDIA_BASIC_APPLICATION;
    enum MAILIMAP_MEDIA_BASIC_AUDIO = _Anonymous_147.MAILIMAP_MEDIA_BASIC_AUDIO;
    enum MAILIMAP_MEDIA_BASIC_IMAGE = _Anonymous_147.MAILIMAP_MEDIA_BASIC_IMAGE;
    enum MAILIMAP_MEDIA_BASIC_MESSAGE = _Anonymous_147.MAILIMAP_MEDIA_BASIC_MESSAGE;
    enum MAILIMAP_MEDIA_BASIC_VIDEO = _Anonymous_147.MAILIMAP_MEDIA_BASIC_VIDEO;
    enum MAILIMAP_MEDIA_BASIC_OTHER = _Anonymous_147.MAILIMAP_MEDIA_BASIC_OTHER;
    struct mailimap_media_basic
    {
        int med_type;
        char* med_basic_type;
        char* med_subtype;
    }
    mailimap_media_basic* mailimap_media_basic_new(int, char*, char*, );
    void mailimap_media_basic_free(mailimap_media_basic*, );
    enum _Anonymous_148
    {
        MAILIMAP_MESSAGE_DATA_ERROR = 0,
        MAILIMAP_MESSAGE_DATA_EXPUNGE = 1,
        MAILIMAP_MESSAGE_DATA_FETCH = 2,
    }
    enum MAILIMAP_MESSAGE_DATA_ERROR = _Anonymous_148.MAILIMAP_MESSAGE_DATA_ERROR;
    enum MAILIMAP_MESSAGE_DATA_EXPUNGE = _Anonymous_148.MAILIMAP_MESSAGE_DATA_EXPUNGE;
    enum MAILIMAP_MESSAGE_DATA_FETCH = _Anonymous_148.MAILIMAP_MESSAGE_DATA_FETCH;
    struct mailimap_message_data
    {
        uint32_t mdt_number;
        int mdt_type;
        mailimap_msg_att* mdt_msg_att;
    }
    mailimap_message_data* mailimap_message_data_new(uint32_t, int, mailimap_msg_att*, );
    void mailimap_message_data_free(mailimap_message_data*, );
    enum _Anonymous_149
    {
        MAILIMAP_MSG_ATT_ITEM_ERROR = 0,
        MAILIMAP_MSG_ATT_ITEM_DYNAMIC = 1,
        MAILIMAP_MSG_ATT_ITEM_STATIC = 2,
        MAILIMAP_MSG_ATT_ITEM_EXTENSION = 3,
    }
    enum MAILIMAP_MSG_ATT_ITEM_ERROR = _Anonymous_149.MAILIMAP_MSG_ATT_ITEM_ERROR;
    enum MAILIMAP_MSG_ATT_ITEM_DYNAMIC = _Anonymous_149.MAILIMAP_MSG_ATT_ITEM_DYNAMIC;
    enum MAILIMAP_MSG_ATT_ITEM_STATIC = _Anonymous_149.MAILIMAP_MSG_ATT_ITEM_STATIC;
    enum MAILIMAP_MSG_ATT_ITEM_EXTENSION = _Anonymous_149.MAILIMAP_MSG_ATT_ITEM_EXTENSION;
    struct mailimap_msg_att_item
    {
        int att_type;
        union _Anonymous_150
        {
            mailimap_msg_att_dynamic* att_dyn;
            mailimap_msg_att_static* att_static;
            mailimap_extension_data* att_extension_data;
        }
        _Anonymous_150 att_data;
    }
    mailimap_msg_att_item* mailimap_msg_att_item_new(int, mailimap_msg_att_dynamic*, mailimap_msg_att_static*, mailimap_extension_data*, );
    void mailimap_msg_att_item_free(mailimap_msg_att_item*, );
    struct mailimap_msg_att
    {
        clist* att_list;
        uint32_t att_number;
    }
    mailimap_msg_att* mailimap_msg_att_new(clist*, );
    void mailimap_msg_att_free(mailimap_msg_att*, );
    struct mailimap_msg_att_dynamic
    {
        clist* att_list;
    }
    mailimap_msg_att_dynamic* mailimap_msg_att_dynamic_new(clist*, );
    void mailimap_msg_att_dynamic_free(mailimap_msg_att_dynamic*, );
    struct mailimap_msg_att_body_section
    {
        mailimap_section* sec_section;
        uint32_t sec_origin_octet;
        char* sec_body_part;
        size_t sec_length;
    }
    mailimap_msg_att_body_section* mailimap_msg_att_body_section_new(mailimap_section*, uint32_t, char*, size_t, );
    void mailimap_msg_att_body_section_free(mailimap_msg_att_body_section*, );
    enum _Anonymous_151
    {
        MAILIMAP_MSG_ATT_ERROR = 0,
        MAILIMAP_MSG_ATT_ENVELOPE = 1,
        MAILIMAP_MSG_ATT_INTERNALDATE = 2,
        MAILIMAP_MSG_ATT_RFC822 = 3,
        MAILIMAP_MSG_ATT_RFC822_HEADER = 4,
        MAILIMAP_MSG_ATT_RFC822_TEXT = 5,
        MAILIMAP_MSG_ATT_RFC822_SIZE = 6,
        MAILIMAP_MSG_ATT_BODY = 7,
        MAILIMAP_MSG_ATT_BODYSTRUCTURE = 8,
        MAILIMAP_MSG_ATT_BODY_SECTION = 9,
        MAILIMAP_MSG_ATT_UID = 10,
    }
    enum MAILIMAP_MSG_ATT_ERROR = _Anonymous_151.MAILIMAP_MSG_ATT_ERROR;
    enum MAILIMAP_MSG_ATT_ENVELOPE = _Anonymous_151.MAILIMAP_MSG_ATT_ENVELOPE;
    enum MAILIMAP_MSG_ATT_INTERNALDATE = _Anonymous_151.MAILIMAP_MSG_ATT_INTERNALDATE;
    enum MAILIMAP_MSG_ATT_RFC822 = _Anonymous_151.MAILIMAP_MSG_ATT_RFC822;
    enum MAILIMAP_MSG_ATT_RFC822_HEADER = _Anonymous_151.MAILIMAP_MSG_ATT_RFC822_HEADER;
    enum MAILIMAP_MSG_ATT_RFC822_TEXT = _Anonymous_151.MAILIMAP_MSG_ATT_RFC822_TEXT;
    enum MAILIMAP_MSG_ATT_RFC822_SIZE = _Anonymous_151.MAILIMAP_MSG_ATT_RFC822_SIZE;
    enum MAILIMAP_MSG_ATT_BODY = _Anonymous_151.MAILIMAP_MSG_ATT_BODY;
    enum MAILIMAP_MSG_ATT_BODYSTRUCTURE = _Anonymous_151.MAILIMAP_MSG_ATT_BODYSTRUCTURE;
    enum MAILIMAP_MSG_ATT_BODY_SECTION = _Anonymous_151.MAILIMAP_MSG_ATT_BODY_SECTION;
    enum MAILIMAP_MSG_ATT_UID = _Anonymous_151.MAILIMAP_MSG_ATT_UID;
    struct mailimap_msg_att_static
    {
        int att_type;
        union _Anonymous_152
        {
            mailimap_envelope* att_env;
            mailimap_date_time* att_internal_date;
            struct _Anonymous_153
            {
                char* att_content;
                size_t att_length;
            }
            _Anonymous_153 att_rfc822;
            struct _Anonymous_154
            {
                char* att_content;
                size_t att_length;
            }
            _Anonymous_154 att_rfc822_header;
            struct _Anonymous_155
            {
                char* att_content;
                size_t att_length;
            }
            _Anonymous_155 att_rfc822_text;
            uint32_t att_rfc822_size;
            mailimap_body* att_bodystructure;
            mailimap_body* att_body;
            mailimap_msg_att_body_section* att_body_section;
            uint32_t att_uid;
        }
        _Anonymous_152 att_data;
    }
    mailimap_msg_att_static* mailimap_msg_att_static_new(int, mailimap_envelope*, mailimap_date_time*, char*, char*, char*, size_t, uint32_t, mailimap_body*, mailimap_body*, mailimap_msg_att_body_section*, uint32_t, );
    void mailimap_msg_att_static_free(mailimap_msg_att_static*, );
    enum _Anonymous_156
    {
        MAILIMAP_RESP_ERROR = 0,
        MAILIMAP_RESP_CONT_REQ = 1,
        MAILIMAP_RESP_RESP_DATA = 2,
    }
    enum MAILIMAP_RESP_ERROR = _Anonymous_156.MAILIMAP_RESP_ERROR;
    enum MAILIMAP_RESP_CONT_REQ = _Anonymous_156.MAILIMAP_RESP_CONT_REQ;
    enum MAILIMAP_RESP_RESP_DATA = _Anonymous_156.MAILIMAP_RESP_RESP_DATA;
    struct mailimap_cont_req_or_resp_data
    {
        int rsp_type;
        union _Anonymous_157
        {
            mailimap_continue_req* rsp_cont_req;
            mailimap_response_data* rsp_resp_data;
        }
        _Anonymous_157 rsp_data;
    }
    mailimap_cont_req_or_resp_data* mailimap_cont_req_or_resp_data_new(int, mailimap_continue_req*, mailimap_response_data*, );
    void mailimap_cont_req_or_resp_data_free(mailimap_cont_req_or_resp_data*, );
    struct mailimap_response
    {
        clist* rsp_cont_req_or_resp_data_list;
        mailimap_response_done* rsp_resp_done;
    }
    mailimap_response* mailimap_response_new(clist*, mailimap_response_done*, );
    void mailimap_response_free(mailimap_response*, );
    enum _Anonymous_158
    {
        MAILIMAP_RESP_DATA_TYPE_ERROR = 0,
        MAILIMAP_RESP_DATA_TYPE_COND_STATE = 1,
        MAILIMAP_RESP_DATA_TYPE_COND_BYE = 2,
        MAILIMAP_RESP_DATA_TYPE_MAILBOX_DATA = 3,
        MAILIMAP_RESP_DATA_TYPE_MESSAGE_DATA = 4,
        MAILIMAP_RESP_DATA_TYPE_CAPABILITY_DATA = 5,
        MAILIMAP_RESP_DATA_TYPE_EXTENSION_DATA = 6,
    }
    enum MAILIMAP_RESP_DATA_TYPE_ERROR = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_ERROR;
    enum MAILIMAP_RESP_DATA_TYPE_COND_STATE = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_COND_STATE;
    enum MAILIMAP_RESP_DATA_TYPE_COND_BYE = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_COND_BYE;
    enum MAILIMAP_RESP_DATA_TYPE_MAILBOX_DATA = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_MAILBOX_DATA;
    enum MAILIMAP_RESP_DATA_TYPE_MESSAGE_DATA = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_MESSAGE_DATA;
    enum MAILIMAP_RESP_DATA_TYPE_CAPABILITY_DATA = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_CAPABILITY_DATA;
    enum MAILIMAP_RESP_DATA_TYPE_EXTENSION_DATA = _Anonymous_158.MAILIMAP_RESP_DATA_TYPE_EXTENSION_DATA;
    struct mailimap_response_data
    {
        int rsp_type;
        union _Anonymous_159
        {
            mailimap_resp_cond_state* rsp_cond_state;
            mailimap_resp_cond_bye* rsp_bye;
            mailimap_mailbox_data* rsp_mailbox_data;
            mailimap_message_data* rsp_message_data;
            mailimap_capability_data* rsp_capability_data;
            mailimap_extension_data* rsp_extension_data;
        }
        _Anonymous_159 rsp_data;
    }
    mailimap_response_data* mailimap_response_data_new(int, mailimap_resp_cond_state*, mailimap_resp_cond_bye*, mailimap_mailbox_data*, mailimap_message_data*, mailimap_capability_data*, mailimap_extension_data*, );
    void mailimap_response_data_free(mailimap_response_data*, );
    enum _Anonymous_160
    {
        MAILIMAP_RESP_DONE_TYPE_ERROR = 0,
        MAILIMAP_RESP_DONE_TYPE_TAGGED = 1,
        MAILIMAP_RESP_DONE_TYPE_FATAL = 2,
    }
    enum MAILIMAP_RESP_DONE_TYPE_ERROR = _Anonymous_160.MAILIMAP_RESP_DONE_TYPE_ERROR;
    enum MAILIMAP_RESP_DONE_TYPE_TAGGED = _Anonymous_160.MAILIMAP_RESP_DONE_TYPE_TAGGED;
    enum MAILIMAP_RESP_DONE_TYPE_FATAL = _Anonymous_160.MAILIMAP_RESP_DONE_TYPE_FATAL;
    struct mailimap_response_done
    {
        int rsp_type;
        union _Anonymous_161
        {
            mailimap_response_tagged* rsp_tagged;
            mailimap_response_fatal* rsp_fatal;
        }
        _Anonymous_161 rsp_data;
    }
    mailimap_response_done* mailimap_response_done_new(int, mailimap_response_tagged*, mailimap_response_fatal*, );
    void mailimap_response_done_free(mailimap_response_done*, );
    struct mailimap_response_fatal
    {
        mailimap_resp_cond_bye* rsp_bye;
    }
    mailimap_response_fatal* mailimap_response_fatal_new(mailimap_resp_cond_bye*, );
    void mailimap_response_fatal_free(mailimap_response_fatal*, );
    struct mailimap_response_tagged
    {
        char* rsp_tag;
        mailimap_resp_cond_state* rsp_cond_state;
    }
    mailimap_response_tagged* mailimap_response_tagged_new(char*, mailimap_resp_cond_state*, );
    void mailimap_response_tagged_free(mailimap_response_tagged*, );
    enum _Anonymous_162
    {
        MAILIMAP_RESP_COND_AUTH_ERROR = 0,
        MAILIMAP_RESP_COND_AUTH_OK = 1,
        MAILIMAP_RESP_COND_AUTH_PREAUTH = 2,
    }
    enum MAILIMAP_RESP_COND_AUTH_ERROR = _Anonymous_162.MAILIMAP_RESP_COND_AUTH_ERROR;
    enum MAILIMAP_RESP_COND_AUTH_OK = _Anonymous_162.MAILIMAP_RESP_COND_AUTH_OK;
    enum MAILIMAP_RESP_COND_AUTH_PREAUTH = _Anonymous_162.MAILIMAP_RESP_COND_AUTH_PREAUTH;
    struct mailimap_resp_cond_auth
    {
        int rsp_type;
        mailimap_resp_text* rsp_text;
    }
    mailimap_resp_cond_auth* mailimap_resp_cond_auth_new(int, mailimap_resp_text*, );
    void mailimap_resp_cond_auth_free(mailimap_resp_cond_auth*, );
    struct mailimap_resp_cond_bye
    {
        mailimap_resp_text* rsp_text;
    }
    mailimap_resp_cond_bye* mailimap_resp_cond_bye_new(mailimap_resp_text*, );
    void mailimap_resp_cond_bye_free(mailimap_resp_cond_bye*, );
    enum _Anonymous_163
    {
        MAILIMAP_RESP_COND_STATE_OK = 0,
        MAILIMAP_RESP_COND_STATE_NO = 1,
        MAILIMAP_RESP_COND_STATE_BAD = 2,
    }
    enum MAILIMAP_RESP_COND_STATE_OK = _Anonymous_163.MAILIMAP_RESP_COND_STATE_OK;
    enum MAILIMAP_RESP_COND_STATE_NO = _Anonymous_163.MAILIMAP_RESP_COND_STATE_NO;
    enum MAILIMAP_RESP_COND_STATE_BAD = _Anonymous_163.MAILIMAP_RESP_COND_STATE_BAD;
    struct mailimap_resp_cond_state
    {
        int rsp_type;
        mailimap_resp_text* rsp_text;
    }
    mailimap_resp_cond_state* mailimap_resp_cond_state_new(int, mailimap_resp_text*, );
    void mailimap_resp_cond_state_free(mailimap_resp_cond_state*, );
    struct mailimap_resp_text
    {
        mailimap_resp_text_code* rsp_code;
        char* rsp_text;
    }
    mailimap_resp_text* mailimap_resp_text_new(mailimap_resp_text_code*, char*, );
    void mailimap_resp_text_free(mailimap_resp_text*, );
    enum _Anonymous_164
    {
        MAILIMAP_RESP_TEXT_CODE_ALERT = 0,
        MAILIMAP_RESP_TEXT_CODE_BADCHARSET = 1,
        MAILIMAP_RESP_TEXT_CODE_CAPABILITY_DATA = 2,
        MAILIMAP_RESP_TEXT_CODE_PARSE = 3,
        MAILIMAP_RESP_TEXT_CODE_PERMANENTFLAGS = 4,
        MAILIMAP_RESP_TEXT_CODE_READ_ONLY = 5,
        MAILIMAP_RESP_TEXT_CODE_READ_WRITE = 6,
        MAILIMAP_RESP_TEXT_CODE_TRY_CREATE = 7,
        MAILIMAP_RESP_TEXT_CODE_UIDNEXT = 8,
        MAILIMAP_RESP_TEXT_CODE_UIDVALIDITY = 9,
        MAILIMAP_RESP_TEXT_CODE_UNSEEN = 10,
        MAILIMAP_RESP_TEXT_CODE_OTHER = 11,
        MAILIMAP_RESP_TEXT_CODE_EXTENSION = 12,
    }
    enum MAILIMAP_RESP_TEXT_CODE_ALERT = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_ALERT;
    enum MAILIMAP_RESP_TEXT_CODE_BADCHARSET = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_BADCHARSET;
    enum MAILIMAP_RESP_TEXT_CODE_CAPABILITY_DATA = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_CAPABILITY_DATA;
    enum MAILIMAP_RESP_TEXT_CODE_PARSE = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_PARSE;
    enum MAILIMAP_RESP_TEXT_CODE_PERMANENTFLAGS = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_PERMANENTFLAGS;
    enum MAILIMAP_RESP_TEXT_CODE_READ_ONLY = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_READ_ONLY;
    enum MAILIMAP_RESP_TEXT_CODE_READ_WRITE = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_READ_WRITE;
    enum MAILIMAP_RESP_TEXT_CODE_TRY_CREATE = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_TRY_CREATE;
    enum MAILIMAP_RESP_TEXT_CODE_UIDNEXT = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_UIDNEXT;
    enum MAILIMAP_RESP_TEXT_CODE_UIDVALIDITY = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_UIDVALIDITY;
    enum MAILIMAP_RESP_TEXT_CODE_UNSEEN = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_UNSEEN;
    enum MAILIMAP_RESP_TEXT_CODE_OTHER = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_OTHER;
    enum MAILIMAP_RESP_TEXT_CODE_EXTENSION = _Anonymous_164.MAILIMAP_RESP_TEXT_CODE_EXTENSION;
    struct mailimap_resp_text_code
    {
        int rc_type;
        union _Anonymous_165
        {
            clist* rc_badcharset;
            mailimap_capability_data* rc_cap_data;
            clist* rc_perm_flags;
            uint32_t rc_uidnext;
            uint32_t rc_uidvalidity;
            uint32_t rc_first_unseen;
            struct _Anonymous_166
            {
                char* atom_name;
                char* atom_value;
            }
            _Anonymous_166 rc_atom;
            mailimap_extension_data* rc_ext_data;
        }
        _Anonymous_165 rc_data;
    }
    mailimap_resp_text_code* mailimap_resp_text_code_new(int, clist*, mailimap_capability_data*, clist*, uint32_t, uint32_t, uint32_t, char*, char*, mailimap_extension_data*, );
    void mailimap_resp_text_code_free(mailimap_resp_text_code*, );
    struct mailimap_section
    {
        mailimap_section_spec* sec_spec;
    }
    mailimap_section* mailimap_section_new(mailimap_section_spec*, );
    void mailimap_section_free(mailimap_section*, );
    enum _Anonymous_167
    {
        MAILIMAP_SECTION_MSGTEXT_HEADER = 0,
        MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS = 1,
        MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS_NOT = 2,
        MAILIMAP_SECTION_MSGTEXT_TEXT = 3,
    }
    enum MAILIMAP_SECTION_MSGTEXT_HEADER = _Anonymous_167.MAILIMAP_SECTION_MSGTEXT_HEADER;
    enum MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS = _Anonymous_167.MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS;
    enum MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS_NOT = _Anonymous_167.MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS_NOT;
    enum MAILIMAP_SECTION_MSGTEXT_TEXT = _Anonymous_167.MAILIMAP_SECTION_MSGTEXT_TEXT;
    struct mailimap_section_msgtext
    {
        int sec_type;
        mailimap_header_list* sec_header_list;
    }
    mailimap_section_msgtext* mailimap_section_msgtext_new(int, mailimap_header_list*, );
    void mailimap_section_msgtext_free(mailimap_section_msgtext*, );
    struct mailimap_section_part
    {
        clist* sec_id;
    }
    mailimap_section_part* mailimap_section_part_new(clist*, );
    void mailimap_section_part_free(mailimap_section_part*, );
    enum _Anonymous_168
    {
        MAILIMAP_SECTION_SPEC_SECTION_MSGTEXT = 0,
        MAILIMAP_SECTION_SPEC_SECTION_PART = 1,
    }
    enum MAILIMAP_SECTION_SPEC_SECTION_MSGTEXT = _Anonymous_168.MAILIMAP_SECTION_SPEC_SECTION_MSGTEXT;
    enum MAILIMAP_SECTION_SPEC_SECTION_PART = _Anonymous_168.MAILIMAP_SECTION_SPEC_SECTION_PART;
    struct mailimap_section_spec
    {
        int sec_type;
        union _Anonymous_169
        {
            mailimap_section_msgtext* sec_msgtext;
            mailimap_section_part* sec_part;
        }
        _Anonymous_169 sec_data;
        mailimap_section_text* sec_text;
    }
    mailimap_section_spec* mailimap_section_spec_new(int, mailimap_section_msgtext*, mailimap_section_part*, mailimap_section_text*, );
    void mailimap_section_spec_free(mailimap_section_spec*, );
    enum _Anonymous_170
    {
        MAILIMAP_SECTION_TEXT_ERROR = 0,
        MAILIMAP_SECTION_TEXT_SECTION_MSGTEXT = 1,
        MAILIMAP_SECTION_TEXT_MIME = 2,
    }
    enum MAILIMAP_SECTION_TEXT_ERROR = _Anonymous_170.MAILIMAP_SECTION_TEXT_ERROR;
    enum MAILIMAP_SECTION_TEXT_SECTION_MSGTEXT = _Anonymous_170.MAILIMAP_SECTION_TEXT_SECTION_MSGTEXT;
    enum MAILIMAP_SECTION_TEXT_MIME = _Anonymous_170.MAILIMAP_SECTION_TEXT_MIME;
    struct mailimap_section_text
    {
        int sec_type;
        mailimap_section_msgtext* sec_msgtext;
    }
    mailimap_section_text* mailimap_section_text_new(int, mailimap_section_msgtext*, );
    void mailimap_section_text_free(mailimap_section_text*, );
    struct mailimap_set_item
    {
        uint32_t set_first;
        uint32_t set_last;
    }
    mailimap_set_item* mailimap_set_item_new(uint32_t, uint32_t, );
    void mailimap_set_item_free(mailimap_set_item*, );
    struct mailimap_set
    {
        clist* set_list;
    }
    mailimap_set* mailimap_set_new(clist*, );
    void mailimap_set_free(mailimap_set*, );
    struct mailimap_date
    {
        int dt_day;
        int dt_month;
        int dt_year;
    }
    mailimap_date* mailimap_date_new(int, int, int, );
    void mailimap_date_free(mailimap_date*, );
    enum _Anonymous_171
    {
        MAILIMAP_FETCH_ATT_ENVELOPE = 0,
        MAILIMAP_FETCH_ATT_FLAGS = 1,
        MAILIMAP_FETCH_ATT_INTERNALDATE = 2,
        MAILIMAP_FETCH_ATT_RFC822 = 3,
        MAILIMAP_FETCH_ATT_RFC822_HEADER = 4,
        MAILIMAP_FETCH_ATT_RFC822_SIZE = 5,
        MAILIMAP_FETCH_ATT_RFC822_TEXT = 6,
        MAILIMAP_FETCH_ATT_BODY = 7,
        MAILIMAP_FETCH_ATT_BODYSTRUCTURE = 8,
        MAILIMAP_FETCH_ATT_UID = 9,
        MAILIMAP_FETCH_ATT_BODY_SECTION = 10,
        MAILIMAP_FETCH_ATT_BODY_PEEK_SECTION = 11,
        MAILIMAP_FETCH_ATT_EXTENSION = 12,
    }
    enum MAILIMAP_FETCH_ATT_ENVELOPE = _Anonymous_171.MAILIMAP_FETCH_ATT_ENVELOPE;
    enum MAILIMAP_FETCH_ATT_FLAGS = _Anonymous_171.MAILIMAP_FETCH_ATT_FLAGS;
    enum MAILIMAP_FETCH_ATT_INTERNALDATE = _Anonymous_171.MAILIMAP_FETCH_ATT_INTERNALDATE;
    enum MAILIMAP_FETCH_ATT_RFC822 = _Anonymous_171.MAILIMAP_FETCH_ATT_RFC822;
    enum MAILIMAP_FETCH_ATT_RFC822_HEADER = _Anonymous_171.MAILIMAP_FETCH_ATT_RFC822_HEADER;
    enum MAILIMAP_FETCH_ATT_RFC822_SIZE = _Anonymous_171.MAILIMAP_FETCH_ATT_RFC822_SIZE;
    enum MAILIMAP_FETCH_ATT_RFC822_TEXT = _Anonymous_171.MAILIMAP_FETCH_ATT_RFC822_TEXT;
    enum MAILIMAP_FETCH_ATT_BODY = _Anonymous_171.MAILIMAP_FETCH_ATT_BODY;
    enum MAILIMAP_FETCH_ATT_BODYSTRUCTURE = _Anonymous_171.MAILIMAP_FETCH_ATT_BODYSTRUCTURE;
    enum MAILIMAP_FETCH_ATT_UID = _Anonymous_171.MAILIMAP_FETCH_ATT_UID;
    enum MAILIMAP_FETCH_ATT_BODY_SECTION = _Anonymous_171.MAILIMAP_FETCH_ATT_BODY_SECTION;
    enum MAILIMAP_FETCH_ATT_BODY_PEEK_SECTION = _Anonymous_171.MAILIMAP_FETCH_ATT_BODY_PEEK_SECTION;
    enum MAILIMAP_FETCH_ATT_EXTENSION = _Anonymous_171.MAILIMAP_FETCH_ATT_EXTENSION;
    struct mailimap_fetch_att
    {
        int att_type;
        mailimap_section* att_section;
        uint32_t att_offset;
        uint32_t att_size;
        char* att_extension;
    }
    mailimap_fetch_att* mailimap_fetch_att_new(int, mailimap_section*, uint32_t, uint32_t, char*, );
    void mailimap_fetch_att_free(mailimap_fetch_att*, );
    enum _Anonymous_172
    {
        MAILIMAP_FETCH_TYPE_ALL = 0,
        MAILIMAP_FETCH_TYPE_FULL = 1,
        MAILIMAP_FETCH_TYPE_FAST = 2,
        MAILIMAP_FETCH_TYPE_FETCH_ATT = 3,
        MAILIMAP_FETCH_TYPE_FETCH_ATT_LIST = 4,
    }
    enum MAILIMAP_FETCH_TYPE_ALL = _Anonymous_172.MAILIMAP_FETCH_TYPE_ALL;
    enum MAILIMAP_FETCH_TYPE_FULL = _Anonymous_172.MAILIMAP_FETCH_TYPE_FULL;
    enum MAILIMAP_FETCH_TYPE_FAST = _Anonymous_172.MAILIMAP_FETCH_TYPE_FAST;
    enum MAILIMAP_FETCH_TYPE_FETCH_ATT = _Anonymous_172.MAILIMAP_FETCH_TYPE_FETCH_ATT;
    enum MAILIMAP_FETCH_TYPE_FETCH_ATT_LIST = _Anonymous_172.MAILIMAP_FETCH_TYPE_FETCH_ATT_LIST;
    struct mailimap_fetch_type
    {
        int ft_type;
        union _Anonymous_173
        {
            mailimap_fetch_att* ft_fetch_att;
            clist* ft_fetch_att_list;
        }
        _Anonymous_173 ft_data;
    }
    mailimap_fetch_type* mailimap_fetch_type_new(int, mailimap_fetch_att*, clist*, );
    void mailimap_fetch_type_free(mailimap_fetch_type*, );
    struct mailimap_store_att_flags
    {
        int fl_sign;
        int fl_silent;
        mailimap_flag_list* fl_flag_list;
    }
    mailimap_store_att_flags* mailimap_store_att_flags_new(int, int, mailimap_flag_list*, );
    void mailimap_store_att_flags_free(mailimap_store_att_flags*, );
    enum _Anonymous_174
    {
        MAILIMAP_SEARCH_KEY_ALL = 0,
        MAILIMAP_SEARCH_KEY_ANSWERED = 1,
        MAILIMAP_SEARCH_KEY_BCC = 2,
        MAILIMAP_SEARCH_KEY_BEFORE = 3,
        MAILIMAP_SEARCH_KEY_BODY = 4,
        MAILIMAP_SEARCH_KEY_CC = 5,
        MAILIMAP_SEARCH_KEY_DELETED = 6,
        MAILIMAP_SEARCH_KEY_FLAGGED = 7,
        MAILIMAP_SEARCH_KEY_FROM = 8,
        MAILIMAP_SEARCH_KEY_KEYWORD = 9,
        MAILIMAP_SEARCH_KEY_NEW = 10,
        MAILIMAP_SEARCH_KEY_OLD = 11,
        MAILIMAP_SEARCH_KEY_ON = 12,
        MAILIMAP_SEARCH_KEY_RECENT = 13,
        MAILIMAP_SEARCH_KEY_SEEN = 14,
        MAILIMAP_SEARCH_KEY_SINCE = 15,
        MAILIMAP_SEARCH_KEY_SUBJECT = 16,
        MAILIMAP_SEARCH_KEY_TEXT = 17,
        MAILIMAP_SEARCH_KEY_TO = 18,
        MAILIMAP_SEARCH_KEY_UNANSWERED = 19,
        MAILIMAP_SEARCH_KEY_UNDELETED = 20,
        MAILIMAP_SEARCH_KEY_UNFLAGGED = 21,
        MAILIMAP_SEARCH_KEY_UNKEYWORD = 22,
        MAILIMAP_SEARCH_KEY_UNSEEN = 23,
        MAILIMAP_SEARCH_KEY_DRAFT = 24,
        MAILIMAP_SEARCH_KEY_HEADER = 25,
        MAILIMAP_SEARCH_KEY_LARGER = 26,
        MAILIMAP_SEARCH_KEY_NOT = 27,
        MAILIMAP_SEARCH_KEY_OR = 28,
        MAILIMAP_SEARCH_KEY_SENTBEFORE = 29,
        MAILIMAP_SEARCH_KEY_SENTON = 30,
        MAILIMAP_SEARCH_KEY_SENTSINCE = 31,
        MAILIMAP_SEARCH_KEY_SMALLER = 32,
        MAILIMAP_SEARCH_KEY_UID = 33,
        MAILIMAP_SEARCH_KEY_UNDRAFT = 34,
        MAILIMAP_SEARCH_KEY_SET = 35,
        MAILIMAP_SEARCH_KEY_MULTIPLE = 36,
        MAILIMAP_SEARCH_KEY_MODSEQ = 37,
        MAILIMAP_SEARCH_KEY_XGMTHRID = 38,
        MAILIMAP_SEARCH_KEY_XGMMSGID = 39,
        MAILIMAP_SEARCH_KEY_XGMRAW = 40,
    }
    enum MAILIMAP_SEARCH_KEY_ALL = _Anonymous_174.MAILIMAP_SEARCH_KEY_ALL;
    enum MAILIMAP_SEARCH_KEY_ANSWERED = _Anonymous_174.MAILIMAP_SEARCH_KEY_ANSWERED;
    enum MAILIMAP_SEARCH_KEY_BCC = _Anonymous_174.MAILIMAP_SEARCH_KEY_BCC;
    enum MAILIMAP_SEARCH_KEY_BEFORE = _Anonymous_174.MAILIMAP_SEARCH_KEY_BEFORE;
    enum MAILIMAP_SEARCH_KEY_BODY = _Anonymous_174.MAILIMAP_SEARCH_KEY_BODY;
    enum MAILIMAP_SEARCH_KEY_CC = _Anonymous_174.MAILIMAP_SEARCH_KEY_CC;
    enum MAILIMAP_SEARCH_KEY_DELETED = _Anonymous_174.MAILIMAP_SEARCH_KEY_DELETED;
    enum MAILIMAP_SEARCH_KEY_FLAGGED = _Anonymous_174.MAILIMAP_SEARCH_KEY_FLAGGED;
    enum MAILIMAP_SEARCH_KEY_FROM = _Anonymous_174.MAILIMAP_SEARCH_KEY_FROM;
    enum MAILIMAP_SEARCH_KEY_KEYWORD = _Anonymous_174.MAILIMAP_SEARCH_KEY_KEYWORD;
    enum MAILIMAP_SEARCH_KEY_NEW = _Anonymous_174.MAILIMAP_SEARCH_KEY_NEW;
    enum MAILIMAP_SEARCH_KEY_OLD = _Anonymous_174.MAILIMAP_SEARCH_KEY_OLD;
    enum MAILIMAP_SEARCH_KEY_ON = _Anonymous_174.MAILIMAP_SEARCH_KEY_ON;
    enum MAILIMAP_SEARCH_KEY_RECENT = _Anonymous_174.MAILIMAP_SEARCH_KEY_RECENT;
    enum MAILIMAP_SEARCH_KEY_SEEN = _Anonymous_174.MAILIMAP_SEARCH_KEY_SEEN;
    enum MAILIMAP_SEARCH_KEY_SINCE = _Anonymous_174.MAILIMAP_SEARCH_KEY_SINCE;
    enum MAILIMAP_SEARCH_KEY_SUBJECT = _Anonymous_174.MAILIMAP_SEARCH_KEY_SUBJECT;
    enum MAILIMAP_SEARCH_KEY_TEXT = _Anonymous_174.MAILIMAP_SEARCH_KEY_TEXT;
    enum MAILIMAP_SEARCH_KEY_TO = _Anonymous_174.MAILIMAP_SEARCH_KEY_TO;
    enum MAILIMAP_SEARCH_KEY_UNANSWERED = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNANSWERED;
    enum MAILIMAP_SEARCH_KEY_UNDELETED = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNDELETED;
    enum MAILIMAP_SEARCH_KEY_UNFLAGGED = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNFLAGGED;
    enum MAILIMAP_SEARCH_KEY_UNKEYWORD = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNKEYWORD;
    enum MAILIMAP_SEARCH_KEY_UNSEEN = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNSEEN;
    enum MAILIMAP_SEARCH_KEY_DRAFT = _Anonymous_174.MAILIMAP_SEARCH_KEY_DRAFT;
    enum MAILIMAP_SEARCH_KEY_HEADER = _Anonymous_174.MAILIMAP_SEARCH_KEY_HEADER;
    enum MAILIMAP_SEARCH_KEY_LARGER = _Anonymous_174.MAILIMAP_SEARCH_KEY_LARGER;
    enum MAILIMAP_SEARCH_KEY_NOT = _Anonymous_174.MAILIMAP_SEARCH_KEY_NOT;
    enum MAILIMAP_SEARCH_KEY_OR = _Anonymous_174.MAILIMAP_SEARCH_KEY_OR;
    enum MAILIMAP_SEARCH_KEY_SENTBEFORE = _Anonymous_174.MAILIMAP_SEARCH_KEY_SENTBEFORE;
    enum MAILIMAP_SEARCH_KEY_SENTON = _Anonymous_174.MAILIMAP_SEARCH_KEY_SENTON;
    enum MAILIMAP_SEARCH_KEY_SENTSINCE = _Anonymous_174.MAILIMAP_SEARCH_KEY_SENTSINCE;
    enum MAILIMAP_SEARCH_KEY_SMALLER = _Anonymous_174.MAILIMAP_SEARCH_KEY_SMALLER;
    enum MAILIMAP_SEARCH_KEY_UID = _Anonymous_174.MAILIMAP_SEARCH_KEY_UID;
    enum MAILIMAP_SEARCH_KEY_UNDRAFT = _Anonymous_174.MAILIMAP_SEARCH_KEY_UNDRAFT;
    enum MAILIMAP_SEARCH_KEY_SET = _Anonymous_174.MAILIMAP_SEARCH_KEY_SET;
    enum MAILIMAP_SEARCH_KEY_MULTIPLE = _Anonymous_174.MAILIMAP_SEARCH_KEY_MULTIPLE;
    enum MAILIMAP_SEARCH_KEY_MODSEQ = _Anonymous_174.MAILIMAP_SEARCH_KEY_MODSEQ;
    enum MAILIMAP_SEARCH_KEY_XGMTHRID = _Anonymous_174.MAILIMAP_SEARCH_KEY_XGMTHRID;
    enum MAILIMAP_SEARCH_KEY_XGMMSGID = _Anonymous_174.MAILIMAP_SEARCH_KEY_XGMMSGID;
    enum MAILIMAP_SEARCH_KEY_XGMRAW = _Anonymous_174.MAILIMAP_SEARCH_KEY_XGMRAW;
    enum _Anonymous_175
    {
        MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_PRIV = 0,
        MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_SHARED = 1,
        MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_ALL = 2,
    }
    enum MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_PRIV = _Anonymous_175.MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_PRIV;
    enum MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_SHARED = _Anonymous_175.MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_SHARED;
    enum MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_ALL = _Anonymous_175.MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_ALL;
    struct mailimap_search_key
    {
        int sk_type;
        union _Anonymous_176
        {
            char* sk_bcc;
            mailimap_date* sk_before;
            char* sk_body;
            char* sk_cc;
            char* sk_from;
            char* sk_keyword;
            mailimap_date* sk_on;
            mailimap_date* sk_since;
            char* sk_subject;
            char* sk_text;
            char* sk_to;
            char* sk_unkeyword;
            struct _Anonymous_177
            {
                char* sk_header_name;
                char* sk_header_value;
            }
            _Anonymous_177 sk_header;
            uint32_t sk_larger;
            mailimap_search_key* sk_not;
            struct _Anonymous_178
            {
                mailimap_search_key* sk_or1;
                mailimap_search_key* sk_or2;
            }
            _Anonymous_178 sk_or;
            mailimap_date* sk_sentbefore;
            mailimap_date* sk_senton;
            mailimap_date* sk_sentsince;
            uint32_t sk_smaller;
            mailimap_set* sk_uid;
            mailimap_set* sk_set;
            uint64_t sk_xgmthrid;
            uint64_t sk_xgmmsgid;
            char* sk_xgmraw;
            clist* sk_multiple;
            struct _Anonymous_179
            {
                mailimap_flag* sk_entry_name;
                int sk_entry_type_req;
                uint64_t sk_modseq_valzer;
            }
            _Anonymous_179 sk_modseq;
        }
        _Anonymous_176 sk_data;
    }
    mailimap_search_key* mailimap_search_key_new(int, char*, mailimap_date*, char*, char*, char*, char*, mailimap_date*, mailimap_date*, char*, char*, char*, char*, char*, char*, uint32_t, mailimap_search_key*, mailimap_search_key*, mailimap_search_key*, mailimap_date*, mailimap_date*, mailimap_date*, uint32_t, mailimap_set*, mailimap_set*, clist*, );
    mailimap_search_key* mailimap_search_key_new_xgmthrid(uint64_t, );
    mailimap_search_key* mailimap_search_key_new_xgmmsgid(uint64_t, );
    mailimap_search_key* mailimap_search_key_new_xgmraw(char*, );
    void mailimap_search_key_free(mailimap_search_key*, );
    struct mailimap_status_att_list
    {
        clist* att_list;
    }
    mailimap_status_att_list* mailimap_status_att_list_new(clist*, );
    void mailimap_status_att_list_free(mailimap_status_att_list*, );
    uint32_t* mailimap_number_alloc_new(uint32_t, );
    void mailimap_number_alloc_free(uint32_t*, );
    void mailimap_addr_host_free(char*, );
    void mailimap_addr_mailbox_free(char*, );
    void mailimap_addr_adl_free(char*, );
    void mailimap_addr_name_free(char*, );
    void mailimap_astring_free(char*, );
    void mailimap_atom_free(char*, );
    void mailimap_auth_type_free(char*, );
    void mailimap_base64_free(char*, );
    void mailimap_body_fld_desc_free(char*, );
    void mailimap_body_fld_id_free(char*, );
    void mailimap_body_fld_md5_free(char*, );
    void mailimap_body_fld_loc_free(char*, );
    void mailimap_env_date_free(char*, );
    void mailimap_env_in_reply_to_free(char*, );
    void mailimap_env_message_id_free(char*, );
    void mailimap_env_subject_free(char*, );
    void mailimap_flag_extension_free(char*, );
    void mailimap_flag_keyword_free(char*, );
    void mailimap_header_fld_name_free(char*, );
    void mailimap_literal_free(char*, );
    void mailimap_mailbox_free(char*, );
    void mailimap_mailbox_data_search_free(clist*, );
    void mailimap_media_subtype_free(char*, );
    void mailimap_media_text_free(char*, );
    void mailimap_msg_att_envelope_free(mailimap_envelope*, );
    void mailimap_msg_att_internaldate_free(mailimap_date_time*, );
    void mailimap_msg_att_rfc822_free(char*, );
    void mailimap_msg_att_rfc822_header_free(char*, );
    void mailimap_msg_att_rfc822_text_free(char*, );
    void mailimap_msg_att_body_free(mailimap_body*, );
    void mailimap_msg_att_bodystructure_free(mailimap_body*, );
    void mailimap_nstring_free(char*, );
    void mailimap_string_free(char*, );
    void mailimap_tag_free(char*, );
    void mailimap_text_free(char*, );
    enum _Anonymous_180
    {
        MAILIMAP_STATE_DISCONNECTED = 0,
        MAILIMAP_STATE_NON_AUTHENTICATED = 1,
        MAILIMAP_STATE_AUTHENTICATED = 2,
        MAILIMAP_STATE_SELECTED = 3,
        MAILIMAP_STATE_LOGOUT = 4,
    }
    enum MAILIMAP_STATE_DISCONNECTED = _Anonymous_180.MAILIMAP_STATE_DISCONNECTED;
    enum MAILIMAP_STATE_NON_AUTHENTICATED = _Anonymous_180.MAILIMAP_STATE_NON_AUTHENTICATED;
    enum MAILIMAP_STATE_AUTHENTICATED = _Anonymous_180.MAILIMAP_STATE_AUTHENTICATED;
    enum MAILIMAP_STATE_SELECTED = _Anonymous_180.MAILIMAP_STATE_SELECTED;
    enum MAILIMAP_STATE_LOGOUT = _Anonymous_180.MAILIMAP_STATE_LOGOUT;
    alias mailimap_msg_att_handler = void function(mailimap_msg_att*, void*);
    alias mailimap_msg_body_handler = _Bool function(int, mailimap_msg_att_body_section*, const(char)*, size_t, void*);
    struct mailimap
    {
        char* imap_response;
        mailstream* imap_stream;
        size_t imap_progr_rate;
        progress_function* imap_progr_fun;
        MMAPString* imap_stream_buffer;
        MMAPString* imap_response_buffer;
        int imap_state;
        int imap_tag;
        mailimap_connection_info* imap_connection_info;
        mailimap_selection_info* imap_selection_info;
        mailimap_response_info* imap_response_info;
        struct _Anonymous_181
        {
            void* sasl_conn;
            const(char)* sasl_server_fqdn;
            const(char)* sasl_login;
            const(char)* sasl_auth_name;
            const(char)* sasl_password;
            const(char)* sasl_realm;
            void* sasl_secret;
        }
        _Anonymous_181 imap_sasl;
        time_t imap_idle_timestamp;
        time_t imap_idle_maxdelay;
        mailprogress_function* imap_body_progress_fun;
        mailprogress_function* imap_items_progress_fun;
        void* imap_progress_context;
        mailimap_msg_att_handler* imap_msg_att_handler;
        void* imap_msg_att_handler_context;
        mailimap_msg_body_handler* imap_msg_body_handler;
        void* imap_msg_body_handler_context;
        time_t imap_timeout;
        void function(mailimap*, int, const(char)*, c_ulong, void*) imap_logger;
        void* imap_logger_context;
        int is_163_workaround_enabled;
        int is_rambler_workaround_enabled;
        int is_qip_workaround_enabled;
    }
    struct mailimap_connection_info
    {
        mailimap_capability_data* imap_capability;
    }
    mailimap_connection_info* mailimap_connection_info_new();
    void mailimap_connection_info_free(mailimap_connection_info*, );
    enum _Anonymous_182
    {
        MAILIMAP_MAILBOX_READONLY = 0,
        MAILIMAP_MAILBOX_READWRITE = 1,
    }
    enum MAILIMAP_MAILBOX_READONLY = _Anonymous_182.MAILIMAP_MAILBOX_READONLY;
    enum MAILIMAP_MAILBOX_READWRITE = _Anonymous_182.MAILIMAP_MAILBOX_READWRITE;
    struct mailimap_selection_info
    {
        clist* sel_perm_flags;
        int sel_perm;
        uint32_t sel_uidnext;
        uint32_t sel_uidvalidity;
        uint32_t sel_first_unseen;
        mailimap_flag_list* sel_flags;
        uint32_t sel_exists;
        uint32_t sel_recent;
        uint32_t sel_unseen;
        uint8_t sel_has_exists;
        uint8_t sel_has_recent;
    }
    mailimap_selection_info* mailimap_selection_info_new();
    void mailimap_selection_info_free(mailimap_selection_info*, );
    struct mailimap_response_info
    {
        char* rsp_alert;
        char* rsp_parse;
        clist* rsp_badcharset;
        int rsp_trycreate;
        clist* rsp_mailbox_list;
        clist* rsp_mailbox_lsub;
        clist* rsp_search_result;
        mailimap_mailbox_data_status* rsp_status;
        clist* rsp_expunged;
        clist* rsp_fetch_list;
        clist* rsp_extension_list;
        char* rsp_atom;
        char* rsp_value;
    }
    mailimap_response_info* mailimap_response_info_new();
    void mailimap_response_info_free(mailimap_response_info*, );
    enum _Anonymous_183
    {
        MAILIMAP_NO_ERROR = 0,
        MAILIMAP_NO_ERROR_AUTHENTICATED = 1,
        MAILIMAP_NO_ERROR_NON_AUTHENTICATED = 2,
        MAILIMAP_ERROR_BAD_STATE = 3,
        MAILIMAP_ERROR_STREAM = 4,
        MAILIMAP_ERROR_PARSE = 5,
        MAILIMAP_ERROR_CONNECTION_REFUSED = 6,
        MAILIMAP_ERROR_MEMORY = 7,
        MAILIMAP_ERROR_FATAL = 8,
        MAILIMAP_ERROR_PROTOCOL = 9,
        MAILIMAP_ERROR_DONT_ACCEPT_CONNECTION = 10,
        MAILIMAP_ERROR_APPEND = 11,
        MAILIMAP_ERROR_NOOP = 12,
        MAILIMAP_ERROR_LOGOUT = 13,
        MAILIMAP_ERROR_CAPABILITY = 14,
        MAILIMAP_ERROR_CHECK = 15,
        MAILIMAP_ERROR_CLOSE = 16,
        MAILIMAP_ERROR_EXPUNGE = 17,
        MAILIMAP_ERROR_COPY = 18,
        MAILIMAP_ERROR_UID_COPY = 19,
        MAILIMAP_ERROR_MOVE = 20,
        MAILIMAP_ERROR_UID_MOVE = 21,
        MAILIMAP_ERROR_CREATE = 22,
        MAILIMAP_ERROR_DELETE = 23,
        MAILIMAP_ERROR_EXAMINE = 24,
        MAILIMAP_ERROR_FETCH = 25,
        MAILIMAP_ERROR_UID_FETCH = 26,
        MAILIMAP_ERROR_LIST = 27,
        MAILIMAP_ERROR_LOGIN = 28,
        MAILIMAP_ERROR_LSUB = 29,
        MAILIMAP_ERROR_RENAME = 30,
        MAILIMAP_ERROR_SEARCH = 31,
        MAILIMAP_ERROR_UID_SEARCH = 32,
        MAILIMAP_ERROR_SELECT = 33,
        MAILIMAP_ERROR_STATUS = 34,
        MAILIMAP_ERROR_STORE = 35,
        MAILIMAP_ERROR_UID_STORE = 36,
        MAILIMAP_ERROR_SUBSCRIBE = 37,
        MAILIMAP_ERROR_UNSUBSCRIBE = 38,
        MAILIMAP_ERROR_STARTTLS = 39,
        MAILIMAP_ERROR_INVAL = 40,
        MAILIMAP_ERROR_EXTENSION = 41,
        MAILIMAP_ERROR_SASL = 42,
        MAILIMAP_ERROR_SSL = 43,
        MAILIMAP_ERROR_NEEDS_MORE_DATA = 44,
        MAILIMAP_ERROR_CUSTOM_COMMAND = 45,
    }
    enum MAILIMAP_NO_ERROR = _Anonymous_183.MAILIMAP_NO_ERROR;
    enum MAILIMAP_NO_ERROR_AUTHENTICATED = _Anonymous_183.MAILIMAP_NO_ERROR_AUTHENTICATED;
    enum MAILIMAP_NO_ERROR_NON_AUTHENTICATED = _Anonymous_183.MAILIMAP_NO_ERROR_NON_AUTHENTICATED;
    enum MAILIMAP_ERROR_BAD_STATE = _Anonymous_183.MAILIMAP_ERROR_BAD_STATE;
    enum MAILIMAP_ERROR_STREAM = _Anonymous_183.MAILIMAP_ERROR_STREAM;
    enum MAILIMAP_ERROR_PARSE = _Anonymous_183.MAILIMAP_ERROR_PARSE;
    enum MAILIMAP_ERROR_CONNECTION_REFUSED = _Anonymous_183.MAILIMAP_ERROR_CONNECTION_REFUSED;
    enum MAILIMAP_ERROR_MEMORY = _Anonymous_183.MAILIMAP_ERROR_MEMORY;
    enum MAILIMAP_ERROR_FATAL = _Anonymous_183.MAILIMAP_ERROR_FATAL;
    enum MAILIMAP_ERROR_PROTOCOL = _Anonymous_183.MAILIMAP_ERROR_PROTOCOL;
    enum MAILIMAP_ERROR_DONT_ACCEPT_CONNECTION = _Anonymous_183.MAILIMAP_ERROR_DONT_ACCEPT_CONNECTION;
    enum MAILIMAP_ERROR_APPEND = _Anonymous_183.MAILIMAP_ERROR_APPEND;
    enum MAILIMAP_ERROR_NOOP = _Anonymous_183.MAILIMAP_ERROR_NOOP;
    enum MAILIMAP_ERROR_LOGOUT = _Anonymous_183.MAILIMAP_ERROR_LOGOUT;
    enum MAILIMAP_ERROR_CAPABILITY = _Anonymous_183.MAILIMAP_ERROR_CAPABILITY;
    enum MAILIMAP_ERROR_CHECK = _Anonymous_183.MAILIMAP_ERROR_CHECK;
    enum MAILIMAP_ERROR_CLOSE = _Anonymous_183.MAILIMAP_ERROR_CLOSE;
    enum MAILIMAP_ERROR_EXPUNGE = _Anonymous_183.MAILIMAP_ERROR_EXPUNGE;
    enum MAILIMAP_ERROR_COPY = _Anonymous_183.MAILIMAP_ERROR_COPY;
    enum MAILIMAP_ERROR_UID_COPY = _Anonymous_183.MAILIMAP_ERROR_UID_COPY;
    enum MAILIMAP_ERROR_MOVE = _Anonymous_183.MAILIMAP_ERROR_MOVE;
    enum MAILIMAP_ERROR_UID_MOVE = _Anonymous_183.MAILIMAP_ERROR_UID_MOVE;
    enum MAILIMAP_ERROR_CREATE = _Anonymous_183.MAILIMAP_ERROR_CREATE;
    enum MAILIMAP_ERROR_DELETE = _Anonymous_183.MAILIMAP_ERROR_DELETE;
    enum MAILIMAP_ERROR_EXAMINE = _Anonymous_183.MAILIMAP_ERROR_EXAMINE;
    enum MAILIMAP_ERROR_FETCH = _Anonymous_183.MAILIMAP_ERROR_FETCH;
    enum MAILIMAP_ERROR_UID_FETCH = _Anonymous_183.MAILIMAP_ERROR_UID_FETCH;
    enum MAILIMAP_ERROR_LIST = _Anonymous_183.MAILIMAP_ERROR_LIST;
    enum MAILIMAP_ERROR_LOGIN = _Anonymous_183.MAILIMAP_ERROR_LOGIN;
    enum MAILIMAP_ERROR_LSUB = _Anonymous_183.MAILIMAP_ERROR_LSUB;
    enum MAILIMAP_ERROR_RENAME = _Anonymous_183.MAILIMAP_ERROR_RENAME;
    enum MAILIMAP_ERROR_SEARCH = _Anonymous_183.MAILIMAP_ERROR_SEARCH;
    enum MAILIMAP_ERROR_UID_SEARCH = _Anonymous_183.MAILIMAP_ERROR_UID_SEARCH;
    enum MAILIMAP_ERROR_SELECT = _Anonymous_183.MAILIMAP_ERROR_SELECT;
    enum MAILIMAP_ERROR_STATUS = _Anonymous_183.MAILIMAP_ERROR_STATUS;
    enum MAILIMAP_ERROR_STORE = _Anonymous_183.MAILIMAP_ERROR_STORE;
    enum MAILIMAP_ERROR_UID_STORE = _Anonymous_183.MAILIMAP_ERROR_UID_STORE;
    enum MAILIMAP_ERROR_SUBSCRIBE = _Anonymous_183.MAILIMAP_ERROR_SUBSCRIBE;
    enum MAILIMAP_ERROR_UNSUBSCRIBE = _Anonymous_183.MAILIMAP_ERROR_UNSUBSCRIBE;
    enum MAILIMAP_ERROR_STARTTLS = _Anonymous_183.MAILIMAP_ERROR_STARTTLS;
    enum MAILIMAP_ERROR_INVAL = _Anonymous_183.MAILIMAP_ERROR_INVAL;
    enum MAILIMAP_ERROR_EXTENSION = _Anonymous_183.MAILIMAP_ERROR_EXTENSION;
    enum MAILIMAP_ERROR_SASL = _Anonymous_183.MAILIMAP_ERROR_SASL;
    enum MAILIMAP_ERROR_SSL = _Anonymous_183.MAILIMAP_ERROR_SSL;
    enum MAILIMAP_ERROR_NEEDS_MORE_DATA = _Anonymous_183.MAILIMAP_ERROR_NEEDS_MORE_DATA;
    enum MAILIMAP_ERROR_CUSTOM_COMMAND = _Anonymous_183.MAILIMAP_ERROR_CUSTOM_COMMAND;
    struct mailimap_parser_context
    {
        int is_rambler_workaround_enabled;
        int is_qip_workaround_enabled;
        mailimap_msg_body_handler* msg_body_handler;
        void* msg_body_handler_context;
        mailimap_msg_att_body_section* msg_body_section;
        int msg_body_att_type;
        _Bool msg_body_parse_in_progress;
    }
    mailimap_parser_context* mailimap_parser_context_new(mailimap*, );
    void mailimap_parser_context_free(mailimap_parser_context*, );
    int mailimap_parser_context_is_rambler_workaround_enabled(mailimap_parser_context*, );
    int mailimap_parser_context_is_qip_workaround_enabled(mailimap_parser_context*, );
}

extern(C)
{
    struct _Anonymous_184
    {
        c_ulong[16] __val;
    }
    union _Anonymous_185
    {
        char[4] __size;
        int __align;
    }


    void* alloca(size_t, );
    union _Anonymous_186
    {
        char[4] __size;
        int __align;
    }
    struct _Anonymous_187
    {
        int quot;
        int rem;
    }
    alias div_t = _Anonymous_187;


    struct _Anonymous_188
    {
        __fd_mask[16] __fds_bits;
    }
    alias ldiv_t = _Anonymous_189;
    struct _Anonymous_189
    {
        c_long quot;
        c_long rem;
    }
    union _Anonymous_190
    {
        __pthread_mutex_s __data;
        char[40] __size;
        c_long __align;
    }


    union _Anonymous_191
    {
        __pthread_cond_s __data;
        char[48] __size;
        long __align;
    }
    alias lldiv_t = _Anonymous_192;
    struct _Anonymous_192
    {
        long quot;
        long rem;
    }


    union _Anonymous_193
    {
        __pthread_rwlock_arch_t __data;
        char[56] __size;
        c_long __align;
    }






    union _Anonymous_194
    {
        char[8] __size;
        c_long __align;
    }


    size_t __ctype_get_mb_cur_max();
    double atof(const(char)*, );
    int atoi(const(char)*, );
    c_long atol(const(char)*, );
    union _Anonymous_195
    {
        char[32] __size;
        c_long __align;
    }
    long atoll(const(char)*, );
    union _Anonymous_196
    {
        char[4] __size;
        int __align;
    }
    double strtod(const(char)*, char**, );
    float strtof(const(char)*, char**, );
    real strtold(const(char)*, char**, );
    c_long strtol(const(char)*, char**, int, );
    c_ulong strtoul(const(char)*, char**, int, );
    struct _Anonymous_197
    {
        int[2] __val;
    }
    long strtoq(const(char)*, char**, int, );
    ulong strtouq(const(char)*, char**, int, );
    long strtoll(const(char)*, char**, int, );
    ulong strtoull(const(char)*, char**, int, );






    char* l64a(c_long, );






    c_long a64l(const(char)*, );
    c_long random();
    void srandom(uint, );
    char* initstate(uint, char*, size_t, );
    char* setstate(char*, );
    struct random_data
    {
        int32_t* fptr;
        int32_t* rptr;
        int32_t* state;
        int rand_type;
        int rand_deg;
        int rand_sep;
        int32_t* end_ptr;
    }
    int random_r(random_data*, int32_t*, );
    int srandom_r(uint, random_data*, );
    int initstate_r(uint, char*, size_t, random_data*, );
    alias wchar_t = int;
    int setstate_r(char*, random_data*, );
    int rand();
    void srand(uint, );
    int rand_r(uint*, );
    double drand48();
    double erand48(ushort*, );
    c_long lrand48();
    c_long nrand48(ushort*, );
    c_long mrand48();
    c_long jrand48(ushort*, );
    void srand48(c_long, );
    ushort* seed48(ushort*, );
    void lcong48(ushort*, );
    struct drand48_data
    {
        ushort[3] __x;
        ushort[3] __old_x;
        ushort __c;
        ushort __init;
        ulong __a;
    }
    int drand48_r(drand48_data*, double*, );
    int erand48_r(ushort*, drand48_data*, double*, );
    int lrand48_r(drand48_data*, c_long*, );
    int nrand48_r(ushort*, drand48_data*, c_long*, );
    int mrand48_r(drand48_data*, c_long*, );
    int jrand48_r(ushort*, drand48_data*, c_long*, );
    int srand48_r(c_long, drand48_data*, );
    int seed48_r(ushort*, drand48_data*, );
    int lcong48_r(ushort*, drand48_data*, );
    void* malloc(size_t, );
    void* calloc(size_t, size_t, );
    void* realloc(void*, size_t, );
    void free(void*, );
    void* valloc(size_t, );
    int posix_memalign(void**, size_t, size_t, );
    void* aligned_alloc(size_t, size_t, );
    void abort();
    int atexit(void function(), );
    int at_quick_exit(void function(), );
    int on_exit(void function(int, void*), void*, );
    void exit(int, );
    void quick_exit(int, );
    void _Exit(int, );
    char* getenv(const(char)*, );
    int putenv(char*, );
    int setenv(const(char)*, const(char)*, int, );
    int unsetenv(const(char)*, );
    int clearenv();
    char* mktemp(char*, );
    int mkstemp(char*, );
    int mkstemps(char*, int, );
    char* mkdtemp(char*, );
    int system(const(char)*, );
    char* realpath(const(char)*, char*, );


    alias __compar_fn_t = int function(const(void)*, const(void)*);
    void* bsearch(const(void)*, const(void)*, size_t, size_t, __compar_fn_t, );
    void qsort(void*, size_t, size_t, __compar_fn_t, );
    int abs(int, );
    c_long labs(c_long, );
    long llabs(long, );
    div_t div(int, int, );
    ldiv_t ldiv(c_long, c_long, );
    lldiv_t lldiv(long, long, );
    char* ecvt(double, int, int*, int*, );
    char* fcvt(double, int, int*, int*, );
    char* gcvt(double, int, char*, );
    char* qecvt(real, int, int*, int*, );
    char* qfcvt(real, int, int*, int*, );
    char* qgcvt(real, int, char*, );
    int ecvt_r(double, int, int*, int*, char*, size_t, );
    int fcvt_r(double, int, int*, int*, char*, size_t, );
    int qecvt_r(real, int, int*, int*, char*, size_t, );
    int qfcvt_r(real, int, int*, int*, char*, size_t, );
    int mblen(const(char)*, size_t, );
    int mbtowc(wchar_t*, const(char)*, size_t, );
    int wctomb(char*, wchar_t, );
    size_t mbstowcs(wchar_t*, const(char)*, size_t, );
    size_t wcstombs(char*, const(wchar_t)*, size_t, );
    int rpmatch(const(char)*, );
    int getsubopt(char**, char**, char**, );
    int getloadavg(double*, int, );
}

extern(C)
{
    struct stat
    {
        __dev_t st_dev;
        __ino_t st_ino;
        __nlink_t st_nlink;
        __mode_t st_mode;
        __uid_t st_uid;
        __gid_t st_gid;
        int __pad0;
        __dev_t st_rdev;
        __off_t st_size;
        __blksize_t st_blksize;
        __blkcnt_t st_blocks;
        timespec st_atim;
        timespec st_mtim;
        timespec st_ctim;
        __syscall_slong_t[3] __glibc_reserved;
    }
    struct _Anonymous_198
    {
        int[2] __val;
    }
    pragma(mangle, "stat") int stat_(const(char)*, stat*, );




    int fstat(int, stat*, );
    int fstatat(int, const(char)*, stat*, int, );
    int lstat(const(char)*, stat*, );
    int chmod(const(char)*, __mode_t, );
    int lchmod(const(char)*, __mode_t, );
    int fchmod(int, __mode_t, );
    int fchmodat(int, const(char)*, __mode_t, int, );
    __mode_t umask(__mode_t, );
    int mkdir(const(char)*, __mode_t, );
    int mkdirat(int, const(char)*, __mode_t, );
    int mknod(const(char)*, __mode_t, __dev_t, );
    int mknodat(int, const(char)*, __mode_t, __dev_t, );
    int mkfifo(const(char)*, __mode_t, );
    int mkfifoat(int, const(char)*, __mode_t, );
    int utimensat(int, const(char)*, const(timespec)*, int, );
    int futimens(int, const(timespec)*, );


    int __fxstat(int, int, stat*, );
    int __xstat(int, const(char)*, stat*, );
    int __lxstat(int, const(char)*, stat*, );
    int __fxstatat(int, int, const(char)*, stat*, int, );
    int __xmknod(int, const(char)*, __mode_t, __dev_t*, );
    int __xmknodat(int, int, const(char)*, __mode_t, __dev_t*, );
}

