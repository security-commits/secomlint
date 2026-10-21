from enum import Enum

class Message(Enum):
    MSG1 = """vuln-fix: Sanitize URLs to reject malicious data (CVE-2012-0036)

Protocols (IMAP, POP3 and SMTP) that use the path part of a URL in a
decoded manner now use the new Curl_urldecode() function to reject URLs
with embedded control codes (anything that is or decodes to a byte value
less than 32).
URLs containing such codes could easily otherwise be used to do harm and
allow users to do unintended actions with otherwise innocent tools and
applications.
Like for example using a URL like pop3://pop3.example.com/1%0d%0aDELE%201
when the app wants a URL to get a mail and instead this would delete one.

Weakness: CWE-89
Severity: High
Detection: Manual
Report: https://curl.se/docs/CVE-2012-0036.html

Reported-by: Dan Fandrich
Signed-off-by: Daniel Stenberg (daniel@haxx.se)

Resolves: #17940
See also: #17937"""

    MSG2 = """vuln-fix: Sanitize URLs to reject malicious data (CVE-2012-0036)

Weakness: CWE-89
Severity: High
Detection: Manual
Report: https://curl.se/docs/CVE-2012-0036.html

Reported-by: Dan Fandrich
Signed-off-by: Daniel Stenberg (daniel@haxx.se)

Resolves: #17940
See also: #17937"""

    MSG3 = """vuln-fix: Sanitize URLs to reject malicious data (CVE-2012-0036)

Reported-by: Dan Fandrich
Signed-off-by: Daniel Stenberg (daniel@haxx.se)

Resolves: #17940
See also: #17937"""

    MSG4 = """[PATCH] lldp: fix a buffer overflow when handling management address
 TLV

When a remote device was advertising a too large management address
while still respecting TLV boundaries, lldpd would crash due to a buffer
overflow. However, the buffer being a static one, this buffer overflow
is not exploitable if hardening was not disabled. This bug exists since
version 0.5.6."""

MSG5 = """crypto: ccm - move cbcmac input off the stack

commit f15f05b0a5de ("crypto: ccm - switch to separate cbcmac driver")
refactored the ccm driver to allow separate implementations of the
underlying mac to be provided by a platform. however, in doing so, it
moved some data from the linear region to the stack, which violates the
sg constraints when the stack is virtually mapped.

so move idata/odata back to the request ctx struct, of which we can
reasonably expect that it has been allocated using kmalloc() et al.

reported-by: johannes berg <johannes@sipsolutions.net>
fixes: f15f05b0a5de ("crypto: ccm - switch to separate cbcmac driver")
signed-off-by: ard biesheuvel <ard.biesheuvel@linaro.org>
tested-by: johannes berg <johannes@sipsolutions.net>
signed-off-by: herbert xu <herbert@gondor.apana.org.au>"""

MSG6 = """fix buffer overflow in mb_ereg_replace

summary:
this diff has already been landed to release and to open-source branches. we're now landing it on master.

cve-2019-11935

reviewed by: jjergus

differential revision: d18177934

fbshipit-source-id: d108a59e38c67f5f5e835febd7255307605ba62c
"""

MSG7 = """change ort to not update ip_allow except badass (#5041)

* change ort to not update ip_allow except badass

ats has a known bug where changing ip_allow.config causes random
blocking on config reload. we changed ort a while back to not reload
when it changes, but other files can later trigger a reload.

this changes ort to not update the file at all, and log an error.
this will cause any added servers to not be added to the allow,
likely breaking edges. but breaking an edge is better than
breaking a mid.

further, the error log will allow users to create alarms, so
they know to go in and manually badass and restart the machine.

* add ort flag to update ip_allow.config in syncds
"""

MSG8 = """tty: prevent ldisc drivers from re-using stale tty fields

line discipline drivers may mistakenly misuse ldisc-related fields
when initializing. for example, a failure to initialize tty->receive_room
in the n_gigaset_m101 line discipline was recently found and fixed [1].
now, the n_x25 line discipline has been discovered accessing the previous
line discipline's already-freed private data [2].

harden the ldisc interface against misuse by initializing revelant
tty fields before instancing the new line discipline.

[1]
    commit fd98e9419d8d622a4de91f76b306af6aa627aa9c
    author: tilman schmidt <tilman@imap.cc>
    date:   tue jul 14 00:37:13 2015 +0200

    isdn/gigaset: reset tty->receive_room when attaching ser_gigaset

[2] report from sasha levin <sasha.levin@oracle.com>
    [  634.336761] ==================================================================
    [  634.338226] bug: kasan: use-after-free in x25_asy_open_tty+0x13d/0x490 at addr ffff8800a743efd0
    [  634.339558] read of size 4 by task syzkaller_execu/8981
    [  634.340359] =============================================================================
    [  634.341598] bug kmalloc-512 (not tainted): kasan: bad access detected
    ...
    [  634.405018] call trace:
    [  634.405277] dump_stack (lib/dump_stack.c:52)
    [  634.405775] print_trailer (mm/slub.c:655)
    [  634.406361] object_err (mm/slub.c:662)
    [  634.406824] kasan_report_error (mm/kasan/report.c:138 mm/kasan/report.c:236)
    [  634.409581] __asan_report_load4_noabort (mm/kasan/report.c:279)
    [  634.411355] x25_asy_open_tty (drivers/net/wan/x25_asy.c:559 (discriminator 1))
    [  634.413997] tty_ldisc_open.isra.2 (drivers/tty/tty_ldisc.c:447)
    [  634.414549] tty_set_ldisc (drivers/tty/tty_ldisc.c:567)
    [  634.415057] tty_ioctl (drivers/tty/tty_io.c:2646 drivers/tty/tty_io.c:2879)
    [  634.423524] do_vfs_ioctl (fs/ioctl.c:43 fs/ioctl.c:607)
    [  634.427491] sys_ioctl (fs/ioctl.c:622 fs/ioctl.c:613)
    [  634.427945] entry_syscall_64_fastpath (arch/x86/entry/entry_64.s:188)

cc: tilman schmidt <tilman@imap.cc>
cc: sasha levin <sasha.levin@oracle.com>
signed-off-by: peter hurley <peter@hurleysoftware.com>
signed-off-by: greg kroah-hartman <gregkh@linuxfoundation.org>
"""

MSG9 = """fix bug that could cause map_fn to produce incorrect results (rather than an error)
when mapping over a ragged tensor with an inappropriate fn_output_signature.  (note: there are cases where the default value for fn_output_signature is not appropriate, so the user needs to explicitly specify the correct output signature.)

piperorigin-revid: 387606546
change-id: ib4ea27b9634e6ab413f211cfe809a69a90f0e2cd
"""