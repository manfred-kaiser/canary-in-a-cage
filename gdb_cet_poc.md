┌─[✗]─[user@parrot]─[~/canary-in-a-cage/service]
└──╼ $gdb -q ./build/service
Reading symbols from ./build/service...
(gdb) set follow-fork-mode child          # when the server fork()s for a connection, follow the CHILD
(gdb) set detach-on-fork off              # ...but keep the long-lived PARENT attached too, so it can
                                           # still accept further connections later in this same session
(gdb) b *main+0x1b9
Breakpoint 1 at 0x1319: file src/service.c, line 193.
                                           # = the shared epilogue's `ret` (both CMD_STATUS and
                                           # CMD_REGISTER funnel through this exact instruction,
                                           # since both handlers are inlined into main())
(gdb) run
Starting program: /home/canary-in-a-cage/service/build/service 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
user_registration_service listening on port 4444

[Attaching after Thread 0x7ffff7daa780 (LWP 47682) fork to child process 47804]
[New inferior 2 (process 47804)]
                                           # ↑ fork #1 — this is the ordinary CMD_STATUS leak
                                           #   connection, the "legitimate" baseline request
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x7ffff7daa780 (LWP 47804)]

Thread 2.1 "service" hit Breakpoint 1.2, 0x0000555555555319 in main () at src/service.c:193
193                 return 0;
(gdb) x/gx $rsp
0x7fffffffd7a8: 0x00007ffff7dd6ca8         # <-- R_legit: the REAL return address, untouched,
                                           #     sitting exactly where the ret is about to read it
(gdb) continue
Continuing.
[Inferior 2 (process 47804) exited normally]
                                           # legit connection finishes cleanly — nothing malicious
                                           # happened here, it's just a normal request/response
(gdb) inferior 1                          # switch focus back to the PARENT (still alive, just
[Switching to inferior 1 [process 47682] (/home/canary-in-a-cage/service/build/service)]
[Switching to thread 1.1 (Thread 0x7ffff7daa780 (LWP 47682))]
#0  0x00007ffff7e89f82 in _Fork () from /lib/x86_64-linux-gnu/libc.so.6
                                           # parent is paused mid-fork() call, right where gdb's
                                           # follow-fork handling left it after the first connection
(gdb) continue                            # resume the parent -> it goes back to accept()ing
Continuing.

[Attaching after Thread 0x7ffff7daa780 (LWP 47682) fork to child process 48006]
[New inferior 3 (process 48006)]
                                           # ↑ fork #2 — this is the CMD_REGISTER overflow
                                           #   connection, i.e. the actual exploit payload
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x7ffff7daa780 (LWP 48006)]

Thread 3.1 "service" hit Breakpoint 1.2, 0x0000555555555319 in main () at src/service.c:193
193                 return 0;
                                           # same breakpoint, same instruction, same stack slot
                                           # (0x7fffffffd7a8 — identical address to the first read,
                                           # confirming this is the SAME memory location being
                                           # compared, not two different ones)
(gdb) x/gx $rsp
0x7fffffffd7a8: 0x00007ffff7dd7145         # <-- R_exploit: the overflow's first ROP gadget
                                           #     address, sitting in that same slot instead
(gdb)