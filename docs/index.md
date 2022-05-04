# Introduction to Firebloom (iBoot)

## Intro

In Feb 2021, Apple published new content regarding [iBoot memory safety](https://support.apple.com/en-il/guide/security/sec30d8d9ec1/web), as part of Apple Security Platform. Their description mentions that "Apple modified the C compiler toolchain used to build the iBoot bootloader to improve its security" and some high-level descriptions of their efforts. The following is the relevant content from the document, quote:

```
Memory safe iBoot implementation

In iOS 14 and iPadOS 14, Apple modified the C compiler toolchain used to build the iBoot bootloader to improve its security. The modified toolchain implements code designed to prevent memory- and type-safety issues that are typically encountered in C programs. For example, it helps prevent most vulnerabilities in the following classes:

* Buffer overflows, by ensuring that all pointers carry bounds information that is verified when accessing memory

* Heap exploitation, by separating heap data from its metadata and accurately detecting error conditions such as double free errors

* Type confusion, by ensuring that all pointers carry runtime type information that’s verified during pointer cast operations

* Type confusion caused by use after free errors, by segregating all dynamic memory allocations by static type

This technology is available on iPhone with Apple A13 Bionic or later, and iPad with the A14 Bionic chip.

```

I was thinking it might be nice to put together some information about the implementation, format and the exciting work Apple has done on this. By the way, there are some very useful information strings in the iBoot binary, which made their way to Twitter very quickly ([one](https://twitter.com/axi0mx/status/1275907272925831168), [two](https://twitter.com/matteyeux/status/1395090120420864002)).

I'm fascinated by this work because the above description gives the impression of a "lightweight version of CHERI" implemented in software. According to Apple's description, in new versions of iBoot, pointers carry more than just an address - they carry bounds and type so that the compiler can introduce new memory safety validations to the code.

I like to get to the bottom of things, so let's dive in and see what we can learn.

This research was done on `iBoot.d53g.RELEASE.im4p`, iPhone 12, ios 14.4 (18D52).

## Start reversing

First, let's see how memory safety violaitons are handled once detected. It makes sense to trigger a panic when a memory safety violation occures, and indeed we have the *"__firebloom_panic"* string in the binary. Using that, we can name the functions around, and focus on the following simple function:

```assembly
iBoot:00000001FC1AA5A0 firebloom_panic
iBoot:00000001FC1AA5A0
iBoot:00000001FC1AA5A0 var_B8= -0xB8
iBoot:00000001FC1AA5A0 var_B0= -0xB0
iBoot:00000001FC1AA5A0 var_18= -0x18
iBoot:00000001FC1AA5A0 var_10= -0x10
iBoot:00000001FC1AA5A0 var_s0=  0
iBoot:00000001FC1AA5A0
iBoot:00000001FC1AA5A0 PACIBSP
iBoot:00000001FC1AA5A4 SUB             SP, SP, #0xD0
iBoot:00000001FC1AA5A8 STP             X20, X19, [SP,#0xC0+var_10]
iBoot:00000001FC1AA5AC STP             X29, X30, [SP,#0xC0+var_s0]
iBoot:00000001FC1AA5B0 ADD             X29, SP, #0xC0
iBoot:00000001FC1AA5B4 MOV             X19, X0
iBoot:00000001FC1AA5B8 ADD             X0, SP, #0xC0+var_B8
iBoot:00000001FC1AA5BC BL              sub_1FC1A9A08
iBoot:00000001FC1AA5C0 ADD             X8, X29, #0x10
iBoot:00000001FC1AA5C4 STUR            X8, [X29,#var_18]
iBoot:00000001FC1AA5C8 ADR             X1, aPasPanic ; "pas panic: "
iBoot:00000001FC1AA5CC NOP
iBoot:00000001FC1AA5D0 ADD             X0, SP, #0xC0+var_B8
iBoot:00000001FC1AA5D4 BL              do_trace
iBoot:00000001FC1AA5D8 LDUR            X2, [X29,#var_18]
iBoot:00000001FC1AA5DC ADD             X0, SP, #0xC0+var_B8
iBoot:00000001FC1AA5E0 MOV             X1, X19
iBoot:00000001FC1AA5E4 BL              sub_1FC1A9A48
iBoot:00000001FC1AA5E8 LDR             X0, [SP,#0xC0+var_B0]
iBoot:00000001FC1AA5EC BL              __firebloom_panic  
```

There are 11 xrefs to this function. I've called *"do_firebloom_panic"* to one of them, which has other 11 xrefs, each one catches a different kind of violation:

![image](https://github.com/saaramar/iBoot_firebloom/blob/main/files/do_firebloom_panic_xrefs.png)

Ok great, now we have a (partial) list of the things firebloom explictly detects and panics upon. Because some of these new checks are on known well-defined functions (`memset`, `memcpy`), we can expect to see new wrappers to `memset` and `memcpy` , with the new checks in place. By following up the xrefs chain and keep reversing the flow, it's easy to see these wrappers.

However, I'm curious what the rest of the validations would look like -- for instance, where/how we would see *ptr_under* / *ptr_over*? Well, the function `panic_ptr_over` has 179 xrefs, where a lot are simply wrappers with some hash. These wrappers have some xrefs, this time from an actual code that triggers panic when memory safety violations occur. By following up the flow, we can see many great examples of how it is used.

I believe in practical examples, and there is nothing clearer than code, so let's just follow one flow, for example:

```assembly
iBoot:00000001FC05C5AC loop                                    ; CODE XREF: sub_1FC05C548+94↓j
iBoot:00000001FC05C5AC                 CMP             X10, X9
iBoot:00000001FC05C5B0                 B.EQ            return
iBoot:00000001FC05C5B4 ; fetch ptr and lower bounds
iBoot:00000001FC05C5B4                 LDP             X11, X13, [X0]
iBoot:00000001FC05C5B8 ; advance the ptr to ptr+offset, it's a loop
iBoot:00000001FC05C5B8                 ADD             X12, X11, X9
iBoot:00000001FC05C5BC                 CMP             X12, X13
iBoot:00000001FC05C5C0                 B.CC            detected_ptr_under
iBoot:00000001FC05C5C4 ; fetch upper bounds
iBoot:00000001FC05C5C4                 LDR             X13, [X0,#0x10]
iBoot:00000001FC05C5C8                 CMP             X12, X13
iBoot:00000001FC05C5CC                 B.CS            detected_ptr_over
iBoot:00000001FC05C5D0 ; actually dereference the pointer
iBoot:00000001FC05C5D0                 LDR             W11, [X11,X9]
iBoot:00000001FC05C5D4                 STR             W11, [X8,#0x1DC]
iBoot:00000001FC05C5D8                 ADD             X9, X9, #4
iBoot:00000001FC05C5DC                 B               loop
iBoot:00000001FC05C5E0 ; ---------------------------------------------------------------------------
iBoot:00000001FC05C5E0
iBoot:00000001FC05C5E0 return                                  ; CODE XREF: sub_1FC05C548+68↑j
iBoot:00000001FC05C5E0                 LDUR            X8, [X29,#var_8]
iBoot:00000001FC05C5E4                 ADRP            X9, #a160d@PAGE ; "160D"
iBoot:00000001FC05C5E8                 NOP
iBoot:00000001FC05C5EC                 LDR             X9, [X9,#a160d@PAGEOFF] ; "160D"
iBoot:00000001FC05C5F0                 CMP             X9, X8
iBoot:00000001FC05C5F4                 B.NE            do_panic
iBoot:00000001FC05C5F8                 LDP             X29, X30, [SP,#0x70+var_s0]
iBoot:00000001FC05C5FC                 ADD             SP, SP, #0x80
iBoot:00000001FC05C600                 RETAB
iBoot:00000001FC05C604 ; ---------------------------------------------------------------------------
iBoot:00000001FC05C604
iBoot:00000001FC05C604 do_panic                                ; CODE XREF: sub_1FC05C548+AC↑j
iBoot:00000001FC05C604                 BL              call_panic
iBoot:00000001FC05C608 ; ---------------------------------------------------------------------------
iBoot:00000001FC05C608
iBoot:00000001FC05C608 detected_ptr_under                      ; CODE XREF: sub_1FC05C548+78↑j
iBoot:00000001FC05C608                 BL              call_panic_ptr_under_5383366e236c433
iBoot:00000001FC05C60C ; ---------------------------------------------------------------------------
iBoot:00000001FC05C60C
iBoot:00000001FC05C60C detected_ptr_over                       ; CODE XREF: sub_1FC05C548+84↑j
iBoot:00000001FC05C60C                 BL              call_panic_ptr_over_5383366e236c433
iBoot:00000001FC05C610 ; ---------------------------------------------------------------------------
```

Interesting. So before accessing the pointer with offset `X9` (at 0x01FC05C5D0), the code verifies `ptr+offset` against some bounds. The raw pointer and the bounds pointers (lower, upper) are retrieved from some structure (which I'll define in a minute). Before that, just to give you a good picture of the functions involved, let's view the panic wrappers:

```assembly
iBoot:00000001FC05D384 call_panic_ptr_over_5383366e236c433     ; CODE XREF: sub_1FC05C548:detected_ptr_over↑p
iBoot:00000001FC05D384                                         ; DATA XREF: call_panic_ptr_over_5383366e236c433+24↓o
iBoot:00000001FC05D384
iBoot:00000001FC05D384 var_8           = -8
iBoot:00000001FC05D384 var_s0          =  0
iBoot:00000001FC05D384
iBoot:00000001FC05D384                 PACIBSP
iBoot:00000001FC05D388                 SUB             SP, SP, #0x20
iBoot:00000001FC05D38C                 STP             X29, X30, [SP,#0x10+var_s0]
iBoot:00000001FC05D390                 ADD             X29, SP, #0x10
iBoot:00000001FC05D394                 ADRL            X8, a5383366e236c43 ; "5383366e236c433"
iBoot:00000001FC05D39C                 STR             X8, [SP,#0x10+var_8]
iBoot:00000001FC05D3A0                 MOV             X8, X30
iBoot:00000001FC05D3A4                 XPACI           X8
iBoot:00000001FC05D3A8                 ADR             X16, call_panic_ptr_over_5383366e236c433
iBoot:00000001FC05D3AC                 NOP
iBoot:00000001FC05D3B0                 PACIZA          X16
iBoot:00000001FC05D3B4                 SUB             X2, X8, X16
iBoot:00000001FC05D3B8                 ADD             X0, SP, #0x10+var_8
iBoot:00000001FC05D3BC                 MOV             W1, #1
iBoot:00000001FC05D3C0                 BL              panic_ptr_over
iBoot:00000001FC05D3C0 ; End of function call_panic_ptr_over_5383366e236c433
```

And:

```assembly
iBoot:00000001FC1AA980 panic_ptr_over                          ; CODE XREF: sub_1FC04CBD0+3C↑p
iBoot:00000001FC1AA980                                         ; sub_1FC04EC2C+3C↑p ...
iBoot:00000001FC1AA980
iBoot:00000001FC1AA980 var_20          = -0x20
iBoot:00000001FC1AA980 var_10          = -0x10
iBoot:00000001FC1AA980 var_s0          =  0
iBoot:00000001FC1AA980
iBoot:00000001FC1AA980                 PACIBSP
iBoot:00000001FC1AA984                 STP             X22, X21, [SP,#-0x10+var_20]!
iBoot:00000001FC1AA988                 STP             X20, X19, [SP,#0x20+var_10]
iBoot:00000001FC1AA98C                 STP             X29, X30, [SP,#0x20+var_s0]
iBoot:00000001FC1AA990                 ADD             X29, SP, #0x20
iBoot:00000001FC1AA994                 MOV             X19, X2
iBoot:00000001FC1AA998                 MOV             X20, X1
iBoot:00000001FC1AA99C                 MOV             X21, X0
iBoot:00000001FC1AA9A0                 ADRP            X8, #0x1FC2F2270@PAGE
iBoot:00000001FC1AA9A4                 LDR             X8, [X8,#0x1FC2F2270@PAGEOFF]
iBoot:00000001FC1AA9A8                 CBZ             X8, do_panic
iBoot:00000001FC1AA9AC                 BLRAAZ          X8
iBoot:00000001FC1AA9B0
iBoot:00000001FC1AA9B0 do_panic                                ; CODE XREF: panic_ptr_over+28↑j
iBoot:00000001FC1AA9B0                 ADR             X0, aPtrOver ; "ptr_over"
iBoot:00000001FC1AA9B4                 NOP
iBoot:00000001FC1AA9B8                 MOV             X1, X21
iBoot:00000001FC1AA9BC                 MOV             X2, X20
iBoot:00000001FC1AA9C0                 MOV             X3, X19
iBoot:00000001FC1AA9C4                 BL              do_firebloom_panic
iBoot:00000001FC1AA9C4 ; End of function panic_ptr_over
```

Great, very simple.

Let's see if the same pattern repeats itself in other places. For instance, this one:

![image](https://github.com/saaramar/iBoot_firebloom/blob/main/files/ptr_check_example.png)

In this example, you can see a loop iterating over an array of elements (each one of size 0x20), and call some function on each element. And, unsurprisingly, the same "pointer structure" is used here, in the same way.

## Format and helper functions

So we have a good base to believe that allocations are represented by the following structure:

```
00000000 safe_allocation struc ; (sizeof=0x20, mappedto_1)
00000000 raw_ptr         DCQ ?                   ; offset
00000008 lower_bound_ptr DCQ ?                   ; offset
00000010 upper_bound_ptr DCQ ?                   ; offset
00000018 field_18        DCQ ?
00000020 safe_allocation ends
```

Awesome. We can look at it as a kind of "Fat/Bounded Pointer". Instead of having a simple raw 64-bit pointer that refers to memory, we have a structure representing the pointer with additional metadata.

Clearly, the fact that we use 32 bytes (i.e. 4 64-bit values) to represent a pointer, has impact on many operations. Consider the simple operation of copying a pointer - instead of having a line of code `p2 = p;`, we now need to read/write 4-tuple of values (which we usually see as 2 `LDP`s and 2 `STP`s).

I would really like to find the new allocation functions that allocate a chunk and initialize these bounds in the structure. I found it by simply reversing more up the call stack, but looking back, there is a REALLY easy way to spot that :)

If you'll look at the xrefs of `do_firebloom_panic`, there is a really interesting wrapper: `call_panic_allocation_size_error`. It has a very few xrefs (less than 5) to a set of very similar functions :) The most simplest one, is the following:

```assembly
iBoot:00000001FC1A1CF0 do_safe_allocation                      ; CODE XREF: sub_1FC0523D8+8↑j
iBoot:00000001FC1A1CF0                                         ; sub_1FC05259C+70↑p ...
iBoot:00000001FC1A1CF0
iBoot:00000001FC1A1CF0 var_20          = -0x20
iBoot:00000001FC1A1CF0 var_18          = -0x18
iBoot:00000001FC1A1CF0 var_10          = -0x10
iBoot:00000001FC1A1CF0 var_s0          =  0
iBoot:00000001FC1A1CF0
iBoot:00000001FC1A1CF0                 PACIBSP
iBoot:00000001FC1A1CF4                 SUB             SP, SP, #0x30
iBoot:00000001FC1A1CF8                 STP             X20, X19, [SP,#0x20+var_10]
iBoot:00000001FC1A1CFC                 STP             X29, X30, [SP,#0x20+var_s0]
iBoot:00000001FC1A1D00                 ADD             X29, SP, #0x20
iBoot:00000001FC1A1D04 ; X8 - the structure to initialize
iBoot:00000001FC1A1D04                 MOV             X19, X8
iBoot:00000001FC1A1D08 ; X0 and X1 are probably `count` and `bytes`
iBoot:00000001FC1A1D08                 UMULH           X8, X1, X0
iBoot:00000001FC1A1D0C                 CBNZ            X8, allocation_size_error_detected
iBoot:00000001FC1A1D10 ; X20 - size of the allocation
iBoot:00000001FC1A1D10                 MUL             X20, X1, X0
iBoot:00000001FC1A1D14                 ADRP            X8, #0x1FC2F50B8@PAGE
iBoot:00000001FC1A1D18                 ADD             X8, X8, #0x1FC2F50B8@PAGEOFF
iBoot:00000001FC1A1D1C                 STR             X8, [SP,#0x20+var_18]
iBoot:00000001FC1A1D20                 STR             WZR, [SP,#0x20+var_20]
iBoot:00000001FC1A1D24                 ADRP            X2, #0x1FC2F50B0@PAGE
iBoot:00000001FC1A1D28                 ADD             X2, X2, #0x1FC2F50B0@PAGEOFF
iBoot:00000001FC1A1D2C                 ADRL            X3, off_1FC2D6EC0
iBoot:00000001FC1A1D34                 ADRL            X1, qword_1FC2D6E80
iBoot:00000001FC1A1D3C ; PAC-sign the allocation API
iBoot:00000001FC1A1D3C                 ADR             X16, do_allocation
iBoot:00000001FC1A1D40                 NOP
iBoot:00000001FC1A1D44                 PACIZA          X16
iBoot:00000001FC1A1D48                 MOV             X6, X16
iBoot:00000001FC1A1D4C                 MOV             X0, #0
iBoot:00000001FC1A1D50                 MOV             X4, X20
iBoot:00000001FC1A1D54                 MOV             W5, #1
iBoot:00000001FC1A1D58                 MOV             X7, X1
iBoot:00000001FC1A1D5C ; call the allocation API, allocates a chunk
iBoot:00000001FC1A1D5C ; the return value (X0) is X19, this function
iBoot:00000001FC1A1D5C ; has "MOV X0, X19" in its return
iBoot:00000001FC1A1D5C                 BL              wrap_do_allocation
iBoot:00000001FC1A1D60                 ADRL            X8, off_1FC2D6EF8
iBoot:00000001FC1A1D68                 STR             X8, [X19,#0x18]
iBoot:00000001FC1A1D6C                 STR             X0, [X19]
iBoot:00000001FC1A1D70 ; check if allocation succeeded
iBoot:00000001FC1A1D70                 CBZ             X0, allocation_failed
iBoot:00000001FC1A1D74 ; X0 - based of the allocation
iBoot:00000001FC1A1D74 ; X8 - X0 + allocation_size, upper bound
iBoot:00000001FC1A1D74                 ADD             X8, X0, X20
iBoot:00000001FC1A1D78 ; store the based (i.e. lower bound) and the upper bound
iBoot:00000001FC1A1D78 ; to the structure, at offsets +0x8, +0x10
iBoot:00000001FC1A1D78                 STP             X0, X8, [X19,#8]
iBoot:00000001FC1A1D7C                 LDP             X29, X30, [SP,#0x20+var_s0]
iBoot:00000001FC1A1D80                 LDP             X20, X19, [SP,#0x20+var_10]
iBoot:00000001FC1A1D84                 ADD             SP, SP, #0x30 ; '0'
iBoot:00000001FC1A1D88                 RETAB
iBoot:00000001FC1A1D8C ; ---------------------------------------------------------------------------
iBoot:00000001FC1A1D8C
iBoot:00000001FC1A1D8C allocation_failed                       ; CODE XREF: do_safe_allocation+80↑j
iBoot:00000001FC1A1D8C                 ADD             X8, X19, #8
iBoot:00000001FC1A1D90 ; allocation failed, set NULL to both
iBoot:00000001FC1A1D90 ; lower and upper bounds
iBoot:00000001FC1A1D90                 STP             XZR, XZR, [X8]
iBoot:00000001FC1A1D94                 LDP             X29, X30, [SP,#0x20+var_s0]
iBoot:00000001FC1A1D98                 LDP             X20, X19, [SP,#0x20+var_10]
iBoot:00000001FC1A1D9C                 ADD             SP, SP, #0x30 ; '0'
iBoot:00000001FC1A1DA0                 RETAB
iBoot:00000001FC1A1DA4 ; ---------------------------------------------------------------------------
iBoot:00000001FC1A1DA4
iBoot:00000001FC1A1DA4 allocation_size_error_detected          ; CODE XREF: do_safe_allocation+1C↑j
iBoot:00000001FC1A1DA4                 BL              call_panic_allocation_size_error
iBoot:00000001FC1A1DA4 ; End of function do_safe_allocation
```

Fantastic! Exactly what I was hoping to find. This function allocates a chunk and sets up a structure to describe it, with the layout we learned from reversing the rest of the binary.

You probably wonder what the rest of the allocation functions look like. Well, just like you probably assume, there is a very similar function, just with a call to *memset0* at the end (i.e. - version of calloc):

```assembly
iBoot:00000001FC1AA58C memset_0                                ; CODE XREF: sub_1FC1A0890+3CC↑p
iBoot:00000001FC1AA58C                                         ; do_safe_allocation_and_zeroing:zero_the_allocation↑j ...
iBoot:00000001FC1AA58C                 CBZ             X1, return
iBoot:00000001FC1AA590
iBoot:00000001FC1AA590 loop                                    ; CODE XREF: memset_0+C↓j
iBoot:00000001FC1AA590                 STRB            WZR, [X0],#1
iBoot:00000001FC1AA594                 SUBS            X1, X1, #1
iBoot:00000001FC1AA598                 B.NE            loop
iBoot:00000001FC1AA59C
iBoot:00000001FC1AA59C return                                  ; CODE XREF: memset_0↑j
iBoot:00000001FC1AA59C                 RET
iBoot:00000001FC1AA59C ; End of function memset_0
```

Combine these 3 new allocation API, there are over 100 xrefs :) Seems about right.

### malloc

While there are 100+ places in iBoot that call the `do_safe_allocation` function directly, I've seen some calls to `malloc` in the past, and I know it's still there. There are many ways to spot `malloc` in iBoot, one of them is simply looking for the "%s malloc failed" string and find the called function before that trace. By doing that, we can see our `do_allocation` is actually what `malloc` calls to!

That's `malloc`:

```assembly
iBoot:00000001FC15ABF8 malloc                                  ; CODE XREF: sub_1FC19F50C+58↓p
iBoot:00000001FC15ABF8                                         ; sub_1FC19F77C+464↓p ...
iBoot:00000001FC15ABF8                 B               call_do_allocation
iBoot:00000001FC15ABF8 ; End of function malloc
```

And that's `call_do_allocation`:

```assembly
iBoot:00000001FC1A1B30 call_do_allocation
iBoot:00000001FC1A1B30
iBoot:00000001FC1A1B30 var_10= -0x10
iBoot:00000001FC1A1B30 var_8= -8
iBoot:00000001FC1A1B30 var_s0=  0
iBoot:00000001FC1A1B30
iBoot:00000001FC1A1B30 PACIBSP
iBoot:00000001FC1A1B34 SUB             SP, SP, #0x20
iBoot:00000001FC1A1B38 STP             X29, X30, [SP,#0x10+var_s0]
iBoot:00000001FC1A1B3C ADD             X29, SP, #0x10
iBoot:00000001FC1A1B40 MOV             X4, X0
iBoot:00000001FC1A1B44 ADRP            X8, #0x1FC2F50B8@PAGE
iBoot:00000001FC1A1B48 ADD             X8, X8, #0x1FC2F50B8@PAGEOFF
iBoot:00000001FC1A1B4C STR             X8, [SP,#0x10+var_8]
iBoot:00000001FC1A1B50 STR             WZR, [SP,#0x10+var_10]
iBoot:00000001FC1A1B54 ADRP            X2, #0x1FC2F50B0@PAGE
iBoot:00000001FC1A1B58 ADD             X2, X2, #0x1FC2F50B0@PAGEOFF
iBoot:00000001FC1A1B5C ADRL            X3, off_1FC2D6EC0
iBoot:00000001FC1A1B64 ADRL            X1, qword_1FC2D6E80
iBoot:00000001FC1A1B6C ADR             X16, do_allocation
iBoot:00000001FC1A1B70 NOP
iBoot:00000001FC1A1B74 PACIZA          X16
iBoot:00000001FC1A1B78 MOV             X6, X16
iBoot:00000001FC1A1B7C MOV             X0, #0
iBoot:00000001FC1A1B80 MOV             W5, #1
iBoot:00000001FC1A1B84 MOV             X7, X1
iBoot:00000001FC1A1B88 BL              wrap_do_allocation
iBoot:00000001FC1A1B8C LDP             X29, X30, [SP,#0x10+var_s0]
iBoot:00000001FC1A1B90 ADD             SP, SP, #0x20 ; ' '
iBoot:00000001FC1A1B94 RETAB
iBoot:00000001FC1A1B94 ; End of function call_do_allocation
```

It was important for me to note that, for two reasons:

1. It's another approval that our understnading of the allocation API is correct.
2. The places which call to `malloc` and not `do_safe_allocation` do not get the security properties of Firebloom.

It's an interesting question why these call sites aren't updated to the new mechanism. There are few possible answers here:

* Maybe Apple has static analysis that proves it's fine to not use firebloom on these callsites?
* Maybe some libraries weren't converted to Firebloom yet? Maybe this mitigation is in transition? 

## Type safety

So, we know the structure has the raw pointer and the lower/upper bound pointers. We identified this in the binary, and we know how it works.

However, I did expect to see some type information here, because:

1. first of all, we have functions such as `panic_memset_bad_type` 
2. Apple explicitily mentioned that in their high-level overview :)

Well, if you recall, the allocation functions above did store a value to offset 0x18 of our structure (that's why I defined it to be 0x20 size). If we will follow up the usage of `panic_memset_bad_type`, for example, we would see the following:

```assembly
iBoot:00000001FC15A9CC                 LDR             X23, [X20,#0x18]
iBoot:00000001FC15A9D0                 MOV             X0, X23
iBoot:00000001FC15A9D4                 BL              check_type
iBoot:00000001FC15A9D8                 TBNZ            W0, #0, call_memset
iBoot:00000001FC15A9DC                 CBNZ            W22, detected_memset_bad_type
```

Yes! Looks like offset 0x18 is used to store a type. I'll elaborate more about the type safety implementation some other time. It's enough to mention that the `type` field is set by individual callers to `do_safe_allocation`, and it's easy to see it in the code.

## Sum up / thoughts

It's great to see more work on memory safety, and it's always great to have more new stuff to look into.

This change is interesting. It certainly helps mitigate some of the memory safety vulnerabilities; however - it's quite expensive in a few different ways:

1. <u>memory overhead:</u> these new pointers take 0x20 bytes of memory, instead of 0x8. Representations of references to memory that are protected this way, consume x4 memory.
2. <u>code size:</u> clearly code size increases - more instructions to manage the new metadata, more branches, more checks, etc.
3. <u>perf:</u> a lot of dereferences now are wrapped with more instructions (that loads data from memory), which impacts performance.

I obviously didn't measure these overheads between old/new versions of iBoot, so it's all theoretical. But I believe it's safe to assume this cost exists, and Apple found a way to make it work.

I know it sounds bad when I list it this way, but to be honest - iBoot is just the place for such a change. I would be highly surprised if Apple (or any other vendor) could pull off such an expensive change in the kernel, but iBoot is a very lightweight, contained environment. It has access to the entire DRAM, and it has a very limited and specific purpose. And it makes sense to protect the second stage bootloader, which is a critical part of the secure boot process.

This is a great exmaple for another effort on Apple's behalf, which improves security by mitigating a lot of 1st order primitives.



I hope you enjoyed this blogpost.

Thanks,

Saar Amar.