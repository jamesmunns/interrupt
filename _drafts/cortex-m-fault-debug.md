---
title: "How to debug an ARM Cortex-M HardFault"
description: "A step by step guide of how to investigate what led to a fault on a Cortex-M device with examples and strategies about how to recover"
tag: [cortex-m]
author: chris
---

At one point or another when working with a ARM Cortex-M MCU, you will hit something like:

```
(gdb) bt
#0  0xe0000000 in ?? ()
#1  0x000002e8 in HardFault_Handler () at startup.c:137
#2  <signal handler called>
```

<!-- excerpt start -->

In this article we will demystify how to debug what went wrong when a ARM Cortex-M fault occurs. We will walk step-by-step through what system registers can be inspected. We will discuss debug tricks that can be used for some of the trickiest classes of hardfaults, how to recover from a fault without rebooting the system, and how how to automate the fault analysis. Finally we will walk through a couple pratical examples where we can apply what we just learned!

<!-- excerpt end -->

_Like Interrupt? [Subscribe](http://eepurl.com/gpRedv) to get our latest
posts straight to your mailbox_

## Table of Contents

<!-- prettier-ignore -->
* auto-gen TOC:
{:toc}

## Determining What Caused The Fault

All MCUs in the Cortex-M series have several different pieces of state which can be analyzed when a fault occurred to understand how it originated.

First we will talk explore the dedicated fault status registers that are present on all Cortex-M MCUs except the Cortex-M0.

If you are trying to debug a Cortex-M0, you can skip ahead to the [this section](#registers-prior-to-exception) where we discuss how to recover the register state and instruction being executed at the time of the exception.

{: #cfsr}

## Configurable Fault Status Registers (CFSR) - 0xE000ED28

This 32 bit register contains a summary of the fault(s) which took place and resulted in the exception. The register is compressed of three sub fault status registers -- UsageFault, BusFault & MemManage Fault Status Registers:

![](img/cortex-m-fault/cfsr.png)

All of these sub-registers can be accessed via a 32 bit read at `0xE000ED28`. They can also be read individually by reading at the appropriate offset. For example, in GDB it would look something like this:

- [UsageFault Status Register (UFSR)](#ufsr) - `print/x *(uint16_t *)0xE000ED2A`
- [BusFault Status Register (BFSR)](#bfsr) - `print/x *(uint8_t *)0xE002ED29`
- [MemManage Status Register (MMFSR)](#mmfsr) - `print/x *(uint8_t *)0xE000ED28`

> NOTE: All the bits reported are sticky and do not reset unless a system reset occurs or they are cleared in software by writing a 1 to the bit to clear. The registers are also additive so if multiple faults have occurred, multiple bits in the registers may be set.

{: #ufsr}

### UsageFault Status Register (UFSR) - 0xE000ED2A

This register is a 2 byte register which summarizes any faults that are not related to memory access failures, such as executing invalid instructions or trying to enter invalid states.

![](img/cortex-m-fault/ufsr.png)

Most of these bits are pretty self explanatory but in short:

- `DIVBYZERO` - Indicates a divide instruction was executed where the denominator was zero
- `UNALIGNED` - Indicates an unaligned access operation occurred. Unaligned multiple word accesses (i.e a `uint64_t` access not along an 8 byte boundary) will _always_ generate this fault. Whether or not unaligned accesses below four bytes generate a fault is configurable and is discusses in more detail [below](#configurable-usage-faults)
- `NOCP` - Indicates the Cortex-M in use implements a coprocessor (such as the Floating Point extension) but the coprocessor is disabled or not present. This type of crash could happen for example if you are compiling your code with the FP extension enabled (`-mfloat-abi=hard -mfpu=fpv4-sp-d16`) but not enabling the FP coprocessor on boot.
- `INVPC` - Indicates an integrity check failure on `EXC_RETURN` has returned. `EXC_RETURN` is the value branched to upon return from an exception. If this fault flag is set, it basically indicates something went wrong exiting an exception. Extensive details about legal `EXC_RETURN` values can be found in our [RTOS context switching article](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#exc-return-info)
- `INVSTATE` - Indicates the processor has tried to execute an instruction with an invalid _Execution Program Status Register_ (**EPSR**). Among other things the ESPR tracks whether or not the processor is in thumb mode state. Instructions which use "interworking addresses"[^1] (`bx`, `blx` or `ldr` & `ldm` which load a `$pc` relative value) must set bit[0] to 1 as this is used to update `ESPR.T`. If this rule is violated, a INVSTATE exception will be generated. When writing C code, the compiler will take care of this for you but this is a common bug which can happen if you try writing your own assembly and flag a label as data when it is a function.
- `UNDEFINSTR` - Indicates an undefined / illegal instruction was executed. One way this could arise is if the stack upon exception entry got corrupted while the exception handler was running. Upon exiting the exception, the hardware would attempt to execute an invalid exception.

{: #configurable-usage-faults}

#### Configurable UsageFault

It's worth noting that some classes of UsageFaults are configurable via the _Configuration and Control Register_ (**CCR**) located at address `0xE000ED14`.

- Bit 4 (`DIV_0_TRP`) - Controls whether or not divide by zeros will trigger a fault.
- Bit 3 (`UNALIGN_TRP`) - Controls whether or not unaligned accesses will always generate a fault.

> NOTE: On reset both of these values are settings are disabled. It's generally a good idea to enable faults on divide by zero to catch mathematical errors in your code.

{: #bfsr}

### BusFault Status Register (BFSR) - 0xE002ED29

This register is a 1 byte register which summarizes faults related to instruction prefetch or memory access failures

![](img/cortex-m-fault/bfsr.png)

- `BFARVALID` - Indicates the address which triggered the bus fault is stored in the _Bus Fault Address Register_ (**BFAR**) - a 32 bit register located at `0xE000ED38`.
- `LSPERR` & `STKERR` - Indicates that a fault occurred during lazy state preservation or during exception entry, respectively. More details about both can be found [here](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#context-state-stacking). One reason this error may occur is if the stack in use runs off the valid RAM address range while trying to service an exception
- `UNSTKERR` - Indicates that a fault occurred trying to return from an exception which usually has something to do with the stack being returned to not being correct.
- `IMPRECISERR` - This flag is _very_ important. It tells us whether or not the hardware was able to determine the exact location of the fault. Some Cortex-M implementations will perform memory accesses that take multiple cycles to complete. In these situations, the fault may occur after the instruction has executed. We will explore this in greater detail in the next section.
- `PRECISERR` - Indicates that the instruction which was executing prior to exception entry triggered the fault.

### Debugging IMPRECISERR

Imprecise errors are one of the hardest classes of faults to debug. They result asynchronously to instruction execution flow. This means the registers stacked on exception entry will **not** point to the code that caused the exception.

Instruction fetches and data loads should always generate synchronous faults for Cortex-M devices. However, some stores operations can generate asynchronous faults. This is because writes will sometimes be buffered prior to being flushed to prevent pipeline stalls.

You'll want to inspect the code around the area reported by the exception for a store that looks suspicious. If the MCU has support for the ARM Embedded Trace Macrocell (ETM), the history of recently executed instructions can be viewed by some debuggers[^8]

#### Auxiliary Control Register (ACTLR) - 0xE000E008

This register allows for some hardware optimizations and implementations to be disabled typically at the cost of overall performance or interrupt latency. The exact configuration options available are specific to the exact Cortex-M series being used.

{: #cortex-m3-m4-debug-trick}
For the Cortex M3 & Cortex M4 **only**, there is a trick to make all `IMPRECISE` accesses `PRECISE` by disabling any write buffering. This can be done by setting bit 1 (`DISDEFWBUF`) of the register to 1.

For the Cortex M7, there is **no** way to force all stores to be synchronous.

#### Auxiliary Bus Fault Status Register (ABFSR) - 0xE000EFA8

This register **only** exists for Cortex-M7 devices. When an `IMPRECISE` error occurs it will at least give you an indication of what memory bus the fault occurred on[^7]:

![](img/cortex-m-fault/abfsr.png)

A full discussion of memory interfaces is outside the scope of this article but more details can be found in the reference manual [^7].

{: #mmfsr}

### MemManage Status Register (MMFSR) - 0xE000ED28

This register reports Memory Protection Unit faults. For a deep dive into the peripheral, see [this article](https://interrupt.memfault.com/blog/fix-bugs-and-secure-firmware-with-the-mpu).

> NOTE: For the most part MPU faults will only trigger if the MPU has been enabled. However, there are a few memory access errors that will always result in a MemManage fault -- such as trying to execute from the `0xExxx.xxxx` address range.

The layout of the register looks like this:

![](img/cortex-m-fault/mmfsr.png)

where,

- `MMARVALID` - Indicates the address which triggered the MemManage fault is stored in the _MemManage Fault Address Register_ (**MMFAR**) - a 32 bit register located at `0xE000ED34`
- `MLSPERR` & `MSTKERR` - Indicates that a MemManage fault occurred during lazy state preservation or exception entry. This could happen if you are using an MPU region as a stack guard in your system
- `MUNSTKERR` - Indicates that a fault occurred while returning from an exception
- `DACCVIOL` - Indicates that a data access triggered the MemManage fault.
- `IACCVIOL` - Indicates that an attempt to execute an instruction triggered a MPU or Execute Never (XN) error.

## HardFault Status Register (HFSR) - 0xE000ED2C

This registers explains the reason a HardFault exception was triggered.

![](img/cortex-m-fault/hfsr.png)

There's not too much information in this register but we will go over the fields real quickly

- `DEBUGEVT` - Indicates that a debug event (i.e executing a breakpoint instruction) occurred while the debug subsystem was not enabled
- `FORCED` - This means a fault of configurable priority, the faults we just discussed [above](#cfsr) has been escalated to a hardfault. The exception handlers for configurable faults are not enabled by default so this is pretty common. If the exception handlers are enabled, a configurable fault may still escalate to a hardfault if the configurable fault occurred at a higher priority than the exception handler
- `VECTTBL` - Indicates a fault occurred because of an issue reading from an address in the vector table. This is pretty atypical but could happen if there is a bad address in the vector table.

{: #registers-prior-to-exception}

## Recovering Register State

To fix a fault, you will want to determine what code was running when the fault occurred. To do this we will want to recover the register state at the time of exception entry.

If you the fault you are using is reproducible and you are trying to look at it with a debugger you can manually add a breakpoint for the address which handles the exception in the vector table. Typically in GDB this will look something like

```
(gdb) break HardFault_Handler
```

However, let's discuss how you can instrument your code to make this recovery easier the next time an unexpected fault hits!

Upon exception entry some registers will always be automatically saved on the stack. Depending on whether or not an FPU is in use, either a [basic](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#basic-context-state-frame) or [extended](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#extended-context-state-frame) stack frame will be pushed by hardware.

Regardless, the very top of the stack frame will _always_ contain the same set of registers. We can represent this with C code as:

```c
typedef struct __attribute__((packed)) ContextStateFrame {
  uint32_t r0;
  uint32_t r1;
  uint32_t r2;
  uint32_t r3;
  uint32_t r12;
  uint32_t lr;
  uint32_t return_address;
  uint32_t xpsr;
} sContextStateFrame;
```

This register state will be pushed to the stack which was active prior to exception entry. ARM Cortex-M devices have [two stack pointers](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#stack-pointers-and-usage), `msp` & `psp`. Upon exception entry, the active stack pointer (`CONTROL.SPSEL`) is encoded in bit 2 of the `EXC_RETURN` value pushed to the link register. If the bit is set, the `psp` was active, else the `msp` was active. We can therefore put together a small shim assembly function that figures out the current sp (whose current layout will match `sContextStateFrame`) and pass that to a C function for further processing.

```c
#define HARDFAULT_HANDLING_ASM(_x)               \
  __asm volatile(                                \
      "tst lr, #4 \n"                            \
      "ite eq \n"                                \
      "mrseq r0, msp \n"                         \
      "mrsne r0, psp \n"                         \
      "b my_fault_handler_c \n"                  \
                                                 )
```

The `my_fault_handler_c` function will usually look something like this:

```c
// NOTE: If you are using CMSIS, the registers can also be accessed through
// CoreDebug->DHCSR & CoreDebug_DHCSR_C_DEBUGEN_Msk
#define HALT_IF_DEBUGGING()                              \
  do {                                                   \
    if ((*(volatile uint32_t *)0xE000EDF0) & (1 << 0)) { \
      __asm("bkpt 1");                                   \
    }                                                    \
  } while (0)

// Disable optimizations for this function so "frame" argument does not get optimized away
__attribute__((optimize("O0")))
void my_fault_handler_c(sContextStateFrame *frame) {
  // If and only if a debugger is attached, execute a breakpoint instruction so
  // we can take a look at what triggered the fault
  HALT_IF_DEBUGGING();

  // Logic for dealing with the exception. Typically:
  //  - log the fault which occurred for postmortem analysis
  //  - If the fault is recoverable,
  //    - clear errors and return back to Thread Mode
  //  - else
  //    - reboot system
}
```

## Recovering From A Fault

> DISCLAIMER: Typically, when a fault occurs you will just want to reset the system to put it back into a sane state. Reboots on embedded devices should be very quick and since there is no Memory Management Unit like there is on beefier processors, when a crash happens it's hard to be certain that other unexpected parts of the system were not corrupted.

Occasionally you may want to recover the system from a fault without rebooting it. For example, maybe you have one isolated RTOS task that just needs to be restarted instead of rebooting the entire system.

Let's quickly explore how we could implement a recovery mechanism that puts RTOS tasks which experience a UsageFault into an Idle loop and reboots the system otherwise.

We will use the
[Application Interrupt and Reset Control Register](https://interrupt.memfault.com/blog/arm-cortex-m-exceptions-and-nvic#application-interrupt-and-reset-control-register-aircr---0xe000ed0c) to reset the device if the fault is unrecoverable. We can easily implement this in `my_fault_handler_c` from above by adding some logic:

```c
void my_fault_handler_c(sContextStateFrame *frame) {
[...]
  volatile uint32_t *cfsr = (volatile uint32_t *)0xE000ED28;
  const uint32_t usage_fault_mask = 0xffff0000;
  const bool non_usage_fault_occurred = (*cfsr & ~usage_fault_mask) != 0;
  // the bottom 8 bits of the xpsr hold the exception number of the
  // executing exception or 0 if the processor is in Thread mode
  const bool faulted_from_exception = ((frame->xpsr & 0xFF) != 0);

  if (faulted_from_exception || non_usage_fault_occurred) {
    // For any fault within an ISR or non-usage faults let's reboot the system
    volatile uint32_t *aircr = (volatile uint32_t *)0xE000ED0C;
    *aircr = (0x05FA << 16) | 0x1 << 2;
    while (1) { } // should be unreachable
    }
[...]
```

Now let's get to the interesting part, how do we clean up our state and exit the fault handler if we want to recover the system?

There's a few things we will need to do:

- Clear any logged faults from the `CFSR` by writing 1 to each bit which is set
- Change the return_address to point to the function we want to go to upon function exit. In the example case it's `recover_from_task_fault`
- Scribble a known pattern over the `lr`. The function we are returning to will need to take special action (i.e like deleting the task or entering a `while (1)` loop). It can't just exit and branch to where we were before
- Reset the xpsr. Among other things the xpsr tracks the state of previous comparison instructions which were run and whether or not we are in the middle of a "If-Then" instruction block. The only bit that needs to remain set is the "T" field (bit 24) indicating the processor is in thumb mode[^11].

This winds up looking like:

```c
  // If it's just a usage fault, let's "recover"
  // Clear any faults from the CFSR
  *cfsr |= *cfsr;
  // the instruction we will return to when we exit from the exception
  frame->return_address = (uint32_t)recover_from_task_fault;
  // the function we are returning too should never branch
  // so set lr to a pattern that would fault if it did
  frame->lr = 0xdeadbeef;
  // reset the psr state and only leave the
  // "thumb instruction interworking" bit set
  frame->xpsr = (1 << 24);
```

You may recall from our [previous post](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#context-state-stacking), fault handlers can work just like regular c functions so after these changes we will exit from `my_fault_handler_c` and start executing whatever is in `recover_from_task_fault`.

> For those who want to walk through this actual example, check out the example with gdb [below](#usage-fault-recovery-example)

## Faults from Faults!

The astute observer might wonder what happens when a new fault occurs in the code dealing with a fault.
If you have enabled configurable fault handlers (i.e MemoryManagement, BusFault, or UsageFault), a fault generated in these handlers will trigger a Hardfault.

Once in the Hardfault Handler, the ARM Core is said to be operating at priority level -1. At this level or above, a fault will put the processor in an unrecoverable state where a reset is expected known as **Lockup**.

Typically, the processor will automatically reset the processor upon entering lockup but this is not a requirement per the specification. For example, you may have to enable a hardware watchdog for a reset to take place. It's worth double checking the reference manual for the MCU being used for clarification.

When a debugger is attached, lockup often has a different behavior. For example, on the NRF52840, "Reset from CPU lockup is disabled if the device is in debug interface mode".

Technically when a lockup happens, the processor will repeatedly fetch the same fixed instruction, 0xFFFFFFFE or the address which triggered the fault, in a loop until a reset occurs.

> Fun Fact: Whether or not some classes of MemManage Faults or BusFaults trigger a fault from an exception is actually configurable via the MPU_CTRL.HFNMIENA & CCR.BFHFNMIGN configurations.

## Automating the Analysis

### Instrumenting the code

Many Real Time Operating Systems (**RTOS**) targetting Cortex-M devices will add options to dump verbose fault information to the console upon crash. Some examples include Arm Mbed OS[^2] and Zephyr[^3]. This approach has a couple notable limitations:

- It bloats the code & data size of the binary image and consequently often gets disabled via compiler flags
- It requires a firmware update to improve or fix issues with the analyzers
- It requires an active console session be active to see what fault occurred and depending on the console setup in the system this can be flaky if the system is in a crashed state

### Debugger Plugins

Many embedded IDEs expose a system view that can be used to look at registers decoded into human readable descriptions. These leverage the CMSIS _System View Description_ (**SVD**) format[^4], a standardized XML file format for describing the memory mapped registers in a ARM MCU. Most silicon vendors expose this information on their own website or from ARMs website[^5] for download.

{: #pycortex-svd-gdb-setup}
You can even load these files in GDB using PyCortexMDebug[^6], a [gdb python](https://interrupt.memfault.com/blog/automate-debugging-with-gdb-python-api#getting-started-with-gdb-python) script .

To use the utility, all you need to do is update your `.gdbinit` to use PyPi packages from your environment (instructions [here](https://interrupt.memfault.com/blog/using-pypi-packages-with-GDB#3-append-syspath-to-gdbs-python)) and then run:

```bash
$ git clone git@github.com:bnahill/PyCortexMDebug.git
$ cd PyCortexMDebug
$ python setup.py install
```

When you next start gdb, you can source the `svd_gdb.py` script and use it to start inspecting registers.

```
(gdb) source cmdebug/svd_gdb.py
(gdb) svd_load <file_to_load.svd>
(gdb) svd
Available Peripherals:
    ...
	SCB:        System control block
    ...
(gdb) svd SCB
Registers in SCB:
    ...
	CFSR_UFSR_BFSR_MMFSR:      524288  Configurable fault status register
    ...
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
	IACCVIOL:     0  Instruction access violation flag
	DACCVIOL:     0  Data access violation flag
	MUNSTKERR:    0  Memory manager fault on unstacking for a return from exception
	MSTKERR:      0  Memory manager fault on stacking for exception entry.
	MLSPERR:      0
	MMARVALID:    0  Memory Management Fault Address Register (MMAR) valid flag
	IBUSERR:      1  Instruction bus error
	PRECISERR:    0  Precise data bus error
	IMPRECISERR:  0  Imprecise data bus error
	UNSTKERR:     0  Bus fault on unstacking for a return from exception
	STKERR:       0  Bus fault on stacking for exception entry
	LSPERR:       0  Bus fault on floating-point lazy state preservation
	BFARVALID:    0  Bus Fault Address Register (BFAR) valid flag
	UNDEFINSTR:   0  Undefined instruction usage fault
	INVSTATE:     1  Invalid state usage fault
	INVPC:        0  Invalid PC load usage fault
	NOCP:         0  No coprocessor usage fault.
	UNALIGNED:    0  Unaligned access usage fault
	DIVBYZERO:    0  Divide by zero usage fault
```

### Post-Mortem Analysis

The previous two approaches are only helpful if you have a debug or physical connection to the device. Once the product has shipped and is out in the field these strategies will not help you to triage what went wrong on devices.

One option is to log the fault register values at the time of crash to persistent storage and periocially collect or push the error logs. On the server side you will want to decode the register values collected and symbolicate any of the addresses collected.

For those who have [Memfault](https://memfault.com/features/error-analysis.html?utm_source=interrupt&utm_medium=link&utm_campaign=cortex-m-faults) integrated, this type of data can be automatically collected, transported and deduplicated to surface the biggest problems being hit. Here's a simple example of a bad memory access from the example app we will use in the next section:

![](img/cortex-m-fault/memfault-fault-analyzer.png)

{: examples}

## Examples

For this setup we will use:

- a nRF52840-DK[^7] (ARM Cortex-M4F) as our development board
- SEGGER JLinkGDBServer[^8] as our GDB Server.
- GCC 8.3.1 / GNU Arm Embedded Toolchain as our compiler[^9]
- GNU make as our build system

All the code can be found on the [Interrupt Github page](https://github.com/memfault/interrupt/tree/master/example/cortex-m-fault-debug) with more details in the `README` in the directory linked.

In the sections below we will walk through the analysis of a couple faults.

### Setup

Start a GDB Server:

```
JLinkGDBServer  -if swd -device nRF52840_xxAA
```

Follow the instructions [above](#pycortex-svd-gdb-setup) to setup support for reading SVD files from GDB, build, and flask the example app:

```
$ make
[...]
Linking library
Generated build/nrf52.elf
$ arm-none-eabi-gdb-py --eval-command="target remote localhost:2331" --ex="mon reset" --ex="load" --ex="mon reset" --se=build/nrf52.elf
$ source PyCortexMDebug/cmdebug/svd_gdb.py
$ (gdb) svd_load cortex-m4-scb.svd
Loading SVD file cortex-m4-scb.svd...
(gdb)
```

The app has eight different crashes you can configure by changing `FAULT_EXAMPLE_CONFIG` at compile time or by editing the value at runtime:

```
(gdb) break main
(gdb) continue
(gdb) set g_crash_config=1
(gdb) continue
```

### Exception Entry Fault

Let's take a look at the first example

```
Breakpoint 1, main () at ./cortex-m-fault-debug/main.c:180
180	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=0
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00000218 in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
(gdb) bt
#0  0x00000218 in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:91
#1  <signal handler called>
#2  0x00001468 in prvPortStartFirstTask () at ./cortex-m-fault-debug/freertos_kernel/portable/GCC/ARM_CM4F/port.c:267
#3  0x000016e6 in xPortStartScheduler () at ./cortex-m-fault-debug/freertos_kernel/portable/GCC/ARM_CM4F/port.c:379
#4  0x1058e476 in ?? ()
```

We can check the `CFSR` to see if there is any information about the fualt which occurred.

```
(gdb) p/x *(uint32_t*)0xE000ED28
$3 = 0x1
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
	IACCVIOL:     1  Instruction access violation flag
[...]
```

That's interesting! We hit a Memory Management instruction access violation fault even though we haven't enabled any MPU regions. From the CFSR, we know that the stacked frame is valid so we can take a look at that to see what it reveals:

```
(gdb) p/a *frame
$1 = {
  r0 = 0x0 <g_pfnVectors>,
  r1 = 0x200003c4 <ucHeap+604>,
  r2 = 0x10000000,
  r3 = 0xe0000000,
  r12 = 0x200001b8 <ucHeap+80>,
  lr = 0x195 <prvQueuePingTask+52>,
  return_address = 0xe0000000,
  xpsr = 0x80000000
}
```

We can clearly see that the executing instruction was `0xe0000000` and that the function we would have returned to after finishing executing the function was `prvQueuePingTask`.

From the ARMv7-M reference manual[^9] we can find:

> The MPU is restricted in how it can change the default memory map attributes associated with System space, that is, for addresses 0xE0000000 and higher. System space is always marked as XN, Execute Never.

So it does make sense we hit a memory management fault.

### Bad Address Read

```
(gdb) set g_crash_config=1
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00000218 in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
```

Again, let's take a look at the `CFSR` and see if it tells us anything useful.

```
(gdb) p/x *(uint32_t*)0xE000ED28
$13 = 0x8200
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
[...]
    PRECISERR:    1  Precise data bus error
[...]
    BFARVALID:    1  Bus Fault Address Register (BFAR) valid flag
```

Great, we have a precise bus fault which means the return address in the stack frame holds the instruction which triggered the fault and that we can read BFAR to determine what address we faulted on!

```
(gdb) svd/x SCB BFAR
Fields in SCB BFAR:
	BFAR:  0x0BADCAFE  Bus fault address

(gdb) p/a *frame
$16 = {
  r0 = 0x1 <g_pfnVectors+1>,
  r1 = 0x200003c4 <ucHeap+604>,
  r2 = 0x10000000,
  r3 = 0xbadcafe,
  r12 = 0x200001b8 <ucHeap+80>,
  lr = 0x195 <prvQueuePingTask+52>,
  return_address = 0x13a <trigger_crash+22>,
  xpsr = 0x81000000
}

(gdb) info line *0x13a
Line 123 of "./cortex-m-fault-debug/main.c" starts at address 0x138 <trigger_crash+20> and ends at 0x13e <trigger_crash+26>.

(gdb) list *0x13a
0x13a is in trigger_crash (./cortex-m-fault-debug/main.c:123).
118	  switch (crash_id) {
119	    case 0:
120	      illegal_instruction_execution();
121	      break;
122	    case 1:
===> FAULT HERE
123	      read_from_bad_address();
124	      break;
125	    case 2:
126	      access_disabled_coprocessor();
127	      break;
```

Great, so we have pinpointed the exact code which triggered the issue and can now fix it!

### Coprocessor Fault

```
Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:180
180	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=2
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00000218 in my_fault_handler_c (frame=0x20002d80) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
```

We can inspect `CFSR` to get a clue about the crash which took place

```
(gdb) p/x *(uint32_t*)0xE000ED28
$13 = 0x8200
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
[...]
	NOCP:         1  No coprocessor usage fault.
[...]
```

We see it was a coprocessor usage fault which tells us we either issued an instruction to a non-existent or disabled Cortex-M coprocessor such as the FPU. We know the frame contents are valid so we can inspect that to figure out where the fault originated:

```
(gdb) p/a *frame
$27 = {
  r0 = 0xe000ed88,
  r1 = 0x0 <g_pfnVectors>,
  r2 = 0x10000000,
  r3 = 0x0 <g_pfnVectors>,
  r12 = 0x200001b8 <ucHeap+80>,
  lr = 0x199 <prvQueuePingTask+52>,
  return_address = 0x114 <access_disabled_coprocessor+12>,
  xpsr = 0x81000000
}

(gdb) disassemble 0x114
Dump of assembler code for function access_disabled_coprocessor:
   0x00000108 <+0>:	ldr	r0, [pc, #16]	; (0x11c)
   0x0000010a <+2>:	mov.w	r1, #0
   0x0000010e <+6>:	str	r1, [r0, #0]
   0x00000110 <+8>:	dsb	sy
===> FAULT HERE
   0x00000114 <+12>:	vmov	r0, s0
   0x00000118 <+16>:	bx	lr
```

So we see there was a coprocessor fault issuing a FP instruction. The FPU is enabled using bits 20-23 of the [CPACR](https://interrupt.memfault.com/blog/cortex-m-rtos-context-switching#fpu-config-options) register located at `0xE000ED88`. A value of 0 indicates the extension is disabled. Let's check it:

```
(gdb) p/x (*(uint32_t*)0xE000ED88 >> 20) & 0xf
$29 = 0x0
```

We can cleary see the FP Extension is disabled. We will have to enable the FPU to fix our bug.

### Imprecise Fault

```
Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:182
182	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=3
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000021c in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
```

Let's inspect `CFSR`:

```
(gdb) p/x *(uint32_t*)0xE000ED28
$31 = 0x400
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
[...]
	IMPRECISERR:  1  Imprecise data bus error
[...]
```

Yikes, the error is imprecise. This means the stack frame will point to the general area where the fault occurred but **not** the exact instruction!

```
(gdb) p/a *frame
$32 = {
  r0 = 0x55667788,
  r1 = 0x11223344,
  r2 = 0x10000000,
  r3 = 0x30000000,
  r12 = 0x200001b8 <ucHeap+80>,
  lr = 0x199 <prvQueuePingTask+52>,
  return_address = 0x198 <prvQueuePingTask+52>,
  xpsr = 0x81000000
}
(gdb) list *0x198
0x198 is in prvQueuePingTask (./cortex-m-fault-debug/main.c:162).
157
158	  while (1) {
159	    vTaskDelayUntil(&xNextWakeTime, mainQUEUE_SEND_FREQUENCY_MS);
160	    xQueueSend(xQueue, &ulValueToSend, 0U);
161
==> Crash somewhere around here
162	    trigger_crash(g_crash_config);
163	  }
164	}
165
166	static void prvQueuePongTask(void *pvParameters) {
```

If the crash was not readily reproducible we would have to inspect the code around this region and hypothesize what looks suspicious but [recall](#cortex-m3-m4-debug-trick) there is a trick we can use for Cortex-M4 to make all faults precise. Let's enable that and re-examine:

```
(gdb) mon reset
Resetting target
(gdb) c
Continuing.

Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:182
182	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=3
==> Make all memory stores precise at the cost of performane
(gdb) set *(uint32_t*)0xE000E008=(*(uint32_t*)0xE000E008 | 1<<1)
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000021c in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
(gdb) p/a *frame
$33 = {
  r0 = 0x55667788,
  r1 = 0x11223344,
  r2 = 0x10000000,
  r3 = 0x30000000,
  r12 = 0x200001b8 <ucHeap+80>,
  lr = 0x199 <prvQueuePingTask+52>,
  return_address = 0xfa <bad_addr_double_word_write+10>,
  xpsr = 0x81000000
}
(gdb) list *0xfa
0xfa is in bad_addr_double_word_write (./cortex-m-fault-debug/main.c:92).
90	void bad_addr_double_word_write(void) {
91	  volatile uint64_t *buf = (volatile uint64_t *)0x30000000;
==> FAULT HERE
92	  *buf = 0x1122334455667788;
93	}
(gdb)
```

Awesome, that saved us some time ... we were able to determine the exact line that caused the crash!

### Fault Entry Exception

```
Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:182
182	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=4
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000021c in my_fault_handler_c (frame=0x1fffffe0) at ./cortex-m-fault-debug/startup.c:91
91	  HALT_IF_DEBUGGING();
```

Let's take a look at `CFSR` again to get a clue about what happened:

```
(gdb) p/x *(uint32_t*)0xE000ED28
$39 = 0x1000
(gdb) svd SCB CFSR_UFSR_BFSR_MMFSR
Fields in SCB CFSR_UFSR_BFSR_MMFSR:
[...]
	STKERR:       1  Bus fault on stacking for exception entry
```

There are two really important things to note when a stacking exception occurs:

1. The `$sp` will always reflect the correct adjusted position as if the hardware successfully stacked the registers. This means you can find the `$sp` prior to exception entry by adding the adjustment value.
2. Depending on what access triggers the exception, the stacked frame may be partially valid. For example, maybe the last store of triggers of the hardware stacking triggers the fault. However, the **order** the hardware stacks registers in is **not** defined. So when inspecting the frame assume the values you are looking at may be incorrect!

Taking this knowledge into account, let's take a look at where the stack frame is at:

```
(gdb) p frame
$40 = (sContextStateFrame *) 0x1fffffe0
```

Interesting, if we look up the memory map of the NRF52[^10], we will find that RAM starts at 0x20000000 and that the stack pointer location, `0x1fffffe0` is right below that in an undefined memory region. This must be why we faulted! We see that the stack pointer is 32 bytes below RAM, the size of the frame the hardware stacks which tells us that unfortunately none of the values will be valid.

We can try to walk up the stack to get some clues:

```
(gdb) x/a 0x20000000
0x20000000 <uxCriticalNesting>:	0x3020100
(gdb)
0x20000004 <g_crash_config>:	0x7060504
(gdb)
0x20000008 <xQueue>:	0xb0a0908
(gdb)
0x2000000c <s_buffer>:	0xf0e0d0c
(gdb)
0x20000010 <s_buffer+4>:	0x13121110
(gdb)
0x20000014 <s_buffer+8>:	0x17161514
(gdb)
0x20000018 <pxCurrentTCB>:	0x1b1a1918
(gdb)
0x2000001c <pxDelayedTaskList>:	0x1f1e1d1c
(gdb)
0x20000020 <pxOverflowDelayedTaskList>:	0x23222120
```

It looks like the RAM has a pattern of sequentially increasing values _and_ that the RAM addresses map to different variables in our code (i.e `pxCurrentTCB`). This suggests we overflowed the stack we were using and started to clobber RAM in the system until we ran off the end of RAM!

> NOTE: To catch this type of failure sooner consider using a [MPU Region](https://interrupt.memfault.com/blog/fix-bugs-and-secure-firmware-with-the-mpu#catch-stack-overflows-with-the-mpu)

Since the crash is reproducible, let's leverage a watchpoint and see if we can capture the stack corruption in action! The syntax for this is a little weird in gdb but we will add a watchpoint for any access near the bottom of RAM, `0x2000000c`:

```
Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:182
182	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=4
(gdb) watch *(uint32_t*)0x2000000c
Hardware watchpoint 9: *(uint32_t*)0x2000000c
```

> NOTE: Sometimes it will take a couple tries to chose the right RAM range to watch. It's possible an area of the stack never gets written to and the watchpoint never fires or you chose to watch a variable that gets updated many many times before the actual failure. In this example I chose to not watch 0x20000000 because that maps to a FreeRTOS variable, `uxCriticalNesting` which is updated many times.

Let's continue and see what happens:

```
Hardware watchpoint 9: *(uint32_t*)0x2000000c

Old value = 0
New value = 12
0x000000c0 in stkerr_from_psp () at ./cortex-m-fault-debug/main.c:68
68	    big_buf[i] = i;
(gdb) bt
#0  0x000000c0 in stkerr_from_psp () at ./cortex-m-fault-debug/main.c:68
#1  0x00000198 in prvQueuePingTask (pvParameters=<optimized out>) at ./cortex-m-fault-debug/main.c:162
#2  0x00001488 in ?? () at ./cortex-m-fault-debug/freertos_kernel/portable/GCC/ARM_CM4F/port.c:703
Backtrace stopped: previous frame identical to this frame (corrupt stack?)
(gdb) list *0xc0
0xc0 is in stkerr_from_psp (./cortex-m-fault-debug/main.c:68).
63	  extern uint32_t _start_of_ram[];
64	  uint8_t dummy_variable;
65	  const size_t distance_to_ram_bottom = (uint32_t)&dummy_variable - (uint32_t)_start_of_ram;
66	  volatile uint8_t big_buf[distance_to_ram_bottom - 8];
67	  for (size_t i = 0; i < sizeof(big_buf); i++) {
68	    big_buf[i] = i;
69	  }
70
71	  trigger_irq();
72	}
```

Great, we've found a variable located on the stack `big_buf` being updated. It must be this function call path which is leading to a stack overflow. We can now inspect the call chain for big stack allocations!

{: #usage-fault-recovery-example}

### Recovering from a UsageFault **without** a SYSRESET

```
Breakpoint 4, main () at ./cortex-m-fault-debug/main.c:188
188	  xQueue = xQueueCreate(mainQUEUE_LENGTH, sizeof(unsigned long));
(gdb) set g_crash_config=5
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0x00000228 in my_fault_handler_c (frame=0x200005e8 <ucHeap+1152>) at ./cortex-m-fault-debug/startup.c:94
94	  HALT_IF_DEBUGGING();
```

We have entered the breakpoint in the fault handler. We can step over it and confirm we fall through to the `recover_from_task_fault` function.

```
(gdb) break recover_from_task_fault
Breakpoint 12 at 0x1a8: file ./cortex-m-fault-debug/main.c, line 181.
(gdb) n
108	  volatile uint32_t *cfsr = (volatile uint32_t *)0xE000ED28;
(gdb) c
Continuing.

Breakpoint 12, recover_from_task_fault () at ./cortex-m-fault-debug/main.c:181
181	void recover_from_task_fault(void) {

(gdb) list *recover_from_task_fault
0x1a8 is in recover_from_task_fault (./cortex-m-fault-debug/main.c:181).
181	void recover_from_task_fault(void) {
182	  while (1) {
183	    vTaskDelay(1);
184	  }
185	}
```

If we continue from here we will see the system happily keeps running because the thread which was calling the `trigger_crash` function is now parked in a while loop. In the while loop you could add some code to delete and/or restart the FreeRTOS code as well.

## Closing

I hope this post gave you a useful overview of how to debug a Hardfault on a Cortex-M MCU and that maybe you even learned something new!

Are the tricks you like to use that I didn't mention or other topics about faults you'd like to learn more about?
Let us know in the discussion area below!

See anything you'd like to change? Submit a pull request or open an issue at [Github](https://github.com/memfault/interrupt)

{:.no_toc}

## References

[^1]: See ARMv7-M and interworking support
[^2]: [MBed OS fault handler](https://github.com/ARMmbed/mbed-os/blob/2e96145b7607de430235dd795ab5350c1d4d64d7/platform/source/TARGET_CORTEX_M/mbed_fault_handler.c#L44-L81)
[^3]: [Zephyr ARM fault handler](https://github.com/intel/zephyr/blob/e09a04f0689fd29aa909cc49ee94fd129798f986/arch/arm/core/fault.c#L55-L275)
[^4]: [CMSIS-SVD](https://arm-software.github.io/CMSIS_5/SVD/html/index.html)
[^5]: [CMSIS Software Packs](https://developer.arm.com/tools-and-software/embedded/cmsis)
[^6]: [PyCortexMDebug](git@github.com:bnahill/PyCortexMDebug.git)
[^7]: [See "3.3.9 Auxiliary Bus Fault Status Register"](http://infocenter.arm.com/help/topic/com.arm.doc.ddi0489b/DDI0489B_cortex_m7_trm.pdf)
[^8]: Link lauterbach, arm, segger ETM utilities
[^9]: [See B3.5.1 "Relation of the MPU to the system memory map"](https://static.docs.arm.com/ddi0403/eb/DDI0403E_B_armv7m_arm.pdf)
[^10]: [See "4.2.3 Memory map"](https://infocenter.nordicsemi.com/pdf/nRF52840_PS_v1.0.pdf)
[^11]: [See "B1.5.5 Reset behavior" & "B1.4.2 The special-purpose program status registers, xPSR"](https://static.docs.arm.com/ddi0403/eb/DDI0403E_B_armv7m_arm.pdf)
[^11]: [See "5.3.6.8 Reset behavior"](https://infocenter.nordicsemi.com/pdf/nRF52840_PS_v1.0.pdf)
