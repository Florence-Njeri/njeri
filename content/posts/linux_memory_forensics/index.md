## Introduction to Linux Memory Forensics

**By Sonia Seddiki**

digital forensics and incidence response 

## Digital Forensics

Digital Forensics is the comprehensive process of identifying, preserving, extracting, and documenting computer evidence for use in a court of law or an internal investigation. 

Includes analysis of the:

- Memory - involves analyzing a amemory dump, hibernation files stored on disk i.e swap files

- Disk- involves investigating if attackers deleted smth on the disk/ hard drive.  (ext4, XFS, Btrfs filesystems). Looking for deleted files, hidden partitions, and file system metadata.

- Network - Analyzing packet captures (PCAP files)  to see how a system was breached.

### Memory Forensics

Involes identifying anomalous behaviour in the computers volatile memory. Because RAM is cleared when a computer is powered off, memory forensics must happen while the system is running or by analyzing the memory dump.

**Why is having direct access to memory messy?**


**Why use volatile memory**

Separation of memory usage by diff programs so the programs don't overwrite the OS. Virtual and physical memories are mapped.

**When swap memory to disk**
The investigator uses a tool like **LiME (Linux Memory Extractor)** or **AVML** to dump the RAM to a file on a USB drive. If they shut down the computer to image the hard drive first, they would lose all the running processes and encryption keys.

**Note**: The tools only save the `.bin` or `.raw` file directly back to the USB drive, not to the computer's internal hard drive.

**Kernel Space vs User Space**

This depends on whether the system is a 32 bit or 64 bit system


### 1. 32-bit Linux System

In a 32-bit system, the total addressable memory is $2^{32}$, which equals **4 GB**. Linux traditionally splits this exactly into two parts:

*   **User Space:** Starts at address **`0x00000000`** and goes up to **`0xBFFFFFFF`** (The first 3 GB).
*   **Kernel Space:** Starts at address **`0xC0000000`** and goes up to **`0xFFFFFFFF`** (The last 1 GB).

### 64-bit Linux System
Kernel space, where the Linux kernel sits, starts at the very top of the memorary upto `0xFFFF800000000000` and the user memory is at the very bottom

| Architecture | User Space Range | Kernel Space Range | Common Split |
| :--- | :--- | :--- | :--- |
| **32-bit** | `0x00000000` $\rightarrow$ `0xBFFFFFFF` | `0xC0000000` $\rightarrow$ `0xFFFFFFFF` | 3GB User / 1GB Kernel |
| **64-bit** | Lower Half (starts at `0x0...`) | Upper Half (starts at `0xFFFF...`) | Massive gap in middle |

## Memory paging

The physiscal memory is separated into fioxed size pages. **Offsets** are indexes that point to where your data resides in memory.


## TOOL: Volatility 3

## Steps of Memory Forensics

Step 1. List all the processes

`vol -f firefox.bin linux.pslist.PsList`

Step 2. `task_struct`

Shows all the info about a task i.e PID, name, parent/siblings, state, tasks (gives info and points to the next task on the list and the last task on the list points back to the first one) etc

--------

Each program has an assigned memory space

Kernel linux management