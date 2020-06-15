#!/bin/bash

# Copyright (c) 2020 Paul Taylor @bao7uo

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

echo "picelf_x86-64.sh by @bao7uo" >&2
echo

elf=""

# bits 64
# org 0x40000

# ehdr:
# db 0x7f, "ELF"                                      ; e_ident
elf+="7f"
elf+=$(echo -en "ELF" | xxd -p -c 3)
# ident_spare:
## db 2, 1, 1, 0                                      ; e_ident (continued)
elf+="fefefefe"                    # IGNORED

# dq 0x00
## elf+="0000000000000000"
# push byte +0x3c - EXIT
elf+="6a3c"
# pop rax
elf+="58"
# push byte +0x41 - $? EXIT CODE
elf+="6a41" 
# pop rdi
elf+="5f"
# syscall
elf+="0f05"

# dw  0x02                                            ; e_type
elf+="0200"                        # REQUIRED
# dw  0x3e                                            ; e_machine
elf+="3e00"                        # REQUIRED
# dd  0x01                                            ; e_version
elf+="9090eb10"                    # IGNORED
# dq _start                                           ; e_entry
elf+="1400400000000000"            # REQUIRED
# dq  phdr - $$                                       ; e_phoff
elf+="3800000000000000"            # REQUIRED
# dq  0x00                                            ; e_shoff
elf+="9090909090909090"            # IGNORED
# dd  0x00                                            ; e_flags
elf+="90909090"                    # IGNORED
# dw  e_ehsize                                        ; e_ehsize
elf+="eb1a"                        # IGNORED
# dw  e_phentsize                                     ; e_phentsize
elf+="3800"                        # REQUIRED
                                                                         # phdr:
# dw 0x01                                             ; e_phnum          ; p_type    dd  0x01
elf+="0100"                        # REQUIRED
# dw  0x00                                            ; e_shentsize
elf+="0000"                        # IGNORED
# dw  0x00                                            ; e_shnum          ; p_flags    dd  0x05
elf+="0100"                        # IGNORED
# dw  0x00                                            ; e_shstrndx        
elf+="0000"                        # IGNORED
# e_ehsize  equ  $ - ehdr

# dq  0x00                                            ; p_offset
elf+="0000000000000000"            # REQUIRED
# dq  $$                                              ; p_vaddr
elf+="0000400000000000"            # REQUIRED
# dq  $$                                              ; p_paddr
elf+="909090909090eb10"            # IGNORED
# dq  elf_size                                        ; p_filesz
elf+="elf_size________"            # REQUIRED
# dq  elf_size                                        ; p_memsz
elf+="elf_size________"            # REQUIRED
# dq  0x1000                                          ; p_align
elf+="9090909090909090"            # IGNORED
# e_phentsize equ  $ - phdr

## section .text
## global _start
## _start:

shellcode_start=${#elf}

## BEGIN Position Independent Code

# mov rax, 0x01
[ -z "$1" ] && elf+="b801000000"
# mov rdi, 0x01
[ -z "$1" ] && elf+="bf01000000"
# mov rdx, 0x0c
[ -z "$1" ] && elf+="ba0c000000"
# lea rsi, [rip + 0x02]     # +2 gives string location
[ -z "$1" ] && elf+="488d3502000000"         
# jmp 0x0c                  ; string length
[ -z "$1" ] && elf+="eb0c" 
[ -z "$1" ] && elf+=$(echo -en "Hello world\n" | xxd -p -c 12)
# syscall
[ -z "$1" ] && elf+="0f05"

[ -n "$1" ] && elf+="$1" 

## END Position Independent Code

shellcode=${elf:$shellcode_start:$(( ${#elf} - $shellcode_start ))}

# jmp nulls
elf+="e9jmp_null"

# elf_size  equ  $ - $$
elf_size=${#elf}
elf_size=$(( elf_size / 2 ))

# 32 bits + 1 (so it's like 0) - elf_size + e_ident + final null byte 
jmp_nulls=$(( 4294967295 + 1 - elf_size + 8 ))
jmp_nulls=$(printf "%08x" $jmp_nulls | tac -rs ..)
elf=${elf//jmp_null/$jmp_nulls}

elf_size=$(printf "%016x" $elf_size | tac -rs ..)
elf=${elf//elf_size________/$elf_size}

[ -n "$1" ] && echo "$1" | grep -E "^([a-fA-F0-9]{2})+$" >/dev/null
[ "$?" != "0" ] && \
    echo -e "Takes a single parameter - \
x86 64-bit position independent shellcode in the format: \n\
$shellcode\n\
Can be produced using: cat shellcode.bin | xxd -p -c \$(wc -c shellcode.bin)\n"

echo "temp=\"picelf.bin\"; touch \$temp; chmod +x \$temp; echo -n $elf | xxd -r -p > \$temp; echo \$temp"
echo
elf=$(echo -n $elf | sed 's/../\\x&/g;s/:$//')
echo "temp=\$(mktemp); chmod +x \$temp; echo -en \"$elf\" > \$temp; \$temp ; echo \$?; rm \$temp"
