#!/bin/bash

echo "picelf_x86-64.sh by @bao7uo" >&2
echo
[ -n "$1" ] && echo "$1" | grep -E "^([a-fA-F0-9]{2})+$" >/dev/null
[ "$?" != "0" ] && \
    echo -e "Takes a single parameter - \
x86 64-bit position independent shellcode in the format: \n\
b801000000bf01000000ba0c000000488d3502000000eb0c48656c6c6f20776f726c640a0f05\n\
Can be produced using: cat shellcode.bin | xxd -p -c \$(wc -c shellcode.bin)\n"

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

elf=""

# bits 64
# org 0x40000

# ehdr:
# db 0x7f, "ELF", 2, 1, 1, 0                         ; e_ident
elf+="7f"
elf+=$(echo -en "ELF" | xxd -p -c 3)
elf+="02010100"

# nulls:
## dq 0x00
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
elf+="0200"
# dw  0x3e                                            ; e_machine
elf+="3e00"
# dd  0x01                                            ; e_version
elf+="01000000"
# dq _start                                           ; e_entry
elf+="7800400000000000"
# dq  phdr - $$                                       ; e_phoff
elf+="4000000000000000"
# dq  0x00                                            ; e_shoff
elf+="0000000000000000"
# dd  0x00                                            ; e_flags
elf+="00000000"
# dw  e_ehsize                                        ; e_ehsize
elf+="4000"
# dw  e_phentsize                                     ; e_phentsize
elf+="3800"
# dw 0x01                                             ; e_phnum  
elf+="0100"
# dw  0x00                                            ; e_shentsize
elf+="0000"
# dw  0x00                                            ; e_shnum
elf+="0000"
# dw  0x00                                            ; e_shstrndx
elf+="0000"
# e_ehsize  equ  $ - ehdr

# phdr:
#  dd  0x01                                           ; p_type
elf+="01000000"
# dd  0x05                                            ; p_flags
elf+="05000000"
# dq  0x00                                            ; p_offset
elf+="0000000000000000"
# dq  $$                                              ; p_vaddr
elf+="0000400000000000"
# dq  $$                                              ; p_paddr
elf+="0000400000000000"
# dq  elf_size                                        ; p_filesz
elf+="elf_size________"
# dq  elf_size                                        ; p_memsz
elf+="elf_size________"
# dq  0x1000                                          ; p_align
elf+="0010000000000000"
# e_phentsize equ  $ - phdr

## section .text
## global _start
## _start:

## BEGIN Position Independent Code

[ -z "$1" ] && elf+="9090909090909090"

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

[ -z "$1" ] && elf+="9090909090909090"

[ -n "$1" ] && elf+="$1" 

## END Position Independent Code

# jmp nulls
elf+="e9jmp_null"

## section .data
elf+="00"

# elf_size  equ  $ - $$
elf_size=${#elf}
elf_size=$(( elf_size / 2 ))

# 32 bits + 1 (so it's like 0) - elf_size + e_ident + final null byte 
jmp_nulls=$(( 4294967295 + 1 - elf_size + 8 + 1 ))
jmp_nulls=$(printf "%08x" $jmp_nulls | tac -rs ..)
elf=${elf//jmp_null/$jmp_nulls}

elf_size=$(printf "%016x" $elf_size | tac -rs ..)
elf=${elf//elf_size________/$elf_size}

echo "temp=\"picelf.bin\"; touch \$temp; chmod +x \$temp; echo -n $elf | xxd -r -p > \$temp; echo \$temp"
echo
elf=$(echo -n $elf | sed 's/../\\x&/g;s/:$//')
echo "temp=\$(mktemp); chmod +x \$temp; echo -en \"$elf\" > \$temp; \$temp ; echo \$?; rm \$temp"
