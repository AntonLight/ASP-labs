# Dll injection

This directory contains applications necessary for performing dll injection. 

## DllInject

It has the injector itself. Should work both on 32/64 application (but should be compiled with the same bitness as a target one).

High-level injection functions defined in _injector.hpp_. It is able inject/call code and also dump some memory. Shellcode generation is separated in _shellcode.hpp_ and _utils.asm_. The last one can find base of the kernel and function of the process.

Injection itself performed in the following way:
1. VirtualAllocEx in target
2. Write shellcode via WriteProcessMemory
3. Call it via CreateRemoteThread

## DummyApp

Application for injection testing. It does nothing but sleep imitating real application

## SimpleShared

It has simple dll payload that prints status of attachment

Contains 
