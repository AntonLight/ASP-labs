# Pipe to cli

This folder has service similar to telnet/ssh server

## PipeToCli

That dir contains server that redirect socket input to shell and prints the results back to socket output stream.

- _PipeToCli.cpp_ - entry point of the server
- _Server.hpp_ launches the network server and performing stream redirection
- _Shell.hpp_ is a r/w interface for the windows shell

## ShellService

Code for controlling windows service, something very similar to the MSDN example

## SockClient

Basic client that can send (e.g shell commands) and return the output. Behavior is similar to netcat.
