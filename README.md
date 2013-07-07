# Message Sender for Monitoring System

## Compile instruction:
Add option `-lnet` and `-lcrypto` when compiling.

## Log sender usage:
Use `ipcs -q` to list the created message queues.

Use `ipcrm -q <msqid>` to remove message queues.
