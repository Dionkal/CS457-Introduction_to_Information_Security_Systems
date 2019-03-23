## **CS457 Assignment 1 Server Client Key Exchange**

### INTRODUCTION

In this assignment you are going to develop, step-by-step, a simple symmetric key
exchange mechanism, using C, for a secure chat server/client scenario, using the
OpenSSL toolkit. The purpose of this assignment is to provide you the opportunity
to get familiar with public key (RSA) and symmetric key (AES) cryptography and the
very popular general-purpose cryptography toolkit, OpenSSL. Also,you will be able
to acquire hands-on experience in implementing simple cryptographic applications.
The tool will provide RSA encryption/decryption in order to exchange AES keys and
establish a secure communication channel using the OpenSSL toolkit. Once the secure
channel is established, the server and the client can securely communicate using
encrypted messages.

### **IMPORTANT:**

The default server port is 3613. However, if many students execute the server on
the same CSD machine this will be a conflict. If you run your server on CSD's
machines, change the port with your AM, as stated in the exercise description.

### DEBUG MODE:

If you want to run it in debug mode uncomment the #define DEBUG line in cs457_crypto.c
for a more verbose output


### SAMPLE EXECUTION:

	`tty1 $ ./Server/server [-p <port>]`
	`tty2 $ ./Client/client -i 127.0.0.1 -p 3613 -m hello_friend`


## **CS457 Assignment 2 AccessControl Logging Tool**


### INTRODUCTION

In this assignment you are going to develop in C, an ​access control logging system​. This system will keep track of all file accesses and modifications. Every
such operation will generate an entry in a log file, stored for further investigation by a separate high privileged process. For this assignment you will need to
use LD_PRELOAD which gives the ability to instruct the linker to bind symbols provided by a shared library before other libraries. This way, you are going to override
the C standard library functions that handle file accesses and modifications (fopen,fwrite) with your own versions in order to extend their functionality. You will
also test your logging system against a ransomware, so your access control logging needs to be able to detect ransomware behavior.


### EVENT LOGGING

As a first task, you need to develop a shared library (logger.so) which overrides (usingLD_PRELOAD) the standard I/O library of C in order to get and log the needed information for each file access before continuing with the standard I/O operation. Each entry (row) has to follow the following format (columns):

a. **UID**​: Unique ID (integer) assigned to the user by the system.
b. **File name**​: The path and name of the accessed file.
c. **Date**​: The date this action occurred.
d. ​**Time​**: The time this action occurred.
e. **Type**​: This field describes whether the corresponding file was opened for read or write. It prints 0 for the creation of a file, 1 if the action performed to this file was an open and 2 if it was a write.
f. **Action denied​**: This field reports if the action was denied to the user with no access privileges. It prints 1 if the action was denied to the user, or 0 otherwise.
g. **Fingerprint​**: This field reports the digital fingerprint of the file the time the event occurred. This digital fingerprint is the hash value of the file contents.


#### IMPORTANT:

**FILE NAMES:** File paths and names must not exceed the BUFSIZE - 1 bytes in length. If the size causes errors then go to logger.c and change it
	`/* Buffer size*/`
	`#define BUFSIZE 256`


**Note:** Fopen logs access denied when errno is set to EACCES, whereas fwrites logs access denied whenever it fails.
Also note that frwite doesn't update the fingerprint of the file. The fingerprint will change only after the user closes
the file with fclose.


**RUNNING:** In order to run demo with the modified shared object you need to type the following command:

	`tty1 $ LD_PRELOAD=./logger.so ./demo`


### LOG MONITORING

Develop a separate monitoring application (monitor.c), responsible for monitoring the logs created by Event logger (Task 1).

1. Parses the log generated from Event logger in Task1 and extracts all incidents where malicious users tried to access multiple files without permissions. Inparticular, as an output, it prints all users that tried to access more than 10 different files.
