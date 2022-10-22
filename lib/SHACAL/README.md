# SHACAL

SHACAL-1 is the name of the ARX block cipher that is used in the SHA-1 hash function. 
It uses keys of up to 512 bits and has a block size of 160 bits.
SHACAL-1 was submitted to the New European Schemes for Signatures, Integrity and Encryption (NESSIE) project as a potential crypt primitive. 
It was selected for the second phase of the project but was ultimately not recommended due to concerns with its key schedule.
At this stage I have not been able to track down the submission paper so I have based my implementation solely off the SHA-1 documentation.
I'm not certain that the key schedule for the SHACAL submission is the same as the message schedule of SHA-1.