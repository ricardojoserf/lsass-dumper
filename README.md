# Dumping Lsass with C++ (and style)

Dumping the Lsass process to get the passwords stored in memory in a Windows machine is one of the most common uses of Mimikatz. However, there are stealthier methods to do this, such as using custom code. Doing so, we can customize the dump file name, using the hostname and date as name and harmless extensions such as ".txt" instead of ".dmp".


## Goal

We will use C++ to create a program that dumps the lsass.exe process in the stealthier way we can.  

Without input arguments it creates a dump file with the hostname and date as name and the ".txt" extension (*hostname_DD-MM-YYYY-HHMM.txt*). With input arguments it will use the first one as path for the file.  

To try to be stealthier, we will not use the "lsass" or "SeDebugPrivilege" strings and will try not to use the "minidump" string when possible.

The code is explained [in here](https://ricardojoserf.github.io/lsassdumper/).
