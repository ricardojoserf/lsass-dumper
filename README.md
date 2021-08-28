# Customizing Lsass Dumps with C++

We will use C++ to create a program that dumps the lsass.exe process in the stealthier way we can.  

Without input arguments it creates a dump file with the hostname and date as name and the ".txt" extension (*hostname_DD-MM-YYYY-HHMM.txt*). With input arguments it will use the first one as path for the file.  

To try to be stealthier, we will not use the "lsass" or "SeDebugPrivilege" strings and will try not to use the "minidump" string when possible. The code is explained [in here](https://ricardojoserf.github.io/lsassdumper/).


## Usage

The fastest way to use it is to right-click the file and click "Run as Administrator": 

![im1](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image1.png?raw=true)

This generates a file with the hostname ("DESKTOP-MA54241") and the date (28/08/2021) as name and with extension ".txt":

![im2](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image2.png?raw=true)

If we execute it from a command line we can choose any name or path:

![im3](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image3.png?raw=true)

The file is generated correctly:

![im4](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image4.png?raw=true)

Then we can parse these dump files with Mimikatz, as it does not care about the extension:

![im5](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image5.png?raw=true)

![im6](https://github.com/ricardojoserf/ricardojoserf.github.io/blob/master/images/custom-lsass-dumper/image6.png?raw=true)
