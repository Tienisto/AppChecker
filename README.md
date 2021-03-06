# AppChecker - Track the trackers

> Jost Alemann, Niklas Baier, Marcus Streuber, Tien Dô Nam, Luca Peters

### Requirements

- Python 3 (should be preinstalled in Linux)
- Java 11 or newer
    - **Debian / Ubuntu:** sudo apt-get install openjdk-11-jdk
    - **Manjaro:** pacman -Syu jdk-openjdk

### Quickstart

**ONLY AVAILABLE IN RELEASE**

Run this script if you want to use the included dependencies.
It does not work immediately if you clone this repo because the dependencies are not part of it.

`python quickstart.py -a <path to apk>`

### Advanced

Run this script if you want to use your external dependencies (e.g. newer version of ghidra).

`python main.py -a <path to apk> -g <path to ghidra> -t <path to apktool> -d <path to dex2jar>`

### Output

You can add `-o <path to output>` choose where to save **result.txt**, **result.json** and **result.html**.

If not specified, the default path **&lt;script location>/output** will be used.

### Experimental Feature

You can also add `-f` to activate the ghidra deep search option.
The analyse duration will be much longer but maybe ghidra finds more hidden trackers.

### Problems

If you get a **Permission Denied** error, then you should make them executable:

`chmod -R +x <script location>/dependencies`

If you get a **FileNotFoundException** (tracker.json cannot be found), then you are in the wrong directory

`cd <script location>`