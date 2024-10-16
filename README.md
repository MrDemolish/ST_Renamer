**Ghidra Script for automatically change about 1121 function names in game named Submarine Titans**

Must rename function under address 6AE780 (this is for Steam version of a game) to "Debug_Info"

Tested on Ghidra 11.2

Script is searching for every Debug_Info call, then fetches it's sixth parameter and extracts then parses string from it, and then renames function that contain that Debug_Info call to the extracted and parsed info from string (sixth parameter).

Functions will have much more friendly name (previously FUN_ named functions):

![image](https://github.com/user-attachments/assets/c69a81e4-1847-43ac-b717-f392020220f0)


Instructions:
1. In Ghidra go to Window->Script Manager
2. Create New Script (Jython), name it as You want
3. Execute it
