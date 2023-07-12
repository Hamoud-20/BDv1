# BDv1

Features

1. Network connections display:
The tool displays a table of network connections on the system, which includes information such as local and remote addresses, connection status, process ID, process name, and duration of connection. This can help system administrators and security analysts monitor network activity and identify any suspicious connections or activity.

2. Create a baseline:
The tool allows users to create a baseline of running processes and services on their system and save it to a JSON file. This baseline can serve as a reference point for future comparisons to detect any changes in the system. The baseline includes information such as process ID, name, command line, username, CPU and memory usage, parent process ID, and open ports.

3. Comparison of the current state with the baseline:
The tool can compare the current state of running processes and services with a previous baseline to detect any changes. If there are differences, it saves the results to a CSV file and prompts the user to display the process tree of the current state. This feature can help system administrators and security analysts identify any unauthorized or suspicious changes to the system.

4. Display process tree:
The tool can display a process tree of specified processes using the `graphviz` library. This can help users visualize the relationship between processes and identify any potential issues or problems in the system.

5. Menu of options:
The tool provides a menu of options for the user to choose from, making it easy to navigate and use. This feature allows users to easily access and utilize the various functions of the tool, making it more user-friendly and efficient.
 
Overall, the process baseline tool is a powerful and useful tool for system administrators and security analysts to monitor and detect any changes in running processes and services on a system. The tool's various features make it easy to use and navigate, while providing valuable insights into system activity and potential security issues.
# Installation
Step 1:
```
https://github.com/Hamoud-20/BDv1.git
```
Step 2:
```
pip install -r requirements.txt
```

# Usage
```
 python BDv1.py
```
