# Log Analyzer Tool

The Log Analyzer Tool is a Python-based application designed to help you analyze log files for suspicious activities such as malware, unauthorized access, phishing attempts, file tampering, security breaches and more. The tool works on macOS, Windows, and Linux. It features a user-friendly GUI and generates clear reports with graphs for easy interpretation.


![Log_analyzer](images/image_1.png) 

## Features

- Analyze log files for various suspicious activities.
- Provides recommended actions for detected issues.
- Allows adding new patterns and corresponding remedies.
- Generates a graphical visualization of detected issues.
- Easy-to-use graphical user interface for selecting log files and running scans.

## Requirements

- Python 3.x
- Required Python libraries:
  - `matplotlib`
  - `tkinter` (macOS and Linux only)
  - `numpy`
- Virtual environment (recommended)

## Installation

### Clone the repository:

    git clone https://github.com/Rishikesh-khot/Log_analyzer.git
    cd Log_analyzer
    
### For macOS and Linux

1. Ensure Python 3.x is installed. If not, install it:

    ```bash
    sudo apt-get install python3 python3-pip   # For Debian-based systems
    sudo pacman -S python python-pip          # For Arch-based systems
    brew install python                       # For macOS using Homebrew
    ```
2. Create a Virtual Environment:

 ```bash
For Linux/Macos:
python3 -m venv venv
source venv/bin/activate

For Windows: 
python3 -m venv venv
venv\Scripts\activate   
```

2. Install the required libraries:

    ```bash
    pip3 install -r requirements.txt
    ```

3. If `tkinter` is not installed, install it via this command:

    ```bash
    sudo apt-get install python3-tk           # For Debian-based systems
    sudo pacman -S tk                         # For Arch-based systems
    ```

### For Windows

1. Ensure Python 3.x is installed. If not, download and install it from the [official website](https://www.python.org/downloads/).

2. Install the required libraries:

    ```bash
    pip3 install -r requirements.txt
    ```

## Usage

1. Run the application:

    ```bash
    sudo python log_analyzer.py
    ```

2. Using the GUI:
- Click on "Select Log File and Scan" to choose a log file.
- The analysis results will be displayed, including any detected suspicious activities and their remedies.
- The output report and graph will be saved in the same directory as the log file.


## Example

Here is an example of the tool's output in a bar graph:

![Log_analyzer](images/image_8.png) 

After selecting a log file and running the analysis, you will see the detected issues and recommended actions with a bar graph.

## Future Enhancements

- **Real-time Monitoring**: Implement real-time monitoring of log files to detect suspicious activities as they happen.
- **Custom Patterns**: Allow users to define custom patterns and rules for detecting suspicious activities.
- **Integration with SIEM**: Integrate with Security Information and Event Management (SIEM) systems for advanced threat detection and incident response.

![Log_analyzer](images/Logo.png)
