# AI Input Firewall

## Overview
The AI Input Firewall is a project designed to monitor, analyze, and filter potentially unsafe inputs to AI systems. It utilizes a FastAPI backend to classify user inputs as safe or unsafe using a machine learning model. The project also features a PyQt5 graphical user interface (GUI) that allows users to interact with the system, input text, view analysis results, and manage server settings.

## Features
- FastAPI backend for input classification
- Machine learning model integration for safety analysis
- User-friendly PyQt5 GUI for text input and result display
- Real-time feedback on input safety
- Server configuration management

## Installation

### Prerequisites
Ensure you have Python 3.7 or higher installed on your system.

### Clone the Repository
```bash
git clone https://github.com/yourusername/ai-input-firewall.git
cd ai-input-firewall
```

### Install Dependencies
Install the required packages using pip:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application
To start the FastAPI server and the PyQt5 GUI, run the following command:
```bash
python src/testrun.py
```

### Interacting with the GUI
1. Open the application window.
2. Enter the text you want to analyze in the input field.
3. Optionally, provide a user ID and select a security level.
4. Click the "Check Input" button to analyze the text.
5. View the results, including the status, reason for blocking (if applicable), safety score, and response from the AI model.

### Server Configuration
You can update the server URL in the GUI settings to point to a different FastAPI server if needed.

## Dependencies
The project requires the following Python packages:
- FastAPI
- PyQt5
- requests
- langchain
- uvicorn
- pydantic

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## Acknowledgments
- Thanks to the contributors and the community for their support and feedback.
