import sys
import re
import requests
import json
from typing import Dict, Optional
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton,
    QStatusBar, QFrame, QSplitter, QComboBox, QLineEdit, QGridLayout, QProgressBar, QToolBar,
    QAction, QMenu, QMessageBox, QTabWidget, QScrollArea, QGroupBox, QRadioButton, QSlider, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QPropertyAnimation, QEasingCurve, QDateTime
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QTextCursor, QFontDatabase, QTextCharFormat
from fastapi import FastAPI
from pydantic import BaseModel
from langchain_ollama import OllamaLLM  # Updated import
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda
from functools import lru_cache
import uvicorn

# ----------------------------
# FastAPI Backend
# ----------------------------

# Configuration
BLOCKLIST = {"hack", "exploit", "malicious", "inject", "root"}
SQL_INJECTION_REGEX = re.compile(r"\b(DROP\s+TABLE|UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM)\b", re.IGNORECASE)
CACHE_SIZE = 1000  # Maximum cache size for recent queries
CONFIDENCE_THRESHOLD = 0.8  # Minimum confidence for blocking inputs

# FastAPI Setup
app = FastAPI(title="AI Input Firewall with Responses", version="2.1")

class UserRequest(BaseModel):
    text: str
    user_id: Optional[str] = None

class FirewallResponse(BaseModel):
    status: str  # "allowed" or "blocked"
    reason: Optional[str] = None
    score: Optional[float] = None
    response: Optional[str] = None  # Response if the input is safe

# LangChain Setup
llm = OllamaLLM(model="llama2")

classification_prompt = PromptTemplate(
    input_variables=["text"],
    template=(
        "Classify the following input as 'SAFE' or 'UNSAFE' based on whether it contains malicious, harmful, "
        "or suspicious content. Respond with only 'SAFE' or 'UNSAFE'.\n\n"
        "Input: {text}\n\nClassification:"
    )
)

response_prompt = PromptTemplate(
    input_variables=["text"],
    template="Respond to the following input:\n\n{text}\n\nResponse:"
)

classification_chain = classification_prompt | llm  # Updated usage
response_chain = response_prompt | llm  # Updated usage

# Core Firewall Logic
@lru_cache(maxsize=CACHE_SIZE)
def classify_input_with_ollama(text: str) -> Dict:
    try:
        result = classification_chain.invoke({"text": text})
        classification = result.strip().upper()
        return {"label": classification, "score": 1.0 if classification == "UNSAFE" else 0.0}
    except Exception as e:
        print(f"[ERROR] LangChain/Ollama classification failed: {e}")
        return {"label": "UNSAFE", "score": 1.0}  # Default to UNSAFE if API fails

def rule_based_checks(text: str) -> Optional[str]:
    text_lower = text.lower()
    if any(word in text_lower for word in BLOCKLIST):
        return "Blocked due to prohibited keyword."
    if SQL_INJECTION_REGEX.search(text):
        return "SQL injection attempt detected."
    return None

def generate_ollama_response(text: str) -> str:
    try:
        response = response_chain.invoke({"text": text})
        return response.strip() or "No response generated."
    except Exception as e:
        print(f"[ERROR] Failed to generate response from LangChain/Ollama: {e}")
        return "Error generating response."

def is_input_safe(text: str) -> Dict:
    rule_based_reason = rule_based_checks(text)
    if rule_based_reason:
        return {
            "status": "blocked",
            "reason": rule_based_reason,
            "score": None,
            "response": "This prompt is unsafe, can't answer."
        }
    ai_result = classify_input_with_ollama(text)
    if ai_result["label"] == "UNSAFE" and ai_result["score"] > CONFIDENCE_THRESHOLD:
        return {
            "status": "blocked",
            "reason": "Ollama classified as unsafe",
            "score": ai_result["score"],
            "response": "This prompt is unsafe, can't answer."
        }
    response = generate_ollama_response(text)
    return {
        "status": "allowed",
        "score": ai_result["score"],
        "response": response
    }

# API Endpoints
@app.post("/check-input", response_model=FirewallResponse)
async def check_input(request: UserRequest):
    result = is_input_safe(request.text)
    print(f"[LOG] User: {request.user_id or 'Anonymous'} | Text: {request.text[:50]}... | Status: {result['status']}")
    return FirewallResponse(**result)

# ----------------------------
# PyQt5 GUI
# ----------------------------

class AnimatedButton(QPushButton):
    """Custom button with hover and click animations"""
    def __init__(self, text, parent=None, accent_color=None):
        super().__init__(text, parent)
        self.default_bg = QColor(60, 63, 65)
        self.hover_bg = QColor(80, 83, 85) if accent_color is None else accent_color
        self.clicked_bg = QColor(42, 130, 218)
        
        self.setMinimumHeight(36)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: rgb(60, 63, 65);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self.hover_bg.name()};
            }}
            QPushButton:pressed {{
                background-color: {self.clicked_bg.name()};
            }}
        """)


class WorkerThread(QThread):
    """Worker thread to handle API requests without blocking the UI"""
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    
    def __init__(self, url, data):
        super().__init__()
        self.url = url
        self.data = data
        
    def run(self):
        try:
            # Simulate progress for better UX
            for i in range(1, 101):
                self.progress.emit(i)
                self.msleep(10)  # Short sleep for animation
            
            response = requests.post(self.url, json=self.data)
            self.finished.emit(response.json())
        except Exception as e:
            self.finished.emit({"status": "error", "reason": str(e)})


class AIFirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Input Firewall")
        self.setMinimumSize(1000, 700)
        
        # Initialize values
        self.server_url = "http://localhost:8000/check-input"
        self.theme = "dark"  # Default theme
        self.accent_color = QColor(42, 130, 218)  # Default accent color
        self.history = []  # To store submission history
        
        # Set up the central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        
        # Initialize UI components
        self.setup_toolbar()
        self.setup_header()
        self.setup_content()
        
        # Set up status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply initial theme
        self.apply_theme()

    def setup_toolbar(self):
        """Set up toolbar with useful actions"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        
        # Theme switcher
        theme_action = QAction("Toggle Theme", self)
        theme_action.triggered.connect(self.toggle_theme)
        toolbar.addAction(theme_action)
        
        # Export action
        export_action = QAction("Export Results", self)
        export_action.triggered.connect(self.export_results)
        toolbar.addAction(export_action)
        
        # Settings action
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        toolbar.addAction(settings_action)
        
        self.addToolBar(toolbar)
    
    def setup_header(self):
        """Set up the header section of the GUI"""
        header = QWidget()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(5, 5, 5, 15)
        header_layout.setSpacing(8)
        
        # Title with stylish display
        title_container = QWidget()
        title_layout = QHBoxLayout(title_container)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        title = QLabel("AI Input Firewall & Response System")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Roboto", 18, QFont.Bold)
        title.setFont(title_font)
        
        title_layout.addStretch()
        title_layout.addWidget(title)
        title_layout.addStretch()
        
        # Subtitle with more information
        subtitle = QLabel("Monitors, analyzes and filters potentially unsafe inputs to AI systems")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont("Roboto", 10)
        subtitle.setFont(subtitle_font)
        
        # Server settings in a nice group
        server_group = QGroupBox("Server Configuration")
        server_group.setFlat(True)
        server_layout = QGridLayout(server_group)
        
        server_label = QLabel("Server URL:")
        self.server_input = QLineEdit()
        self.server_input.setText(self.server_url)
        
        update_server_button = AnimatedButton("Update", accent_color=QColor(42, 130, 218))
        update_server_button.clicked.connect(self.update_server_url)
        
        server_layout.addWidget(server_label, 0, 0)
        server_layout.addWidget(self.server_input, 0, 1)
        server_layout.addWidget(update_server_button, 0, 2)
        
        # Add elements to header
        header_layout.addWidget(title_container)
        header_layout.addWidget(subtitle)
        header_layout.addWidget(server_group)
        
        # Add separator line
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        
        self.main_layout.addWidget(header)
        self.main_layout.addWidget(separator)
    
    def update_server_url(self):
        """Update the server URL from the input field"""
        self.server_url = self.server_input.text().strip()
        self.status_bar.showMessage(f"Server URL updated to: {self.server_url}")
        
        # Show confirmation tooltip
        QMessageBox.information(self, "Server Updated", 
                              f"Server URL has been updated to:\n{self.server_url}")
        
    def setup_content(self):
        """Set up the main content area with input/output panels"""
        # Create tab widget for multiple views
        self.tab_widget = QTabWidget()
        
        # Main tab - Input and Results
        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        
        # Create a splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)
        
        # Input panel with improved styling
        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        
        input_header = QLabel("Input")
        input_header.setFont(QFont("Roboto", 14, QFont.Bold))
        
        # User configuration
        user_config = QGroupBox("User Information")
        user_config_layout = QGridLayout(user_config)
        
        user_config_layout.addWidget(QLabel("User ID:"), 0, 0)
        self.user_id_input = QLineEdit()
        self.user_id_input.setPlaceholderText("Anonymous")
        user_config_layout.addWidget(self.user_id_input, 0, 1)
        
        # Content security level selector
        user_config_layout.addWidget(QLabel("Security Level:"), 0, 2)
        self.security_level = QComboBox()
        self.security_level.addItems(["Low", "Medium", "High", "Custom"])
        user_config_layout.addWidget(self.security_level, 0, 3)
        
        # Input text with better styling
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to check...")
        self.input_text.setMinimumHeight(120)
        
        # Button row with controls
        button_row = QHBoxLayout()
        clear_button = AnimatedButton("Clear")
        clear_button.clicked.connect(lambda: self.input_text.clear())
        
        submit_button = AnimatedButton("Check Input")
        submit_button.setMinimumWidth(150)
        submit_button.clicked.connect(self.submit_request)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumHeight(10)
        self.progress_bar.hide()
        
        button_row.addWidget(clear_button)
        button_row.addStretch()
        button_row.addWidget(self.progress_bar)
        button_row.addWidget(submit_button)
        
        input_layout.addWidget(input_header)
        input_layout.addWidget(user_config)
        input_layout.addWidget(self.input_text)
        input_layout.addLayout(button_row)
        
        # Result panel with improved layout and visualization
        result_widget = QWidget()
        result_layout = QVBoxLayout(result_widget)
        
        result_header = QLabel("Results")
        result_header.setFont(QFont("Roboto", 14, QFont.Bold))
        
        # Result information in a nice grid
        result_info = QGroupBox("Analysis Details")
        result_info_layout = QGridLayout(result_info)
        
        # Status display
        result_info_layout.addWidget(QLabel("Status:"), 0, 0)
        self.status_display = QLabel("No submission yet")
        self.status_display.setFont(QFont("Roboto", 10, QFont.Bold))
        result_info_layout.addWidget(self.status_display, 0, 1)
        
        # Reason display
        result_info_layout.addWidget(QLabel("Reason:"), 1, 0)
        self.reason_display = QLabel("N/A")
        result_info_layout.addWidget(self.reason_display, 1, 1)
        
        # Score display with visual indicator
        result_info_layout.addWidget(QLabel("Safety Score:"), 0, 2)
        score_container = QWidget()
        score_layout = QHBoxLayout(score_container)
        score_layout.setContentsMargins(0, 0, 0, 0)
        
        self.score_display = QLabel("N/A")
        self.score_indicator = QProgressBar()
        self.score_indicator.setMinimum(0)
        self.score_indicator.setMaximum(100)
        self.score_indicator.setValue(0)
        self.score_indicator.setTextVisible(False)
        self.score_indicator.setFixedWidth(120)
        self.score_indicator.setMaximumHeight(10)
        
        score_layout.addWidget(self.score_display)
        score_layout.addWidget(self.score_indicator)
        result_info_layout.addWidget(score_container, 0, 3)
        
        # Categories
        result_info_layout.addWidget(QLabel("Categories:"), 1, 2)
        self.categories_display = QLabel("N/A")
        result_info_layout.addWidget(self.categories_display, 1, 3)
        
        # Response display with syntax highlighting
        response_group = QGroupBox("Response")
        response_layout = QVBoxLayout(response_group)
        
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setMinimumHeight(150)
        
        response_layout.addWidget(self.response_text)
        
        result_layout.addWidget(result_header)
        result_layout.addWidget(result_info)
        result_layout.addWidget(response_group)
        
        # Add widgets to splitter
        splitter.addWidget(input_widget)
        splitter.addWidget(result_widget)
        
        # Set initial sizes
        splitter.setSizes([300, 400])
        
        main_layout.addWidget(splitter)
        
        # History tab
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        
        history_label = QLabel("Submission History")
        history_label.setFont(QFont("Roboto", 14, QFont.Bold))
        
        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)
        
        history_layout.addWidget(history_label)
        history_layout.addWidget(self.history_text)
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        settings_label = QLabel("Application Settings")
        settings_label.setFont(QFont("Roboto", 14, QFont.Bold))
        
        # Theme settings
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QVBoxLayout(theme_group)
        
        self.light_theme_radio = QRadioButton("Light Theme")
        self.dark_theme_radio = QRadioButton("Dark Theme")
        
        if self.theme == "dark":
            self.dark_theme_radio.setChecked(True)
        else:
            self.light_theme_radio.setChecked(True)
            
        self.light_theme_radio.toggled.connect(self.on_theme_changed)
        self.dark_theme_radio.toggled.connect(self.on_theme_changed)
        
        theme_layout.addWidget(self.light_theme_radio)
        theme_layout.addWidget(self.dark_theme_radio)
        
        # Add settings
        settings_layout.addWidget(settings_label)
        settings_layout.addWidget(theme_group)
        settings_layout.addStretch()
        
        # Add tabs
        self.tab_widget.addTab(main_tab, "Input & Results")
        self.tab_widget.addTab(history_tab, "History")
        self.tab_widget.addTab(settings_tab, "Settings")
        
        self.main_layout.addWidget(self.tab_widget)
    
    def submit_request(self):
        """Submit text to the firewall API with visual feedback"""
        # Validate input
        if not self.input_text.toPlainText().strip():
            QMessageBox.warning(self, "Input Required", "Please enter text to check.")
            return
            
        self.status_bar.showMessage("Processing request...")
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        
        # Prepare data
        security_level = self.security_level.currentText().lower()
        
        data = {
            "text": self.input_text.toPlainText(),
            "user_id": self.user_id_input.text() or "anonymous",
            "security_level": security_level
        }
        
        # Use worker thread to avoid blocking UI
        self.worker = WorkerThread(self.server_url, data)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.handle_response)
        self.worker.start()
    
    def update_progress(self, value):
        """Update progress bar during request"""
        self.progress_bar.setValue(value)
    
    def handle_response(self, result):
        """Process and display the API response with improved visual feedback"""
        self.progress_bar.hide()
        
        if "status" not in result:
            self.status_display.setText("ERROR")
            self.status_display.setStyleSheet("color: red; font-weight: bold;")
            self.reason_display.setText("Invalid response from server")
            self.status_bar.showMessage("Error: Invalid response format")
            return
            
        # Update status with animation
        status = result.get("status", "unknown")
        self.status_display.setText(status.upper())
        
        # Visual styling based on status
        if status == "allowed":
            self.status_display.setStyleSheet("color: #2ecc71; font-weight: bold;")
        elif status == "blocked":
            self.status_display.setStyleSheet("color: #e74c3c; font-weight: bold;")
        else:
            self.status_display.setStyleSheet("color: #f39c12; font-weight: bold;")
            
        # Update reason
        reason = result.get("reason", "N/A")
        self.reason_display.setText(reason)
        
        # Update score with animation
        score = result.get("score", 0)
        if score is not None:
            self.score_display.setText(f"{score}%")
            
            # Animate the score indicator
            animation = QPropertyAnimation(self.score_indicator, b"value")
            animation.setDuration(500)
            animation.setStartValue(0)
            animation.setEndValue(score)
            animation.setEasingCurve(QEasingCurve.OutCubic)
            animation.start()
            
            # Color the score indicator based on value
            if score > 80:
                self.score_indicator.setStyleSheet("QProgressBar::chunk { background-color: #2ecc71; }")
            elif score > 50:
                self.score_indicator.setStyleSheet("QProgressBar::chunk { background-color: #f39c12; }")
            else:
                self.score_indicator.setStyleSheet("QProgressBar::chunk { background-color: #e74c3c; }")
        else:
            self.score_display.setText("N/A")
            self.score_indicator.setValue(0)
        
        # Update categories if available
        categories = result.get("categories", [])
        if categories:
            self.categories_display.setText(", ".join(categories))
        else:
            self.categories_display.setText("N/A")
        
        # Update response with formatting
        response = result.get("response", "No response provided")
        self.response_text.setText(response)
        
        # Apply text highlighting based on status
        highlighter = QTextCharFormat()
        if status == "allowed":
            highlighter.setForeground(QColor("#2ecc71"))
        elif status == "blocked":
            highlighter.setForeground(QColor("#e74c3c"))
        
        # Add to history
        timestamp = QDateTime.currentDateTime().toString(Qt.DefaultLocaleLongDate)
        history_entry = f"[{timestamp}] - {status.upper()}: {reason}\n"
        self.history.append(history_entry)
        self.history_text.append(history_entry)
        
        # Update status bar
        self.status_bar.showMessage(f"Request processed: {status}")
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        if self.theme == "dark":
            self.theme = "light"
            self.light_theme_radio.setChecked(True)
        else:
            self.theme = "dark"
            self.dark_theme_radio.setChecked(True)
            
        self.apply_theme()
    
    def on_theme_changed(self):
        """Handle theme radio button changes"""
        if self.light_theme_radio.isChecked():
            self.theme = "light"
        else:
            self.theme = "dark"
            
        self.apply_theme()
    
    def apply_theme(self):
        """Apply the selected theme to the application"""
        palette = QPalette()
        
        if self.theme == "dark":
            # Dark theme
            palette.setColor(QPalette.Window, QColor(45, 45, 45))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
        else:
            # Light theme
            palette.setColor(QPalette.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.WindowText, Qt.black)
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.AlternateBase, QColor(233, 233, 233))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.black)
            palette.setColor(QPalette.Text, Qt.black)
            palette.setColor(QPalette.Button, QColor(220, 220, 220))
            palette.setColor(QPalette.ButtonText, Qt.black)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(0, 100, 200))
            palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.HighlightedText, Qt.white)
            
        QApplication.setPalette(palette)
    
    def export_results(self):
        """Export the current results to a file"""
        if not self.response_text.toPlainText():
            QMessageBox.warning(self, "No Results", "There are no results to export.")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    # Create a formatted export with all information
                    export_text = "AI Input Firewall - Analysis Results\n"
                    export_text += "=" * 40 + "\n\n"
                    export_text += f"Status: {self.status_display.text()}\n"
                    export_text += f"Reason: {self.reason_display.text()}\n"
                    export_text += f"Safety Score: {self.score_display.text()}\n"
                    export_text += f"Categories: {self.categories_display.text()}\n\n"
                    export_text += "Input Text:\n"
                    export_text += "-" * 40 + "\n"
                    export_text += self.input_text.toPlainText() + "\n\n"
                    export_text += "Response:\n"
                    export_text += "-" * 40 + "\n"
                    export_text += self.response_text.toPlainText()
                    
                    f.write(export_text)
                    
                self.status_bar.showMessage(f"Results exported to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
    
    def show_settings(self):
        """Switch to the settings tab"""
        self.tab_widget.setCurrentIndex(2)


def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    window = AIFirewallGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    # Start FastAPI server in a separate thread
    import threading
    fastapi_thread = threading.Thread(target=lambda: uvicorn.run(app, host="127.0.0.1", port=8000))
    fastapi_thread.daemon = True
    fastapi_thread.start()
    
    # Start the PyQt5 GUI
    main()
