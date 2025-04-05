import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import re
import matplotlib.pyplot as plt
from collections import defaultdict
import json
import os
import tempfile
from fpdf import FPDF
from ai_log_analyzer import classify_log
from voice_assistant import listen, speak
from PIL import Image, ImageTk

patterns = {
    'malware': re.compile(r'malware|virus|trojan|ransomware', re.IGNORECASE),
    'file_tampering': re.compile(r'file tampering|unauthorized file modification', re.IGNORECASE),
    'unauthorized_access': re.compile(r'unauthorized access|login failure|invalid login|access denied', re.IGNORECASE),
    'security_breach': re.compile(r'security breach|data breach|intrusion detected|unauthorized entry', re.IGNORECASE),
    'advanced_malware': re.compile(r'zero-day|advanced persistent threat|rootkit', re.IGNORECASE),
    'phishing': re.compile(r'phishing|spear phishing|fraudulent email', re.IGNORECASE),
    'data_leakage': re.compile(r'data leakage|data exfiltration|information leak', re.IGNORECASE)
}

remedies = {
    "NEGATIVE": "The log entry may indicate a problem. Please investigate further.",
    "POSITIVE": "The log entry appears to be normal.",
    'malware': "Remedy: Run a full system antivirus scan, isolate the affected systems, and update your antivirus software.",
    'file_tampering': "Remedy: Restore the affected files from backup, change file permissions, and monitor file integrity.",
    'unauthorized_access': "Remedy: Reset passwords, implement multi-factor authentication, and review access logs.",
    'security_breach': "Remedy: Disconnect affected systems from the network, conduct a thorough investigation, and notify affected parties.",
    'advanced_malware': "Remedy: Employ advanced threat detection tools, perform a deep system scan, and update security protocols.",
    'phishing': "Remedy: Educate users about phishing, implement email filtering solutions, and report the phishing attempt.",
    'data_leakage': "Remedy: Identify the source of the leak, implement data loss prevention solutions, and review data access policies."
}

config_file = 'log_analyzer_config.json'

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            patterns.update({k: re.compile(v, re.IGNORECASE) for k, v in config.get('patterns', {}).items()})
            remedies.update(config.get('remedies', {}))

def save_patterns():
    config = {
        'patterns': {k: v.pattern for k, v in patterns.items()},
        'remedies': {k: v for k, v in remedies.items()}
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(list)
    total_lines = 0
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, start=1):
            total_lines += 1
            label, confidence = classify_log(line)
            if confidence > 0.8 and label != "neutral":
                suspicious_activity[label].append((i, line.strip()))
    return suspicious_activity, total_lines

def save_report(log_file, suspicious_activity, total_lines):
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, os.path.basename(log_file).replace('.log', '_output.txt'))

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for label, entries in suspicious_activity.items():
                f.write(f'{label.upper()}: {len(entries)} occurrences\n')
                f.write(f'{remedies.get(label, "No remedy provided.")}\n\n')
                for line_num, content in entries:
                    f.write(f'  Line {line_num}: {content}\n')
                f.write('\n')
        else:
            f.write('✅ No suspicious activity detected.\n')

    return report_file

def plot_suspicious_activity(log_file, suspicious_activity):
    if not suspicious_activity:
        return None

    activities = list(suspicious_activity.keys())
    counts = [len(v) for v in suspicious_activity.values()]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(activities, counts, color='red')
    ax.set_xlabel('Activity Type')
    ax.set_ylabel('Count')
    ax.set_title('Suspicious Activity Detected in Logs')

    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    graph_file = os.path.join(output_dir, os.path.basename(log_file).replace('.log', '_suspicious_activity.png'))

    fig.savefig(graph_file)
    plt.close(fig)
    return graph_file

def merge_logs(file_paths):
    merged = ""
    for path in file_paths:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            merged += f"\n--- START OF: {os.path.basename(path)} ---\n"
            merged += f.read()
            merged += f"\n--- END OF: {os.path.basename(path)} ---\n"
    return merged

def run_analysis():
    global last_suspicious_activity, last_total_lines, temp_log_path

    log_files = filedialog.askopenfilenames(title="Select Log Files", filetypes=[("Log Files", "*.log *.txt")])
    if not log_files:
        return

    merged_logs = merge_logs(log_files)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log", mode='w', encoding='utf-8') as temp_file:
        temp_file.write(merged_logs)
        temp_log_path = temp_file.name

    suspicious_activity, total_lines = analyze_log_file(temp_log_path)
    last_suspicious_activity = suspicious_activity
    last_total_lines = total_lines

    report_file = save_report(temp_log_path, suspicious_activity, total_lines)
    graph_file = plot_suspicious_activity(temp_log_path, suspicious_activity)

    result_message = f"Analysis complete!\nReport saved to: {report_file}"
    if graph_file:
        result_message += f"\nGraph saved to: {graph_file}"
        display_graph(graph_file)

    if suspicious_activity:
        messagebox.showwarning("Alert", "Suspicious activity detected!")

    messagebox.showinfo("Analysis Complete", result_message)
    update_analysis_results(suspicious_activity, total_lines)

def display_graph(graph_file):
    img = Image.open(graph_file)
    img = img.resize((600, 300), Image.LANCZOS)
    tk_img = ImageTk.PhotoImage(img)
    img_label.config(image=tk_img)
    img_label.image = tk_img

def update_analysis_results(suspicious_activity, total_lines):
    for widget in analysis_results_frame.winfo_children():
        widget.destroy()

    tk.Label(analysis_results_frame, text=f"Total lines processed: {total_lines}", font=("Helvetica", 12)).pack(pady=5)

    if suspicious_activity:
        for activity, entries in suspicious_activity.items():
            tk.Label(analysis_results_frame, text=f'{activity}: {len(entries)}', font=("Helvetica", 12), fg='red').pack(pady=2)
            tk.Label(analysis_results_frame, text=f'{remedies.get(activity, "No remedy provided.")}',
                     font=("Helvetica", 10), wraplength=750, justify='left', fg='darkblue').pack(pady=2)
    else:
        tk.Label(analysis_results_frame, text='✅ No suspicious activity detected.', font=("Helvetica", 12), fg='green').pack(pady=5)

def export_to_pdf(log_file, suspicious_activity, total_lines):
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    pdf_file = os.path.join(output_dir, os.path.basename(log_file).replace('.log', '_report.pdf'))

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Log Analysis Report", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Total lines processed: {total_lines}", ln=True)
    pdf.ln(5)

    if suspicious_activity:
        for label, entries in suspicious_activity.items():
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt=f"{label.upper()} - {len(entries)} entries", ln=True)
            pdf.set_font("Arial", size=11)
            pdf.multi_cell(0, 10, txt=remedies.get(label, "No remedy provided."))
            for line_num, content in entries:
                pdf.multi_cell(0, 8, txt=f"Line {line_num}: {content}")
            pdf.ln(3)
    else:
        pdf.cell(200, 10, txt="✅ No suspicious activity detected.", ln=True)

    pdf.output(pdf_file)
    messagebox.showinfo("PDF Exported", f"PDF saved to: {pdf_file}")

def quit_application():
    root.quit()

def add_custom_pattern():
    pattern_name = simpledialog.askstring("Input", "Enter the name of the custom pattern:")
    pattern_regex = simpledialog.askstring("Input", "Enter the regex for the custom pattern:")
    if pattern_name and pattern_regex:
        try:
            patterns[pattern_name] = re.compile(pattern_regex, re.IGNORECASE)
            remedies[pattern_name] = "Custom pattern remedy not provided."
            save_patterns()
            messagebox.showinfo("Success", "Custom pattern added successfully.")
        except re.error:
            messagebox.showerror("Error", "Invalid regex pattern.")

def start_voice_assistant():
    speak("Voice assistant ready. Say 'scan log' to begin.")
    while True:
        command = listen()
        if "scan log" in command:
            speak("Scanning now.")
            run_analysis()
        elif "exit" in command:
            speak("Goodbye!")
            break
        else:
            speak("Try again.")

def create_gui():
    global root, tab_analysis, tab_custom_patterns, analysis_results_frame, img_label

    root = tk.Tk()
    root.title("Log Analyzer")
    root.geometry("800x600")

    tab_control = ttk.Notebook(root)
    tab_analysis = ttk.Frame(tab_control)
    tab_custom_patterns = ttk.Frame(tab_control)

    tab_control.add(tab_analysis, text='Log Analysis')
    tab_control.add(tab_custom_patterns, text='Custom Patterns')
    tab_control.pack(expand=1, fill='both')

    tk.Label(tab_analysis, text="Log Analyzer Tool", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_analysis, text="Select Log Files and Scan", command=run_analysis, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Start Voice Assistant", command=start_voice_assistant, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Export Last Report to PDF", command=lambda: export_to_pdf(temp_log_path, last_suspicious_activity, last_total_lines), font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Quit", command=quit_application, font=("Helvetica", 12)).pack(pady=10)

    canvas = tk.Canvas(tab_analysis)
    scrollbar = ttk.Scrollbar(tab_analysis, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    analysis_results_frame = scrollable_frame

    img_label = tk.Label(tab_analysis)
    img_label.pack(pady=10)

    tk.Label(tab_custom_patterns, text="Custom Pattern Management", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_custom_patterns, text="Add Custom Pattern", command=add_custom_pattern, font=("Helvetica", 12)).pack(pady=10)

    root.mainloop()

if __name__ == '__main__':
    load_patterns()
    create_gui()
