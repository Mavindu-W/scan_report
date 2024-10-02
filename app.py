from flask import Flask, render_template, send_from_directory
import os
from datetime import datetime

app = Flask(__name__)

REPORTS_DIR = "/home/mavindu/Desktop/test/reports"  # Change this to the actual path if different

@app.route('/')
def index():
    files = []
    for file_name in os.listdir(REPORTS_DIR):
        file_path = os.path.join(REPORTS_DIR, file_name)
        if os.path.isdir(file_path):
            file_size = '-'
        else:
            file_size = os.path.getsize(file_path)
        files.append({
            'name': file_name,
            'size': file_size,
            'date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%H:%M:%S %p')
        })
    return render_template('index.html', files=files)

@app.route('/reports/<filename>')
def get_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)


