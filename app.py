from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

# Path to the reports folder
REPORTS_DIR = '/home/mavindu/Desktop/test/reports'

# Route to serve the HTML template and list all reports
@app.route('/')
def index():
    # Get all files from the reports directory
    reports = os.listdir(REPORTS_DIR)
    return render_template('index.html', reports=reports)

# Route to download/view a specific report from the reports folder
@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

