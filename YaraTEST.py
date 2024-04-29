import os
import subprocess
import time
from win10toast import ToastNotifier
from Yara import YaraScanner
#from Database import Tested_Files
import hashlib


class YaraDirectoryWatcher:
    def __init__(self, powershell_script_path, yara_rules_directory):
        self.powershell_script_path = powershell_script_path
        self.previous_paths = None
        self.yara_rules_directory = yara_rules_directory
    def get_file_hash(self, file_path):
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            #print(f"The hash of {file_path} is: {file_hash}")
            return file_hash
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None

    def show_notification(self, title, message):
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=10)

    def get_current_directory_paths(self):
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", self.powershell_script_path],
            stdout=subprocess.PIPE,
            text=True,
            shell=True
        )
        directory_paths = result.stdout.strip().split('\n')
        filtered_paths = [path.split(": ", 1)[1] for path in directory_paths if path.startswith("Directory Path")]
        return filtered_paths

    def process_directory(self, path):
        extension = 'exe'
        files = [file for file in os.listdir(path) if file.endswith(f".{extension}")]
        print(f"EXEs in {path}:")

        for file in files:
            full_path = os.path.join(path, file)
            yara_scanner = YaraScanner(self.yara_rules_directory)
            is_malware = yara_scanner.scan_file(full_path)
            hash = self.get_file_hash(full_path)

            if is_malware:
                os.remove(full_path)
                self.show_notification(f"Malware Found {file}",
                                       f"{file} is Classified as Malware and Deleted\nPath:{full_path}")

            self.previous_paths = [path]

    def watch_directory(self):
        while True:
            extracted_paths = self.get_current_directory_paths()
            for path in extracted_paths:
                print("Scanning...")
                self.process_directory(path)
            time.sleep(1)


# Example usage:
powershell_script_path = "Powershell/CurrentDirectory.ps1"
yara_rules_directory = "YaraRules/YaraFilt"
directory_watcher = YaraDirectoryWatcher(powershell_script_path, yara_rules_directory)
directory_watcher.watch_directory()
