import sqlite3
import datetime

class MalwareRecords:
    def __init__(self, db_file="malware_database.db"):
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                malware_name TEXT,
                date_time_detected DATETIME,
                action_taken TEXT,
                details TEXT
            )
        ''')
        self.conn.commit()

    def show_database(self):
        self.cursor.execute('SELECT * FROM malware_records')
        rows = self.cursor.fetchall()

        if rows:
            print("id  | malware_name | date_time_detected | action_taken | details")
            print("---------------------------------")
            for row in rows:
                print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} ")
        else:
            print("Database is empty.")

    def add_record(self, malware_name, action_taken, details):
        date_time_detected = datetime.datetime.now()
        self.cursor.execute('''
            INSERT INTO malware_records 
            (malware_name, date_time_detected, action_taken, details) 
            VALUES (?, ?, ?, ?)
        ''', (malware_name, date_time_detected, action_taken, details))
        self.conn.commit()
        print("Record added successfully.")

    def delete_record(self, record_id):
        self.cursor.execute("DELETE FROM malware_records WHERE id=?", (record_id,))
        if self.cursor.rowcount > 0:
            print(f"Record with ID {record_id} deleted successfully.")
        else:
            print(f"Record with ID {record_id} not found.")

    def get_report(self):
        self.cursor.execute("SELECT * FROM malware_records")
        records = self.cursor.fetchall()

        report = f"Malware Database Report:\n"
        for record in records:
            report += f"\nRecord {record[0]}:\n"
            report += f"Malware Name: {record[1]}\n"
            report += f"Date/Time Detected: {record[2]}\n"
            report += f"Action Taken: {record[3]}\n"
            report += f"Details: {record[4]}\n"
        return report

    def clear_all_data(self):
        self.cursor.execute("DELETE FROM malware_records")
        self.conn.commit()
        print("All records cleared successfully.")

"""
# Example Usage
malware_db = MalwareRecords()
malware_db.add_record("Trojan", "Quarantined", "Detected during system scan.")
malware_db.add_record("Ransomware", "Blocked", "Prevented file encryption.")
malware_db.show_database()
malware_db.delete_record(1)
malware_db.show_database()
report = malware_db.get_report()
print(report)
"""