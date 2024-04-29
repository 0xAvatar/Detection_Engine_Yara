import sqlite3

class Tested_Files:
    def __init__(self, db_path='FilesDataset/malware_data.db'):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_data (
                md5_hash TEXT PRIMARY KEY,
                is_malware BOOLEAN,
                report TEXT
            )
        ''')
        self.conn.commit()

    def show_database(self):
        self.cursor.execute('SELECT * FROM malware_data')
        rows = self.cursor.fetchall()

        if rows:
            print("md5_hash | is_malware | report")
            print("---------------------------------")
            for row in rows:
                print(f"{row[0]} | {row[1]} | {row[2]}")
        else:
            print("Database is empty.")

    def add_file(self, md5_hash, is_malware, report=''):
        self.cursor.execute('INSERT OR IGNORE INTO malware_data (md5_hash, is_malware, report) VALUES (?, ?, ?)',
                            (md5_hash, is_malware, report))
        self.conn.commit()

    def delete_file(self, md5_hash):
        self.cursor.execute('DELETE FROM malware_data WHERE md5_hash = ?', (md5_hash,))
        self.conn.commit()

    def is_malware(self, md5_hash):
        self.cursor.execute('SELECT is_malware FROM malware_data WHERE md5_hash = ?', (md5_hash,))
        result = self.cursor.fetchone()
        if result:
            return result[0]
        else:
            return None

    def get_report(self, md5_hash):
        self.cursor.execute('SELECT report FROM malware_data WHERE md5_hash = ?', (md5_hash,))
        result = self.cursor.fetchone()
        if result:
            return result[0]
        else:
            return None

    def hash_in_db(self, md5_hash):
        self.cursor.execute('SELECT COUNT(*) FROM malware_data WHERE md5_hash = ?', (md5_hash,))
        result = self.cursor.fetchone()
        return result[0] > 0

    def close_connection(self):
        self.conn.close()




malware_db = Tested_Files()
#malware_db.delete_file("ec4f0c22b0bd26bf05dd8c2781f65bdd")

#print(malware_db.hash_in_db("ec4f0c22b0bd26bf05dd8c2781f65bdd"))

malware_db.show_database()
#print(malware_db.hash_in_db("ec4f0c22b0bd26bf05dd8c2781f65bdd"))
# Close the database connection
malware_db.close_connection()
"""
now i have a dataset of some files that i have already tested
[ md5_hash , is_malware,Report ] 
i want to skip testing the files 
"""