import sqlite3

conn = sqlite3.connect("example.db")
cursor = conn.cursor()

username = input("Enter username: ")

# ✅ SAFE VERSION
query = "SELECT * FROM users WHERE username = ?"
print("\nRunning query safely:")
print(query)

cursor.execute(query, (username,))
results = cursor.fetchall()

print("\nResults:")
for row in results:
    print(row)

conn.close()
