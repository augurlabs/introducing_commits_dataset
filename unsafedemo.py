import sqlite3

conn = sqlite3.connect("example.db")
cursor = conn.cursor()

username = input("Enter username: ")

# 🚨 VULNERABLE CODE
query = f"SELECT * FROM users WHERE username = '{username}'"
print("\nRunning query:")
print(query)

cursor.execute(query)
results = cursor.fetchall()

print("\nResults:")
for row in results:
    print(row)

conn.close()