import sqlite3

conn = sqlite3.connect("example.db")
cursor = conn.cursor()

sort = input("Sort by column: ")

# 🚨 VULNERABLE
query = f"SELECT * FROM users ORDER BY {sort}"
print("\nRunning query:")
print(query)

cursor.execute(query)
results = cursor.fetchall()

print("\nResults:")
for row in results:
    print(row)

conn.close()
