#!/usr/bin/env python3
"""
Script to generate bcrypt hashes and update admin passwords in database
Run this script to fix the "Invalid salt" error
"""

import mysql.connector
from flask_bcrypt import Bcrypt

# Initialize bcrypt
bcrypt = Bcrypt()

# Database configuration (same as your app.py)
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',
    'database': 'bus_pass_system'
}

def update_admin_passwords():
    # Generate bcrypt hashes for passwords
    admin_password = 'admin123'  # Change this to your desired admin password
    college_password = 'college123'  # Change this to your desired college admin password
    
    admin_hash = bcrypt.generate_password_hash(admin_password).decode()
    college_hash = bcrypt.generate_password_hash(college_password).decode()
    
    print("Generated hashes:")
    print(f"Admin hash: {admin_hash}")
    print(f"College hash: {college_hash}")
    print(f"Admin hash length: {len(admin_hash)}")
    print(f"College hash length: {len(college_hash)}")
    
    # Connect to database
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Update admin password
        cursor.execute(
            "UPDATE admins SET password = %s WHERE username = %s",
            (admin_hash, 'admin')
        )
        print(f"✅ Updated admin password for user 'admin'")
        
        # Update college admin password
        cursor.execute(
            "UPDATE college_admins SET password = %s WHERE username = %s",
            (college_hash, 'collegeadmin')
        )
        print(f"✅ Updated college admin password for user 'collegeadmin'")
        
        # Commit changes
        conn.commit()
        
        # Verify the updates
        cursor.execute("SELECT username, LENGTH(password) as len FROM admins WHERE username = 'admin'")
        admin_result = cursor.fetchone()
        print(f"Admin verification: {admin_result}")
        
        cursor.execute("SELECT username, LENGTH(password) as len FROM college_admins WHERE username = 'collegeadmin'")
        college_result = cursor.fetchone()
        print(f"College admin verification: {college_result}")
        
        print("\n🎉 Password update completed successfully!")
        print(f"Login credentials:")
        print(f"Admin: username='admin', password='{admin_password}'")
        print(f"College Admin: username='collegeadmin', password='{college_password}'")
        
    except mysql.connector.Error as e:
        print(f"❌ Database error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    print("Updating admin passwords...")
    update_admin_passwords()
