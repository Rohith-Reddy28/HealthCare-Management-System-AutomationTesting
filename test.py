# Healthcare Management System - Comprehensive Automation Testing Suite
# This suite covers Unit Tests, Integration Tests, Database Tests, UI Tests, Performance Tests, and Security Tests

import unittest
import sqlite3
import tkinter as tk
import threading
import time
import os
import sys
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil
from datetime import datetime
import re
import hashlib

# =============================================================================
# 1. DATABASE TESTS - Testing SQLite operations
# =============================================================================

class TestDatabaseOperations(unittest.TestCase):
    """Test database operations for the healthcare system"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db_path = 'test_database.db'
        self.conn = sqlite3.connect(self.test_db_path)
        self.cursor = self.conn.cursor()
        
        # Create test tables
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT NOT NULL,
                              age INTEGER NOT NULL,
                              gender TEXT NOT NULL,
                              location TEXT NOT NULL,
                              scheduled_time TEXT NOT NULL,
                              phone TEXT NOT NULL,
                              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS credentials
                             (id TEXT PRIMARY KEY,
                              name TEXT NOT NULL,
                              pass TEXT NOT NULL,
                              designation TEXT NOT NULL,
                              photo BLOB,
                              secret1_status BOOLEAN,
                              secret1_answer TEXT,
                              secret2_status BOOLEAN,
                              secret2_answer TEXT,
                              secret3_status BOOLEAN,
                              secret3_answer TEXT,
                              email TEXT)''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up test database"""
        self.conn.close()
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_appointment_creation(self):
        """Test creating an appointment"""
        appointment_data = ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890')
        self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                           appointment_data)
        self.conn.commit()
        
        # Verify appointment was created
        self.cursor.execute("SELECT * FROM appointments WHERE name = ?", ('John Doe',))
        result = self.cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[1], 'John Doe')
        self.assertEqual(result[2], 30)
        self.assertEqual(result[3], 'Male')
    
    def test_appointment_search(self):
        """Test searching for appointments"""
        # Insert test data
        appointments = [
            ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890'),
            ('Jane Smith', 25, 'Female', 'Boston', '14:00', '+0987654321')
        ]
        
        for appointment in appointments:
            self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                               appointment)
        self.conn.commit()
        
        # Test search
        self.cursor.execute("SELECT * FROM appointments WHERE name LIKE ?", ('John Doe',))
        result = self.cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[1], 'John Doe')
    
    def test_appointment_update(self):
        """Test updating appointment details"""
        # Insert test appointment
        self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                           ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890'))
        self.conn.commit()
        
        # Update appointment
        self.cursor.execute("UPDATE appointments SET age = ?, location = ? WHERE name = ?", 
                           (31, 'Chicago', 'John Doe'))
        self.conn.commit()
        
        # Verify update
        self.cursor.execute("SELECT * FROM appointments WHERE name = ?", ('John Doe',))
        result = self.cursor.fetchone()
        
        self.assertEqual(result[2], 31)
        self.assertEqual(result[4], 'Chicago')
    
    def test_appointment_deletion(self):
        """Test deleting appointments"""
        # Insert test appointment
        self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                           ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890'))
        self.conn.commit()
        
        # Delete appointment
        self.cursor.execute("DELETE FROM appointments WHERE name = ?", ('John Doe',))
        self.conn.commit()
        
        # Verify deletion
        self.cursor.execute("SELECT * FROM appointments WHERE name = ?", ('John Doe',))
        result = self.cursor.fetchone()
        
        self.assertIsNone(result)
    
    def test_user_credentials(self):
        """Test user credential operations"""
        # Insert test user
        user_data = ('test_user', 'Test User', 'password123', 'Doctor', None, True, 'Fluffy', False, '', False, '', 'test@email.com')
        self.cursor.execute("INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", user_data)
        self.conn.commit()
        
        # Verify user creation
        self.cursor.execute("SELECT * FROM credentials WHERE id = ?", ('test_user',))
        result = self.cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[1], 'Test User')
        self.assertEqual(result[2], 'password123')
        self.assertEqual(result[3], 'Doctor')

# =============================================================================
# 2. VALIDATION TESTS - Testing input validation
# =============================================================================

class TestInputValidation(unittest.TestCase):
    """Test input validation for various fields"""
    
    def test_phone_validation(self):
        """Test phone number validation"""
        valid_phones = ['+1234567890', '123-456-7890', '(123) 456-7890']
        invalid_phones = ['123', 'abc', '+12345', '']
        
        def is_valid_phone(phone):
            # Simple phone validation pattern
            pattern = r'^[\+\-\(\)\s\d]{10,}$'
            return bool(re.match(pattern, phone)) and any(c.isdigit() for c in phone)
        
        for phone in valid_phones:
            self.assertTrue(is_valid_phone(phone), f"Phone {phone} should be valid")
        
        for phone in invalid_phones:
            self.assertFalse(is_valid_phone(phone), f"Phone {phone} should be invalid")
    
    def test_age_validation(self):
        """Test age validation"""
        def is_valid_age(age_str):
            try:
                age = int(age_str)
                return 0 < age < 150
            except ValueError:
                return False
        
        self.assertTrue(is_valid_age('25'))
        self.assertTrue(is_valid_age('1'))
        self.assertTrue(is_valid_age('100'))
        
        self.assertFalse(is_valid_age('0'))
        self.assertFalse(is_valid_age('-5'))
        self.assertFalse(is_valid_age('abc'))
        self.assertFalse(is_valid_age('150'))
    
    def test_time_validation(self):
        """Test appointment time validation"""
        def is_valid_time(time_str):
            try:
                time_parts = time_str.split(':')
                if len(time_parts) != 2:
                    return False
                hour, minute = int(time_parts[0]), int(time_parts[1])
                return 0 <= hour <= 23 and 0 <= minute <= 59
            except ValueError:
                return False
        
        self.assertTrue(is_valid_time('10:30'))
        self.assertTrue(is_valid_time('00:00'))
        self.assertTrue(is_valid_time('23:59'))
        
        self.assertFalse(is_valid_time('24:00'))
        self.assertFalse(is_valid_time('10:60'))
        self.assertFalse(is_valid_time('abc'))
        self.assertFalse(is_valid_time('10'))
    
    def test_name_validation(self):
        """Test name validation"""
        def is_valid_name(name):
            return len(name.strip()) > 0 and name.replace(' ', '').replace('-', '').replace('.', '').isalpha()
        
        self.assertTrue(is_valid_name('John Doe'))
        self.assertTrue(is_valid_name('Mary-Jane'))
        self.assertTrue(is_valid_name('Dr. Smith'))
        
        self.assertFalse(is_valid_name(''))
        self.assertFalse(is_valid_name('   '))
        self.assertFalse(is_valid_name('John123'))

# =============================================================================
# 3. BUSINESS LOGIC TESTS - Testing application logic
# =============================================================================

class TestBusinessLogic(unittest.TestCase):
    """Test business logic and workflows"""
    
    def test_appointment_scheduling_logic(self):
        """Test appointment scheduling business rules"""
        def can_schedule_appointment(time_slot, existing_appointments):
            """Check if a time slot is available"""
            return time_slot not in existing_appointments
        
        existing_appointments = ['10:00', '14:00', '16:30']
        
        self.assertTrue(can_schedule_appointment('11:00', existing_appointments))
        self.assertFalse(can_schedule_appointment('10:00', existing_appointments))
    
    def test_user_role_permissions(self):
        """Test user role-based permissions"""
        def has_permission(user_role, action):
            permissions = {
                'System Administrator': ['add', 'edit', 'delete', 'view'],
                'Doctor': ['add', 'edit', 'delete', 'view'],
                'Guest': ['view']
            }
            return action in permissions.get(user_role, [])
        
        self.assertTrue(has_permission('System Administrator', 'delete'))
        self.assertTrue(has_permission('Doctor', 'add'))
        self.assertTrue(has_permission('Guest', 'view'))
        self.assertFalse(has_permission('Guest', 'delete'))
        self.assertFalse(has_permission('Nurse', 'add'))  # Unknown role
    
    def test_password_reset_logic(self):
        """Test password reset functionality"""
        def generate_verification_code():
            import random
            import string
            return ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        def validate_secret_answer(stored_answer, provided_answer):
            return stored_answer.lower().strip() == provided_answer.lower().strip()
        
        code = generate_verification_code()
        self.assertEqual(len(code), 12)
        self.assertTrue(code.isalnum())
        
        self.assertTrue(validate_secret_answer('Fluffy', 'fluffy'))
        self.assertTrue(validate_secret_answer('  Fluffy  ', 'Fluffy'))
        self.assertFalse(validate_secret_answer('Fluffy', 'Max'))

# =============================================================================
# 4. UI COMPONENT TESTS - Testing GUI components
# =============================================================================

class TestUIComponents(unittest.TestCase):
    """Test UI components and interactions"""
    
    def setUp(self):
        """Set up test environment"""
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the window during tests
    
    def tearDown(self):
        """Clean up"""
        if self.root:
            self.root.destroy()
    
    def test_form_validation(self):
        """Test form field validation"""
        def validate_form(fields):
            """Validate all form fields are filled"""
            return all(field.strip() for field in fields.values())
        
        valid_form = {
            'name': 'John Doe',
            'age': '30',
            'gender': 'Male',
            'location': 'New York',
            'time': '10:30',
            'phone': '+1234567890'
        }
        
        invalid_form = {
            'name': '',
            'age': '30',
            'gender': 'Male',
            'location': 'New York',
            'time': '10:30',
            'phone': '+1234567890'
        }
        
        self.assertTrue(validate_form(valid_form))
        self.assertFalse(validate_form(invalid_form))
    
    def test_login_validation(self):
        """Test login credential validation"""
        def validate_login(username, password, stored_credentials):
            """Validate login credentials"""
            if not username or not password:
                return False, "All credentials required"
            
            if username in stored_credentials:
                if stored_credentials[username]['password'] == password:
                    return True, f"Welcome {stored_credentials[username]['name']}"
                else:
                    return False, "Invalid credentials"
            return False, "User not found"
        
        credentials = {
            'admin': {'password': 'admin123', 'name': 'Administrator'},
            'doctor1': {'password': 'doc123', 'name': 'Dr. Smith'}
        }
        
        # Valid login
        success, msg = validate_login('admin', 'admin123', credentials)
        self.assertTrue(success)
        self.assertIn('Welcome', msg)
        
        # Invalid password
        success, msg = validate_login('admin', 'wrong', credentials)
        self.assertFalse(success)
        self.assertEqual(msg, "Invalid credentials")
        
        # Empty fields
        success, msg = validate_login('', '', credentials)
        self.assertFalse(success)
        self.assertEqual(msg, "All credentials required")

# =============================================================================
# 5. INTEGRATION TESTS - Testing component interactions
# =============================================================================

class TestIntegration(unittest.TestCase):
    """Test integration between different components"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.test_db_path = 'integration_test_db.db'
        self.conn = sqlite3.connect(self.test_db_path)
        self.cursor = self.conn.cursor()
        
        # Set up test tables
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT NOT NULL,
                              age INTEGER NOT NULL,
                              gender TEXT NOT NULL,
                              location TEXT NOT NULL,
                              scheduled_time TEXT NOT NULL,
                              phone TEXT NOT NULL,
                              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up"""
        self.conn.close()
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_appointment_workflow(self):
        """Test complete appointment management workflow"""
        # 1. Create appointment
        appointment_data = ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890')
        self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                           appointment_data)
        self.conn.commit()
        
        # 2. Search for appointment
        self.cursor.execute("SELECT * FROM appointments WHERE name LIKE ?", ('John Doe',))
        result = self.cursor.fetchone()
        self.assertIsNotNone(result)
        
        # 3. Update appointment
        self.cursor.execute("UPDATE appointments SET location = ? WHERE name = ?", ('Boston', 'John Doe'))
        self.conn.commit()
        
        # 4. Verify update
        self.cursor.execute("SELECT location FROM appointments WHERE name = ?", ('John Doe',))
        updated_location = self.cursor.fetchone()[0]
        self.assertEqual(updated_location, 'Boston')
        
        # 5. Delete appointment
        self.cursor.execute("DELETE FROM appointments WHERE name = ?", ('John Doe',))
        self.conn.commit()
        
        # 6. Verify deletion
        self.cursor.execute("SELECT * FROM appointments WHERE name = ?", ('John Doe',))
        result = self.cursor.fetchone()
        self.assertIsNone(result)
    
    def test_search_functionality(self):
        """Test search functionality with various scenarios"""
        # Insert test data
        appointments = [
            ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890'),
            ('Jane Doe', 25, 'Female', 'Boston', '14:00', '+0987654321'),
            ('Bob Smith', 40, 'Male', 'Chicago', '16:00', '+1122334455')
        ]
        
        for appointment in appointments:
            self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                               appointment)
        self.conn.commit()
        
        # Test exact match
        self.cursor.execute("SELECT * FROM appointments WHERE name = ?", ('John Doe',))
        results = self.cursor.fetchall()
        self.assertEqual(len(results), 1)
        
        # Test partial match
        self.cursor.execute("SELECT * FROM appointments WHERE name LIKE ?", ('%Doe%',))
        results = self.cursor.fetchall()
        self.assertEqual(len(results), 2)
        
        # Test no match
        self.cursor.execute("SELECT * FROM appointments WHERE name LIKE ?", ('NonExistent',))
        results = self.cursor.fetchall()
        self.assertEqual(len(results), 0)

# =============================================================================
# 6. PERFORMANCE TESTS - Testing system performance
# =============================================================================

class TestPerformance(unittest.TestCase):
    """Test performance characteristics"""
    
    def setUp(self):
        """Set up performance test environment"""
        self.test_db_path = 'performance_test_db.db'
        self.conn = sqlite3.connect(self.test_db_path)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT NOT NULL,
                              age INTEGER NOT NULL,
                              gender TEXT NOT NULL,
                              location TEXT NOT NULL,
                              scheduled_time TEXT NOT NULL,
                              phone TEXT NOT NULL,
                              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up"""
        self.conn.close()
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_bulk_insert_performance(self):
        """Test performance of bulk insert operations"""
        start_time = time.time()
        
        # Insert 1000 test appointments
        appointments = []
        for i in range(1000):
            appointments.append((f'Patient_{i}', 25 + (i % 50), 'Male', 'Test City', '10:00', f'+123456{i:04d}'))
        
        self.cursor.executemany("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                               appointments)
        self.conn.commit()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete in reasonable time (less than 5 seconds for 1000 records)
        self.assertLess(execution_time, 5.0)
        
        # Verify all records were inserted
        self.cursor.execute("SELECT COUNT(*) FROM appointments")
        count = self.cursor.fetchone()[0]
        self.assertEqual(count, 1000)
    
    def test_search_performance(self):
        """Test search performance with large dataset"""
        # Insert test data
        appointments = []
        for i in range(1000):
            appointments.append((f'Patient_{i}', 25 + (i % 50), 'Male', 'Test City', '10:00', f'+123456{i:04d}'))
        
        self.cursor.executemany("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                               appointments)
        self.conn.commit()
        
        # Test search performance
        start_time = time.time()
        
        for i in range(100):
            search_name = f'Patient_{i * 10}'
            self.cursor.execute("SELECT * FROM appointments WHERE name = ?", (search_name,))
            result = self.cursor.fetchone()
            self.assertIsNotNone(result)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # 100 searches should complete quickly (less than 1 second)
        self.assertLess(execution_time, 1.0)

# =============================================================================
# 7. SECURITY TESTS - Testing security aspects
# =============================================================================

class TestSecurity(unittest.TestCase):
    """Test security-related functionality"""
    
    def test_sql_injection_prevention(self):
        """Test protection against SQL injection"""
        test_db_path = 'security_test_db.db'
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                         (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT NOT NULL,
                          age INTEGER NOT NULL,
                          gender TEXT NOT NULL,
                          location TEXT NOT NULL,
                          scheduled_time TEXT NOT NULL,
                          phone TEXT NOT NULL)''')
        
        # Insert test data
        cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                      ('John Doe', 30, 'Male', 'New York', '10:30', '+1234567890'))
        conn.commit()
        
        # Test parameterized query (safe)
        malicious_input = "'; DROP TABLE appointments; --"
        cursor.execute("SELECT * FROM appointments WHERE name = ?", (malicious_input,))
        results = cursor.fetchall()
        
        # Should return no results without causing damage
        self.assertEqual(len(results), 0)
        
        # Verify table still exists
        cursor.execute("SELECT COUNT(*) FROM appointments")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)  # Original record should still be there
        
        conn.close()
        os.remove(test_db_path)
    
    def test_password_security(self):
        """Test password security measures"""
        def hash_password(password):
            """Simple password hashing simulation"""
            return hashlib.sha256(password.encode()).hexdigest()
        
        def verify_password(stored_hash, provided_password):
            """Verify password against stored hash"""
            return stored_hash == hash_password(provided_password)
        
        password = "secure123"
        hashed = hash_password(password)
        
        # Password should be hashed (not stored in plain text)
        self.assertNotEqual(password, hashed)
        self.assertEqual(len(hashed), 64)  # SHA256 produces 64-character hex string
        
        # Verification should work
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "wrong_password"))
    
    def test_input_sanitization(self):
        """Test input sanitization"""
        def sanitize_input(user_input):
            """Basic input sanitization"""
            # Remove potentially dangerous characters
            dangerous_chars = ['<', '>', '&', '"', "'", ';']
            sanitized = user_input
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '')
            return sanitized.strip()
        
        # Test normal input
        normal_input = "John Doe"
        self.assertEqual(sanitize_input(normal_input), "John Doe")
        
        # Test malicious input
        malicious_input = "<script>alert('XSS')</script>"
        sanitized = sanitize_input(malicious_input)
        self.assertNotIn('<', sanitized)
        self.assertNotIn('>', sanitized)
        self.assertEqual(sanitized, "scriptalert('XSS')/script")

# =============================================================================
# 8. ERROR HANDLING TESTS - Testing error scenarios
# =============================================================================

class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def test_database_connection_error(self):
        """Test handling of database connection errors"""
        def safe_db_operation(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                conn.close()
                return True, "Success"
            except sqlite3.Error as e:
                return False, f"Database error: {e}"
            except Exception as e:
                return False, f"Unexpected error: {e}"
        
        # Test with valid database
        success, msg = safe_db_operation(':memory:')
        self.assertTrue(success)
        
        # Test with invalid path (should handle gracefully)
        success, msg = safe_db_operation('/invalid/path/database.db')
        self.assertFalse(success)
        self.assertIn("error", msg.lower())
    
    def test_invalid_data_handling(self):
        """Test handling of invalid data inputs"""
        def process_appointment_data(data):
            errors = []
            
            # Validate name
            if not data.get('name') or not data['name'].strip():
                errors.append("Name is required")
            
            # Validate age
            try:
                age = int(data.get('age', 0))
                if age <= 0 or age > 150:
                    errors.append("Invalid age")
            except ValueError:
                errors.append("Age must be a number")
            
            # Validate phone
            phone = data.get('phone', '')
            if len(phone) < 10:
                errors.append("Invalid phone number")
            
            return len(errors) == 0, errors
        
        # Test valid data
        valid_data = {'name': 'John Doe', 'age': '30', 'phone': '+1234567890'}
        is_valid, errors = process_appointment_data(valid_data)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
        
        # Test invalid data
        invalid_data = {'name': '', 'age': 'abc', 'phone': '123'}
        is_valid, errors = process_appointment_data(invalid_data)
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)
        self.assertIn("Name is required", errors)
        self.assertIn("Age must be a number", errors)
        self.assertIn("Invalid phone number", errors)
    
    def test_concurrent_access(self):
        """Test handling of concurrent database access"""
        test_db_path = 'concurrent_test_db.db'
        
        def create_appointments_table():
            conn = sqlite3.connect(test_db_path)
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT NOT NULL,
                              age INTEGER NOT NULL,
                              gender TEXT NOT NULL,
                              location TEXT NOT NULL,
                              scheduled_time TEXT NOT NULL,
                              phone TEXT NOT NULL)''')
            conn.commit()
            conn.close()
        
        def insert_appointment(name):
            try:
                conn = sqlite3.connect(test_db_path)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                              (name, 30, 'Male', 'Test', '10:00', '+1234567890'))
                conn.commit()
                conn.close()
                return True
            except Exception as e:
                return False
        
        create_appointments_table()
        
        # Create multiple threads to simulate concurrent access
        threads = []
        for i in range(5):
            thread = threading.Thread(target=insert_appointment, args=(f'Patient_{i}',))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all appointments were inserted
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM appointments")
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertEqual(count, 5)
        
        # Clean up
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

# =============================================================================
# 9. TEST RUNNER AND REPORTING
# =============================================================================

class TestRunner:
    """Custom test runner with detailed reporting"""
    
    def __init__(self):
        self.results = {}
    
    def run_all_tests(self):
        """Run all test suites and generate report"""
        test_classes = [
            TestDatabaseOperations,
            TestInputValidation,
            TestBusinessLogic,
            TestUIComponents,
            TestIntegration,
            TestPerformance,
            TestSecurity,
            TestErrorHandling
        ]
        
        total_tests = 0
        total_failures = 0
        total_errors = 0
        
        print("=" * 80)
        print("HEALTHCARE MANAGEMENT SYSTEM - AUTOMATION TEST REPORT")
        print("=" * 80)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        for test_class in test_classes:
            print(f"Running {test_class.__name__}...")
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
            result = runner.run(suite)
            
            tests_run = result.testsRun
            failures = len(result.failures)
            errors = len(result.errors)
            
            total_tests += tests_run
            total_failures += failures
            total_errors += errors
            
            status = "PASSED" if failures == 0 and errors == 0 else "FAILED"
            print(f"  {test_class.__name__}: {tests_run} tests, {failures} failures, {errors} errors - {status}")
            
            self.results[test_class.__name__] = {
                'tests': tests_run,
                'failures': failures,
                'errors': errors,
                'status': status
            }
        
        print()
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"Failures: {total_failures}")
        print(f"Errors: {total_errors}")
        print(f"Success Rate: {((total_tests - total_failures - total_errors) / total_tests * 100):.1f}%" if total_tests > 0 else "0%")
        print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        return self.results

# =============================================================================
# 10. LOAD TESTING - Testing system under load
# =============================================================================

class LoadTester:
    """Load testing for the healthcare system"""
    
    def __init__(self, db_path='load_test_db.db'):
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Set up database for load testing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                         (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT NOT NULL,
                          age INTEGER NOT NULL,
                          gender TEXT NOT NULL,
                          location TEXT NOT NULL,
                          scheduled_time TEXT NOT NULL,
                          phone TEXT NOT NULL,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()
    
    def simulate_concurrent_users(self, num_users=10, operations_per_user=50):
        """Simulate multiple concurrent users"""
        def user_operations(user_id):
            """Simulate operations for a single user"""
            operations_completed = 0
            errors = 0
            
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for i in range(operations_per_user):
                    try:
                        operation = i % 4  # Cycle through different operations
                        
                        if operation == 0:  # Create appointment
                            cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                                         (f'User{user_id}_Patient{i}', 25, 'Male', 'Test City', '10:00', f'+123{user_id}{i:03d}'))
                        elif operation == 1:  # Search appointment
                            cursor.execute("SELECT * FROM appointments WHERE name LIKE ?", (f'User{user_id}%',))
                            cursor.fetchall()
                        elif operation == 2:  # Update appointment
                            cursor.execute("UPDATE appointments SET age = ? WHERE name LIKE ?", (30, f'User{user_id}%'))
                        else:  # Count appointments
                            cursor.execute("SELECT COUNT(*) FROM appointments WHERE name LIKE ?", (f'User{user_id}%',))
                            cursor.fetchone()
                        
                        conn.commit()
                        operations_completed += 1
                        
                    except Exception as e:
                        errors += 1
                        print(f"User {user_id} operation {i} failed: {e}")
                
                conn.close()
                
            except Exception as e:
                print(f"User {user_id} failed to connect: {e}")
                errors += operations_per_user
            
            return operations_completed, errors
        
        print(f"Starting load test with {num_users} concurrent users...")
        start_time = time.time()
        
        threads = []
        for user_id in range(num_users):
            thread = threading.Thread(target=user_operations, args=(user_id,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Verify database integrity
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM appointments")
        total_records = cursor.fetchone()[0]
        conn.close()
        
        print(f"Load test completed in {total_time:.2f} seconds")
        print(f"Total records created: {total_records}")
        print(f"Average operations per second: {(num_users * operations_per_user) / total_time:.2f}")
        
        # Clean up
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

# =============================================================================
# 11. API SIMULATION TESTS - Testing API-like functionality
# =============================================================================

class TestAPISimulation(unittest.TestCase):
    """Simulate API testing for future web service conversion"""
    
    def setUp(self):
        """Set up API simulation environment"""
        self.test_db_path = 'api_test_db.db'
        self.conn = sqlite3.connect(self.test_db_path)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT NOT NULL,
                              age INTEGER NOT NULL,
                              gender TEXT NOT NULL,
                              location TEXT NOT NULL,
                              scheduled_time TEXT NOT NULL,
                              phone TEXT NOT NULL,
                              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        self.conn.commit()
    
    def tearDown(self):
        """Clean up"""
        self.conn.close()
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def simulate_api_request(self, method, endpoint, data=None):
        """Simulate API request handling"""
        try:
            if method == 'POST' and endpoint == '/appointments':
                # Create appointment
                if not data or not all(key in data for key in ['name', 'age', 'gender', 'location', 'scheduled_time', 'phone']):
                    return {'status': 400, 'error': 'Missing required fields'}
                
                self.cursor.execute("INSERT INTO appointments (name, age, gender, location, scheduled_time, phone) VALUES (?, ?, ?, ?, ?, ?)", 
                                   (data['name'], data['age'], data['gender'], data['location'], data['scheduled_time'], data['phone']))
                self.conn.commit()
                
                appointment_id = self.cursor.lastrowid
                return {'status': 201, 'id': appointment_id, 'message': 'Appointment created successfully'}
            
            elif method == 'GET' and endpoint.startswith('/appointments/'):
                # Get specific appointment
                appointment_id = endpoint.split('/')[-1]
                self.cursor.execute("SELECT * FROM appointments WHERE ID = ?", (appointment_id,))
                result = self.cursor.fetchone()
                
                if result:
                    appointment = {
                        'id': result[0],
                        'name': result[1],
                        'age': result[2],
                        'gender': result[3],
                        'location': result[4],
                        'scheduled_time': result[5],
                        'phone': result[6],
                        'created_at': result[7]
                    }
                    return {'status': 200, 'data': appointment}
                else:
                    return {'status': 404, 'error': 'Appointment not found'}
            
            elif method == 'GET' and endpoint == '/appointments':
                # List all appointments
                self.cursor.execute("SELECT * FROM appointments")
                results = self.cursor.fetchall()
                
                appointments = []
                for result in results:
                    appointments.append({
                        'id': result[0],
                        'name': result[1],
                        'age': result[2],
                        'gender': result[3],
                        'location': result[4],
                        'scheduled_time': result[5],
                        'phone': result[6],
                        'created_at': result[7]
                    })
                
                return {'status': 200, 'data': appointments, 'count': len(appointments)}
            
            elif method == 'PUT' and endpoint.startswith('/appointments/'):
                # Update appointment
                appointment_id = endpoint.split('/')[-1]
                
                if not data:
                    return {'status': 400, 'error': 'No data provided'}
                
                # Check if appointment exists
                self.cursor.execute("SELECT * FROM appointments WHERE ID = ?", (appointment_id,))
                if not self.cursor.fetchone():
                    return {'status': 404, 'error': 'Appointment not found'}
                
                # Update fields
                update_fields = []
                values = []
                
                for field in ['name', 'age', 'gender', 'location', 'scheduled_time', 'phone']:
                    if field in data:
                        update_fields.append(f"{field} = ?")
                        values.append(data[field])
                
                if update_fields:
                    values.append(appointment_id)
                    query = f"UPDATE appointments SET {', '.join(update_fields)} WHERE ID = ?"
                    self.cursor.execute(query, values)
                    self.conn.commit()
                    return {'status': 200, 'message': 'Appointment updated successfully'}
                
                return {'status': 400, 'error': 'No valid fields to update'}
            
            elif method == 'DELETE' and endpoint.startswith('/appointments/'):
                # Delete appointment
                appointment_id = endpoint.split('/')[-1]
                
                # Check if appointment exists
                self.cursor.execute("SELECT * FROM appointments WHERE ID = ?", (appointment_id,))
                if not self.cursor.fetchone():
                    return {'status': 404, 'error': 'Appointment not found'}
                
                self.cursor.execute("DELETE FROM appointments WHERE ID = ?", (appointment_id,))
                self.conn.commit()
                return {'status': 200, 'message': 'Appointment deleted successfully'}
            
            else:
                return {'status': 405, 'error': 'Method not allowed'}
                
        except Exception as e:
            return {'status': 500, 'error': f'Internal server error: {str(e)}'}
    
    def test_create_appointment_api(self):
        """Test appointment creation via API simulation"""
        data = {
            'name': 'John Doe',
            'age': 30,
            'gender': 'Male',
            'location': 'New York',
            'scheduled_time': '10:30',
            'phone': '+1234567890'
        }
        
        response = self.simulate_api_request('POST', '/appointments', data)
        
        self.assertEqual(response['status'], 201)
        self.assertIn('id', response)
        self.assertEqual(response['message'], 'Appointment created successfully')
    
    def test_get_appointment_api(self):
        """Test retrieving appointment via API simulation"""
        # First create an appointment
        data = {
            'name': 'Jane Doe',
            'age': 25,
            'gender': 'Female',
            'location': 'Boston',
            'scheduled_time': '14:00',
            'phone': '+0987654321'
        }
        
        create_response = self.simulate_api_request('POST', '/appointments', data)
        appointment_id = create_response['id']
        
        # Then retrieve it
        response = self.simulate_api_request('GET', f'/appointments/{appointment_id}')
        
        self.assertEqual(response['status'], 200)
        self.assertIn('data', response)
        self.assertEqual(response['data']['name'], 'Jane Doe')
        self.assertEqual(response['data']['age'], 25)
    
    def test_update_appointment_api(self):
        """Test updating appointment via API simulation"""
        # Create appointment
        data = {
            'name': 'Bob Smith',
            'age': 40,
            'gender': 'Male',
            'location': 'Chicago',
            'scheduled_time': '16:00',
            'phone': '+1122334455'
        }
        
        create_response = self.simulate_api_request('POST', '/appointments', data)
        appointment_id = create_response['id']
        
        # Update appointment
        update_data = {
            'age': 41,
            'location': 'Miami'
        }
        
        response = self.simulate_api_request('PUT', f'/appointments/{appointment_id}', update_data)
        
        self.assertEqual(response['status'], 200)
        self.assertEqual(response['message'], 'Appointment updated successfully')
        
        # Verify update
        get_response = self.simulate_api_request('GET', f'/appointments/{appointment_id}')
        self.assertEqual(get_response['data']['age'], 41)
        self.assertEqual(get_response['data']['location'], 'Miami')
    
    def test_delete_appointment_api(self):
        """Test deleting appointment via API simulation"""
        # Create appointment
        data = {
            'name': 'Alice Johnson',
            'age': 35,
            'gender': 'Female',
            'location': 'Seattle',
            'scheduled_time': '11:00',
            'phone': '+5566778899'
        }
        
        create_response = self.simulate_api_request('POST', '/appointments', data)
        appointment_id = create_response['id']
        
        # Delete appointment
        response = self.simulate_api_request('DELETE', f'/appointments/{appointment_id}')
        
        self.assertEqual(response['status'], 200)
        self.assertEqual(response['message'], 'Appointment deleted successfully')
        
        # Verify deletion
        get_response = self.simulate_api_request('GET', f'/appointments/{appointment_id}')
        self.assertEqual(get_response['status'], 404)
    
    def test_api_error_handling(self):
        """Test API error handling"""
        # Test missing fields
        incomplete_data = {'name': 'John Doe'}
        response = self.simulate_api_request('POST', '/appointments', incomplete_data)
        self.assertEqual(response['status'], 400)
        self.assertIn('Missing required fields', response['error'])
        
        # Test non-existent appointment
        response = self.simulate_api_request('GET', '/appointments/999')
        self.assertEqual(response['status'], 404)
        
        # Test invalid method
        response = self.simulate_api_request('PATCH', '/appointments')
        self.assertEqual(response['status'], 405)

# =============================================================================
# 12. COMPATIBILITY TESTS - Testing cross-platform compatibility
# =============================================================================

class TestCompatibility(unittest.TestCase):
    """Test cross-platform compatibility"""
    
    def test_file_path_handling(self):
        """Test file path handling across platforms"""
        import platform
        
        def get_resource_path(filename):
            """Get platform-appropriate resource path"""
            if platform.system() == 'Windows':
                return f"resources\\{filename}"
            else:
                return f"resources/{filename}"
        
        # Test different platforms
        expected_paths = {
            'Windows': 'resources\\icon.png',
            'Linux': 'resources/icon.png',
            'Darwin': 'resources/icon.png'  # macOS
        }
        
        for system, expected_path in expected_paths.items():
            with patch('platform.system', return_value=system):
                actual_path = get_resource_path('icon.png')
                self.assertEqual(actual_path, expected_path)
    
    def test_database_compatibility(self):
        """Test SQLite database compatibility"""
        # Create database with various data types
        test_db = 'compatibility_test.db'
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE test_compatibility 
                         (id INTEGER, 
                          text_field TEXT, 
                          real_field REAL, 
                          blob_field BLOB,
                          date_field TIMESTAMP)''')
        
        # Insert test data
        import datetime
        test_data = (1, 'Test String', 3.14, b'binary_data', datetime.datetime.now())
        cursor.execute("INSERT INTO test_compatibility VALUES (?, ?, ?, ?, ?)", test_data)
        conn.commit()
        
        # Retrieve and verify
        cursor.execute("SELECT * FROM test_compatibility WHERE id = 1")
        result = cursor.fetchone()
        
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], 'Test String')
        self.assertAlmostEqual(result[2], 3.14, places=2)
        
        conn.close()
        os.remove(test_db)
    
    def test_encoding_handling(self):
        """Test Unicode and special character handling"""
        test_names = [
            'José García',
            '王小明',
            'Müller',
            'O\'Brien',
            'Smith-Jones'
        ]
        
        test_db = 'encoding_test.db'
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE encoding_test (id INTEGER PRIMARY KEY, name TEXT)''')
        
        # Insert names with special characters
        for i, name in enumerate(test_names):
            cursor.execute("INSERT INTO encoding_test (name) VALUES (?)", (name,))
        
        conn.commit()
        
        # Retrieve and verify
        cursor.execute("SELECT name FROM encoding_test ORDER BY id")
        results = cursor.fetchall()
        
        retrieved_names = [row[0] for row in results]
        self.assertEqual(retrieved_names, test_names)
        
        conn.close()
        os.remove(test_db)

# =============================================================================
# 13. MAIN EXECUTION SCRIPT
# =============================================================================

def main():
    """Main function to run all tests"""
    print("Healthcare Management System - Comprehensive Testing Suite")
    print("=" * 60)
    
    # Run main test suite
    runner = TestRunner()
    results = runner.run_all_tests()
    
    print("\n" + "=" * 60)
    print("ADDITIONAL TESTS")
    print("=" * 60)
    
    # Run load testing
    print("\nRunning Load Tests...")
    load_tester = LoadTester()
    load_tester.simulate_concurrent_users(num_users=5, operations_per_user=20)
    
    # Run API simulation tests
    print("\nRunning API Simulation Tests...")
    api_suite = unittest.TestLoader().loadTestsFromTestCase(TestAPISimulation)
    api_runner = unittest.TextTestRunner(verbosity=2)
    api_result = api_runner.run(api_suite)
    
    # Run compatibility tests
    print("\nRunning Compatibility Tests...")
    compat_suite = unittest.TestLoader().loadTestsFromTestCase(TestCompatibility)
    compat_runner = unittest.TextTestRunner(verbosity=2)
    compat_result = api_runner.run(compat_suite)
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)
    
    return results

if __name__ == '__main__':
    # Set up test environment
    os.makedirs('resources', exist_ok=True)
    
    # Create a dummy icon file for testing
    dummy_icon_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01\xdd\xcc\xdb\xca\x00\x00\x00\x00IEND\xaeB`\x82'
    
    try:
        with open('resources/icon.png', 'wb') as f:
            f.write(dummy_icon_content)
    except:
        pass
    
    # Run tests
    main()