import requests
import json
import jwt
import time
from datetime import datetime, timedelta
import unittest
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/app/backend/.env')

# Get backend URL from frontend .env
with open('/app/frontend/.env', 'r') as f:
    for line in f:
        if line.startswith('REACT_APP_BACKEND_URL='):
            BACKEND_URL = line.strip().split('=')[1].strip('"\'')
            break

# API base URL
API_URL = f"{BACKEND_URL}/api"

# JWT Secret for creating test tokens
JWT_SECRET = os.environ.get('SECRET_KEY', 'your-super-secret-jwt-key-here-make-it-very-long-and-random-for-production')

class TestGoogleOAuth(unittest.TestCase):
    
    def create_test_token(self, sub="test_google_id", email="test@example.com", name="Test User", expired=False):
        """Create a test JWT token for authentication testing"""
        payload = {
            "sub": sub,
            "email": email,
            "name": name
        }
        
        if expired:
            # Create an expired token (expired 1 hour ago)
            payload["exp"] = datetime.utcnow() - timedelta(hours=1)
        else:
            # Valid for 24 hours
            payload["exp"] = datetime.utcnow() + timedelta(hours=24)
            
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    def test_root_endpoint(self):
        """Test the root endpoint to ensure API is accessible"""
        response = requests.get(f"{API_URL}/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "Hello World")
        print("✅ Root endpoint test passed")
    
    def test_google_login_redirect(self):
        """Test that the Google login endpoint redirects to Google"""
        response = requests.get(f"{API_URL}/auth/login/google", allow_redirects=False)
        self.assertEqual(response.status_code, 307)  # Temporary redirect
        location = response.headers.get('Location', '')
        self.assertTrue('accounts.google.com' in location, f"Expected Google redirect, got: {location}")
        print("✅ Google login redirect test passed")
    
    def test_auth_me_unauthorized(self):
        """Test that /auth/me requires authentication"""
        response = requests.get(f"{API_URL}/auth/me")
        self.assertEqual(response.status_code, 401)
        print("✅ Unauthorized access to /auth/me test passed")
    
    def test_auth_me_invalid_token(self):
        """Test that /auth/me rejects invalid tokens"""
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = requests.get(f"{API_URL}/auth/me", headers=headers)
        self.assertEqual(response.status_code, 401)
        print("✅ Invalid token test passed")
    
    def test_auth_me_expired_token(self):
        """Test that /auth/me rejects expired tokens"""
        expired_token = self.create_test_token(expired=True)
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = requests.get(f"{API_URL}/auth/me", headers=headers)
        self.assertEqual(response.status_code, 401)
        print("✅ Expired token test passed")
    
    def test_auth_me_valid_token(self):
        """
        Test /auth/me with a valid token
        Note: This test will fail in a real environment as the token is mocked
        and the user doesn't exist in the database
        """
        valid_token = self.create_test_token()
        headers = {"Authorization": f"Bearer {valid_token}"}
        response = requests.get(f"{API_URL}/auth/me", headers=headers)
        # This will fail with 404 "User not found" as our test user doesn't exist in DB
        # We're just checking that token validation works
        self.assertEqual(response.status_code, 404)
        print("✅ Valid token format test passed (expected 404 as test user doesn't exist)")
    
    def test_profile_update_unauthorized(self):
        """Test that profile update requires authentication"""
        data = {"name": "Updated Name", "about_me": "Test bio", "age": 30}
        response = requests.put(f"{API_URL}/auth/profile", json=data)
        self.assertEqual(response.status_code, 401)
        print("✅ Unauthorized profile update test passed")
    
    def test_profile_update_invalid_token(self):
        """Test that profile update rejects invalid tokens"""
        data = {"name": "Updated Name", "about_me": "Test bio", "age": 30}
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = requests.put(f"{API_URL}/auth/profile", json=data, headers=headers)
        self.assertEqual(response.status_code, 401)
        print("✅ Invalid token for profile update test passed")
    
    def test_profile_update_valid_token(self):
        """
        Test profile update with a valid token
        Note: This test will fail in a real environment as the token is mocked
        and the user doesn't exist in the database
        """
        valid_token = self.create_test_token()
        headers = {"Authorization": f"Bearer {valid_token}"}
        data = {"name": "Updated Name", "about_me": "Test bio", "age": 30}
        response = requests.put(f"{API_URL}/auth/profile", json=data, headers=headers)
        # This will fail with 404 "User not found" as our test user doesn't exist in DB
        # We're just checking that token validation works
        self.assertEqual(response.status_code, 404)
        print("✅ Valid token format for profile update test passed (expected 404 as test user doesn't exist)")
    
    def test_logout(self):
        """Test the logout endpoint"""
        response = requests.post(f"{API_URL}/auth/logout")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "Logged out successfully")
        print("✅ Logout test passed")
    
    def test_invalid_profile_data(self):
        """Test profile update with invalid data"""
        valid_token = self.create_test_token()
        headers = {"Authorization": f"Bearer {valid_token}"}
        
        # Test with invalid age (string instead of int)
        data = {"age": "thirty"}
        response = requests.put(f"{API_URL}/auth/profile", json=data, headers=headers)
        # Should return 422 Unprocessable Entity for validation error
        self.assertEqual(response.status_code, 422)
        print("✅ Invalid profile data validation test passed")

def run_tests():
    """Run all the tests"""
    print(f"Testing API at: {API_URL}")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    test_suite.addTest(TestGoogleOAuth('test_root_endpoint'))
    test_suite.addTest(TestGoogleOAuth('test_google_login_redirect'))
    test_suite.addTest(TestGoogleOAuth('test_auth_me_unauthorized'))
    test_suite.addTest(TestGoogleOAuth('test_auth_me_invalid_token'))
    test_suite.addTest(TestGoogleOAuth('test_auth_me_expired_token'))
    test_suite.addTest(TestGoogleOAuth('test_auth_me_valid_token'))
    test_suite.addTest(TestGoogleOAuth('test_profile_update_unauthorized'))
    test_suite.addTest(TestGoogleOAuth('test_profile_update_invalid_token'))
    test_suite.addTest(TestGoogleOAuth('test_profile_update_valid_token'))
    test_suite.addTest(TestGoogleOAuth('test_logout'))
    test_suite.addTest(TestGoogleOAuth('test_invalid_profile_data'))
    
    # Run the tests
    runner = unittest.TextTestRunner()
    runner.run(test_suite)

if __name__ == "__main__":
    run_tests()