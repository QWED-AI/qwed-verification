"""
Load testing script - simulate 1000 concurrent users.
Requires: pip install locust

Run with: locust -f tests/load_test.py --host http://13.71.22.94:8000
Then open browser: http://localhost:8089
Set: 1000 users, spawn rate: 50/sec
"""

from locust import HttpUser, task, between
import random

class QWEDUser(HttpUser):
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests
    
    def on_start(self):
        """Setup - runs once per user"""
        self.headers = {
            "x-api-key": "qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI",
            "Content-Type": "application/json"
        }
    
    @task(10)  # Weight: 10 (most common)
    def verify_simple_math(self):
        """Test simple math verification"""
        queries = [
            "What is 2 + 2?",
            "What is 10 * 5?",
            "What is 100 / 4?",
            "What is 15% of 200?",
        ]
        
        self.client.post(
            "/verify/natural_language",
            headers=self.headers,
            json={"query": random.choice(queries)},
            name="Math: Simple"
        )
    
    @task(5)  # Weight: 5
    def verify_complex_math(self):
        """Test complex calculations"""
        queries = [
            "What is 15% of 200 plus 5% of 300?",
            "Calculate compound interest on $1000 at 5% for 2 years",
            "What is the square root of 144 times 2?",
        ]
        
        self.client.post(
            "/verify/natural_language",
            headers=self.headers,
            json={"query": random.choice(queries)},
            name="Math: Complex"
        )
    
    @task(3)  # Weight: 3
    def verify_logic(self):
        """Test logic verification"""
        queries = [
            "x > 5 and x < 10",
            "y == 42",
            "a + b == 100 and a > 50",
        ]
        
        self.client.post(
            "/verify/logic",
            headers=self.headers,
            json={"query": random.choice(queries)},
            name="Logic"
        )
    
    @task(1)  # Weight: 1 (least common)
    def check_health(self):
        """Test health endpoint"""
        self.client.get("/health", name="Health Check")
    
    @task(2)
    def get_logs(self):
        """Test logs endpoint"""
        self.client.get("/logs?limit=5", headers=self.headers, name="Audit Logs")


class StressTestUser(HttpUser):
    """Aggressive testing - rapid fire requests"""
    wait_time = between(0.1, 0.5)  # Very short wait
    
    def on_start(self):
        self.headers = {
            "x-api-key": "qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI",
            "Content-Type": "application/json"
        }
    
    @task
    def rapid_fire_math(self):
        """Stress test with rapid requests"""
        self.client.post(
            "/verify/natural_language",
            headers=self.headers,
            json={"query": "What is 2 + 2?"},
            name="Stress: Rapid Math"
        )
