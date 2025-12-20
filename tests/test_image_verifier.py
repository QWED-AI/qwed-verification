import requests
import matplotlib.pyplot as plt
import io

BASE_URL = "http://127.0.0.1:8002"

def create_test_chart():
    """Create a simple line chart showing an upward trend."""
    plt.figure(figsize=(8, 6))
    years = [2020, 2021, 2022, 2023, 2024]
    sales = [100, 120, 150, 200, 250]
    
    plt.plot(years, sales, marker='o')
    plt.title("Annual Sales Growth")
    plt.xlabel("Year")
    plt.ylabel("Sales ($M)")
    plt.grid(True)
    
    # Save to bytes
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return buf

def test_image_verifier():
    print("\n" + "=" * 60)
    print("🖼️ Engine 7: Image Verifier Test")
    print("=" * 60)
    
    # 1. Create Image
    print("Generating test chart...")
    image_buf = create_test_chart()
    
    # 2. Define Test Cases
    test_cases = [
        {
            "claim": "Sales have increased consistently from 2020 to 2024.",
            "expected_verdict": "SUPPORTED"
        },
        {
            "claim": "Sales dropped in 2023.",
            "expected_verdict": "REFUTED"
        },
        {
            "claim": "The CEO's name is Bob.",
            "expected_verdict": "NOT_ENOUGH_INFO"
        }
    ]
    
    for case in test_cases:
        print(f"\n🔹 Testing Claim: '{case['claim']}'")
        
        # Reset buffer position for each request
        image_buf.seek(0)
        
        try:
            files = {'file': ('chart.png', image_buf, 'image/png')}
            data = {'claim': case['claim']}
            
            response = requests.post(f"{BASE_URL}/verify/image", files=files, data=data)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Verdict: {result['verdict']}")
                print(f"📝 Reasoning: {result['reasoning']}")
                print(f"📊 Confidence: {result['confidence']}")
                
                if result['verdict'] == case['expected_verdict']:
                    print("🎯 PASS")
                else:
                    print(f"❌ FAIL (Expected {case['expected_verdict']}, got {result['verdict']})")
            else:
                print(f"❌ API Error: {response.text}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")

if __name__ == "__main__":
    test_image_verifier()
