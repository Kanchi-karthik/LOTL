import requests
import json
import random

class GeolocationService:
    def __init__(self):
        self.cache = {}
        # Mock data for internal/simulated IPs
        self.mock_locations = [
            {"city": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060, "isp": "Verizon"},
            {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278, "isp": "British Telecom"},
            {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lon": 139.6503, "isp": "SoftBank"},
            {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lon": 103.8198, "isp": "StarHub"},
            {"city": "Berlin", "country": "Germany", "lat": 52.5200, "lon": 13.4050, "isp": "Deutsche Telekom"}
        ]

    def get_location(self, ip):
        """Resolves IP to location data using ip-api.com or mock fallback"""
        if not ip or ip == "127.0.0.1" or ip.startswith("10.") or ip.startswith("192.168."):
            # For local/cluster IPs, return a consistent mock location based on the IP
            random.seed(ip)
            return random.choice(self.mock_locations)

        if ip in self.cache:
            return self.cache[ip]

        try:
            # Using ip-api.com (free, no key required for low volume)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    loc = {
                        "city": data.get("city"),
                        "country": data.get("country"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp")
                    }
                    self.cache[ip] = loc
                    return loc
        except Exception:
            pass

        # Final fallback to mock
        random.seed(ip)
        return random.choice(self.mock_locations)

geo_service = GeolocationService()
