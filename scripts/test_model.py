import json
import urllib.request
import sys

def test_model():
    req = urllib.request.Request(
        "http://localhost:8080/completion",
        data=json.dumps({"prompt": "Hello", "n_predict": 5}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        print("Model Response Content:", repr(result.get("content", "")))
        print("Model timings:", result.get("timings", {}))
        return result

if __name__ == "__main__":
    test_model()
