import sys, json
from client import PromptGuardInjectionSanitizerClient
sys.stdout.reconfigure(encoding='utf-8')

def handle_mcp():
    guard = PromptGuardInjectionSanitizerClient()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps({"status": "ready", "skill": "genpark-agent-prompt-guard-injection-sanitizer-skill"}))
        return
    req = json.loads(sys.stdin.read() or "{}")
    text = req.get("text", "")
    res = guard.sanitize(text)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    handle_mcp()
