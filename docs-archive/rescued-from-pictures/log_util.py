import time

def log_event(event):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {event}"
    print(line)
    with open("defense_actions.log", "a") as f:
        f.write(line + "\n")