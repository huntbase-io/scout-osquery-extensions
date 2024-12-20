import platform
import psutil
import json

def main():
    # Collect system information
    system_info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "cpu_count": psutil.cpu_count(logical=True),
        "memory_total": psutil.virtual_memory().total,
        "disk_usage": psutil.disk_usage('/').percent
    }

    # Print each piece of information in the specified format
    for key, value in system_info.items():
        print(f"\"{key}\": \"{value}\"")

if __name__ == "__main__":
    main()