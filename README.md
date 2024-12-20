# Scout Osquery Extension

**Scout** is an osquery extension that provides two powerful tables for executing and managing scripts in a secure and efficient manner.

## Supported Script Types

Scout currently supports the following script types:

- **Python**: Execute limited Python scripts for various automation and data collection tasks.
- **Bash**: Run Bash scripts for system administration and configuration.
- **PowerShell**: Utilize PowerShell scripts for Windows environments.
- **Vbscript**: Execute VB scripts for specific use cases and integrations.

Support for additional script types may be added in future releases based on user feedback and requirements.

## Tables

### 1. `scout_exec`
The `scout_exec` table allows you to run hosted scripts immediately during query time. This is particularly useful for **Live Query** scenarios, where immediate execution and feedback are necessary. In future versions, this table will adopt a pub/sub execution model, allowing for asynchronous or longer-running processes to be handled in a more scalable way.

### 2. `scout_cache`
The `scout_cache` table provides visibility into scripts cached on the endpoint. By caching scripts, Scout minimizes redundant network requests and optimizes resource usage. You can query this table to check whether an endpoint already has the script you need, ensuring faster and more efficient script execution.

## Security

To ensure security, **all scripts must be signed**. The osquery extension is configured with a public key to verify the integrity and authenticity of the scripts before execution. This guarantees that only trusted and verified scripts can be run on your endpoints.

## Running the Extension

### Step 1: Compile the Extension
Once you have compiled the Scout extension, configure it by adding a `scout` block to your osquery configuration file. You will need to specify the URL for your script server and provide a public key for script verification.

- **`server_url`**: The URL where Scout will fetch scripts from.
- **`public_key`**: The public key used to verify the integrity of the scripts.
- **`cache_window`**: Optional - Duration for which the scripts are cached.
- **`exec_timeout`**: Optional - Timeout for script execution.
- **`cache_dir`**: Optional - Directory for caching scripts.

```json
 "scout": {
	"server_url": "http://localhost:5000/scripts",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...Your New Public Key...\n-----END PUBLIC KEY-----",
    "cache_window": 3600,
    "exec_timeout": 60,
    "cache_dir": "/path/to/cache"
  }
```

### Step 2: Start a Content Server
You can use any web server to host signed scripts. For testing purposes, a simple content server and some example scripts are provided in the `content_server` directory.

To start the server:

1. Go to the `content_server` directory.
2. Run your preferred web server (e.g., Python’s built-in server):

```bash
cd content_server
pip install -r requirements.txt
python script_server.py
```

Place any scripts you want to serve to clients in the scripts directory.

### Step 3: Run the Extension with Osquery

After setting up the server, you can run osquery with the Scout Query extension to start executing and caching scripts.

```bash
./build.sh
osqueryi --extension bin/scout-query-darwin-arm64.ext --allow-unsafe
```

### Future Development

Scout Query  is still in early development. The aim of this project is to allow for quick retrieval of data in a similar table format to existing osquery tables, securely distribute scripts around the network, and safely execute them. It includes some optional configs to limit the risk of long-running processes and denial of service on the download side.

There is a level of caching that takes place at the endpoint with signature verification and checks should the hosted content change or someone tamper with the local cached files.

We’re open to collaboration and would love to explore new use cases. If you find the Scout Query helpful or have any suggestions, feel free to reach out!