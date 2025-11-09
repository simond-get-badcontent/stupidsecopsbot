# stupidsecopsbot
A script to perform network scanning using Nmap. It defines an MCP server with tools to run pre-defined Nmap scans and specific port scans on given targets.

Install notes:

- Windows using Claude
	- Install Claude: https://www.claude.com/download
	- Upgrade from free license (required for MCP usage)
	- Install NMAP: https://nmap.org/download
	- Configure an MCP server in Claude:
		- File > Settings > Developer -> "Edit Config"
		- Paste the contents of the provided claude_desktop_config.json file
	- Install requirements
		- pip install mcp
	- Restart Claude (right-click the system tray icon and choose "Quit")
	- Start Claude again, under the previous Developer tab, you will see
	  the status of your MCP server.
	- Start asking questions! Like:
		"Please use the stupidsecopsbot:scan_network tool on 192.168.1.1/24 with the quick scan type."
		
