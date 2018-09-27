Pyrecon
=======
_External and web app pentesting automation framework. Uses SQLite databases to store project data._


**Status**: Prototype


## **Goals of Pyrecon**

- Combine already existing and effective tools into single Pyrecon commands. Instead of running 5 different tools in a row with dozens of different arguments, just type `run` and let Pyrecon do the rest.
- Create an orgainzed and consitent output file and directory structure for each Pyrecon project. Even if you change Pyrecon's default output structure, your output paths will be available in the database. "Where did I put that masscan output from last week?" Use `show` to output a table with your dated masscan outputs. Another `show` can be used to print a table with that specific output.
- Store structured project related data and metrics in project specific databases. This data can be printed to the terminal in formatted tables or written to text, JSON, CSV, and Excel files (file outputs are not yet implemented).
- **_Overall, organization and consitency across projects are the main goals of Pyrecon._** The ability to easily access structured data across multiple projects in the Pyrecon CLI without having to navigate a directory structure will leave more time and energy for the actual analysis of the data. A consistent and logically laid out directory structure will then make it easy to access the data files (both the tool output itself and any JSON, CSV, Excel, etc. that Pyrecon offers).


## **Setup**


#### **_1. Make sure you have a working Go environment on your machine:_**
The command `go version` can be used to check for a Go installation. If you see "no command found", that means Go is either not installed or not set up properly. Run the following commands to setup a Go environment (you may have to log out after running them):
```bash
mkdir /opt/go/
mkdir $HOME/go
wget -P /opt/go/ https://dl.google.com/go/go1.11.linux-amd64.tar.gz
tar -C /usr/local/ -xzf /opt/go/go1.11.linux-amd64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin" >>~/.profile
echo "export GOPATH=$HOME/go" >>~/.profile
source ~/.profile
```


#### **_2. Run setup.sh:_**
	`./pyrecon/setup/setup.sh`



## **Using Pyrecon**

Run Pyrecon with `python3 pyrecon.py`. This will enter the Pyrecon CLI, and you will be presented with available commands. Pyrecon recon can exist in one of three contexts, with each giving access to different commands. A new project must first be intialized or an existing project selected, then a module group (e.g. dns, portscan) must be initialized. You then gain access to the selected projects instance of those modules, with all associated run time options, outputs, etc.

- ### **Project initialization/selection**

	_Create a new project and initialize it's database, or select an existing project database._

	***Commands:***

	`init`		Create and initialize a new project database

	`select`	Select an already existing project and it's database


- ### **Module initialization**
	
	_Use one of the available commands to initialize and gain access to it's accosiated modules._

	***Commands:***
	
	`dns`	Run DNS recon modules (whois, dnsrecon)
	
	`portscan`	Run portscan modules (masscan, nmap) using dns outputs
	
	`back`	Return to project initialization/selection


- ### **Module execution and structured data output**
	
	_Set module options, execute modules individually or all at once, and print/write structured data from tool outputs._

	***Commands:***

	`run`	Runs all modules available to the current context. Pass a module as an argument to run individually.

	`set` 	Set module options

	`get`	Get currently configured module options

	`show`	Print module outputs to the terminal. Takes arguments depending on the current context.

	`back`	Return to module initialization

- ### **Universal commands**

	_These commands will be available regardless of the current context of Pyrecon_

	`clear`	Clears the terminal

	`shell` or `!`	Execute shell commands

	`exit`	Exit Pyrecon
