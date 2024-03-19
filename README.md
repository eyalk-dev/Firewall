Firewall
========

The firewall consists of two components: kernelspace (in C) and userspace (in Python). It operates transparently between the client and server, structured as follows:

Client <--> Proxy (as Server) <--> Proxy (as Client) <--> Server

Kernelspace
-----------

The kernelspace program is intended to be a module in the Linux kernel, communicating with the userspace program. It routes blocked packets and forwards relevant packets to the userspace proxy for advanced filtering.

### Manager

This module initializes the firewall, using netfilter to hook pre-routing and local-out packets (sent from the proxy). Both packet types are then sent to the stateful module.

### Stateful

This module checks packets against a connection table, processes TCP state machine (three-way handshake), routes packets to the proxy, forges packets to appear as if they were sent from the client or server, and updates the log.

### Connections

Responsible for managing the connection table, including searching, adding new connections, and providing the userspace proxy with the ability to edit connections.

### Rules

Checks basic rules for packets. Allows userspace to read and write rules, and provides a feature to toggle the firewall on and off.

### Logs

Records logs and allows userspace to read them.

Userspace
---------

The userspace component, written in Python, controls firewall functions (activating/deactivating, editing connections/rules, reading logs) and requires root access. It also handles data leak prevention and blocks the OrientDB 2.2.x Remote Code Execution (CVE-2017-11467) vulnerability.

### Interface

Handles commands from users:

- `activate`: Activates the firewall.
- `deactivate`: Deactivates the firewall.
- `show_rules`: Displays rules.
- `clear_rules`: Clears all connections and rules.
- `load_rules x`: Clears connections and loads rules from the file path `x`.
- `show_log`: Displays logs.
- `clear_log`: Clears logs.
- `show_connections`: Displays connections.

### Parser

Parses rules, logs, and connections from the kernel and presents them in a readable format.

### Proxy

A new class that manages the connection between the client and server, using an epoll loop for transparent data forwarding.

### Proxy HTTP

A proxy that parses HTTP payloads in C code before forwarding.

### Proxy SMTP

A proxy that parses SMTP payloads in C code before forwarding.

### Data Leak Prevention

The aim was to prevent C code leaks over HTTP or SMTP. I created a proxy on port 25 (SMTP) and a parser to receive payloads. Additionally, a second proxy on port 80 (HTTP) was established for payloads containing only the message after the header. Both types of payloads underwent analysis in a dedicated function.

The analysis focused on distinguishing C code's structural patterns from English text. While both share common words (e.g., "if," "else," "return," "include," "define," etc.), their structural organization differs. English is organized into paragraphs and sentences, while C code is divided into lines, each with a unique structure (e.g., 'return' at the start of a line).

To identify potential C code, I used regex to parse lines, paying attention to word and symbol locations. Matches were scored based on their uniqueness in C versus English. The total score, calculated as the sum of (each key's score \* its count), was normalized by the number of lines. If the normalized score surpassed a threshold, the message was flagged as C code and discarded.

### OrientDB Vulnerability

The class inherits from Proxy to mitigate CVE-2017-11467, a vulnerability in OrientDB 2.2.x. OrientDB can execute Groovy functions without a sandbox, exposing system functionalities. While this behavior is normal, the vulnerability allows a *writer* to escalate privileges to *admin*, enabling unauthorized remote code execution.

This vulnerability arises from the GRANT command, which grants permissions on databases to roles. Exploiting this, *writer* gain control over meta-databases it shouldn't, such as database.class.ouser (managing roles) and database.function (handling function executions).

To address this, I chose to block any GRANT command that gives *writer* permission on these databases, thereby preventing the privilege escalation and unauthorized code execution.