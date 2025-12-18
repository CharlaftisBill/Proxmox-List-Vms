# Proxmox VM List

A Python CLI tool that fetches a list of all VMs across your Proxmox nodes and displays details (Name, OS, IP, CPU, RAM, Storage) in a neat table.

## How to Run

To install Python packages locally (without affecting your system-wide Python), you should use a **Virtual Environment (`venv`)**.

### 1. Install the `venv` module (if missing)
On Debian/Ubuntu systems, the virtual environment tool is often a separate package.
```bash
sudo apt update
sudo apt install python3-venv
```

### 2. Create the Virtual Environment
Navigate to the folder where your script is located, then create a new virtual environment folder (commonly named `.venv` or `venv`).

```bash
python3 -m venv .venv
```

### 3. Activate the Environment
This tells your shell to use the Python and Pip inside that folder instead of the global system one.

```bash
source .venv/bin/activate
```
*(You will notice your terminal prompt change, usually showing `(.venv)` at the start).*

### 4. Install Requirements
Now, when you run `pip install`, the files go into the `.venv` folder, not your system.

```bash
# Install from your text file
pip install -r requirements.txt
```

### 5. Run
As long as the environment is active, `python` refers to the isolated version.

```bash
./.venv/bin/python list_vms.py 192.168.5.21 root@pam --password "mySuperSecretPassword123" --interface tun0
```

### 6. Deactivate (When finished)
To go back to your system's normal Python:

```bash
deactivate
```