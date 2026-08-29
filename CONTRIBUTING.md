# Module Development Guide

This guide outlines the standardized process for adding new functionality to the Netool toolkit to ensure maintainability and consistency.

## 1. Create the Logic Module
Create a new Python file in the root directory (e.g., `mynewtool.py`).

### Requirements:
- **Logging**: Initialize a module-level logger.
- **Core Function**: Define a primary entry-point function (e.g., `run()`) that accepts parameters and returns data (dictionaries or lists).
- **Separation**: Keep all CLI-specific code (like `click` or `print` statements) out of the logic module.
- **Concurrency**: For network-heavy tasks (like port scanning), prefer `asyncio` pipelines with `asyncio.Semaphore` to manage concurrency and prevent resource exhaustion. Raw socket operations should be offloaded using `asyncio.to_thread()` to avoid blocking the event loop.
- **Comments**: Use `""" triple quotes """` for documentation and internal comments.

**Example Structure:**
```python
import logging
import some_library

logger = logging.getLogger(__name__)

def run_tool(target, timeout=1.0):
    """
    Performs the core logic of the tool.
    """
    try:
        logger.info(f"Executing tool on {target}...")
        # ... logic here ...
        return {"result": "success", "data": []}
    except Exception as e:
        logger.exception(f"Tool failed: {e}")
        return {"error": str(e)}
```

## 2. Integrate into `main.py`
Register the new module in the CLI interface.

### Step A: Import the module
Add the import at the top of `main.py`.
```python
import mynewtool
```

### Step B: Define the CLI Command
Add a new `@cli.command()` decorated function.

```python
@cli.command()
@click.option("-t", "--target", required=True, help="Target identifier")
@click.option("-to", "--timeout", type=float, default=1.0, help="Timeout in seconds")
def mytool_cmd(target, timeout):
    """Brief description of what this command does"""
    # 1. Call the logic module
    result = mynewtool.run_tool(target, timeout)
    
    # 2. Format and display the output using the 'console' object
    if "error" in result:
        console.print(f"[bold red]Error:[/bold red] {result['error']}")
    else:
        console.print(f"[bold magenta]Results:[/bold magenta]\n{result}")
```

## 3. Update Documentation
- Update `README.md` with the new command.
- Add any new dependencies to the `Requirements` section.
- If the tool requires root privileges, add it to the "root/admin" list.

