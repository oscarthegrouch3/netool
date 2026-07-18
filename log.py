import logging
import sys

def setup_logging(log_file=None):
    """
    Configures the logging system for the Netool toolkit.
    
    Args:
        log_file (str, optional): Path to a file where logs should be written. 
                                  If None, logs only go to stderr.
    """
    handlers = [logging.StreamHandler(sys.stderr)]
    
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except Exception as e:
            print(f"Warning: Could not open log file {log_file}: {e}", file=sys.stderr)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True # Overwrite any previous configuration
    )

