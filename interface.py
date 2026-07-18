import psutil
import logging

logger = logging.getLogger(__name__)

def list_interfaces():
    """
    Lists all available network interfaces on the device that are currently UP.
    
    Returns:
        list: A list of interface names.
    """
    try:
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        result = []
        for name in interfaces:
            # Only add interface if it is up
            if name in stats and stats[name].isup:
                result.append(name)
            
        logger.info(f"Found {len(result)} active interfaces")
        return result
    except Exception as e:
        logger.exception(f"Error listing interfaces: {e}")
        return []

if __name__ == "__main__":
    # Simple test
    print("Active Interfaces:")
    for iface in list_interfaces():
        print(iface)
