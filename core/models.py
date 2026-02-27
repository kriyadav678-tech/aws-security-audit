from datetime import datetime


def create_finding(
    service,
    resource,
    severity,
    message,
    category=None,
    region=None
):
    """
    Standard finding object for all services
    """

    return {
        "service": service,
        "resource": resource,
        "severity": severity,
        "category": category,
        "region": region,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }