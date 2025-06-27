"""Constants used across Budget Guard services."""

from enum import Enum

# DynamoDB Table Names
PRODUCTS_TABLE = "budget-guard-products"
METRICS_TABLE = "budget-guard-metrics"
ANOMALIES_TABLE = "budget-guard-anomalies"
RESOURCE_MAPPING_TABLE = "budget-guard-resource-mapping"

# Time Constants
ANOMALY_LOOKBACK_DAYS = 30
COST_SPIKE_THRESHOLD_PERCENT = 50
COST_SPIKE_THRESHOLD_ABSOLUTE = 1000
NEW_RESOURCE_COST_THRESHOLD = 100
BUDGET_WARNING_THRESHOLD = 0.8  # 80% of budget
BUDGET_CRITICAL_THRESHOLD = 0.95  # 95% of budget

# Alert Thresholds
CRITICAL_COST_IMPACT = 5000  # $5000/day
HIGH_COST_IMPACT = 1000  # $1000/day
MEDIUM_COST_IMPACT = 100  # $100/day

# Required Tags
REQUIRED_TAGS = ["Product", "Team", "Environment", "Component"]

# AWS Services to Track
TRACKED_AWS_SERVICES = [
    "AmazonEC2",
    "AmazonRDS",
    "AmazonS3",
    "AWSLambda",
    "AmazonDynamoDB",
    "AmazonElastiCache",
    "AmazonCloudFront",
    "AmazonSNS",
    "AmazonSQS",
    "AmazonECS",
    "AmazonEKS",
    "ElasticLoadBalancing",
    "AmazonVPC",
    "AWSDataTransfer"
]


class ProductType(str, Enum):
    ORGANIC = "ORGANIC"
    ACQUISITION = "ACQUISITION"


class AnomalyType(str, Enum):
    COST_SPIKE = "COST_SPIKE"
    NEW_RESOURCE = "NEW_RESOURCE"
    MISSING_RESOURCE = "MISSING_RESOURCE"
    BUDGET_VIOLATION = "BUDGET_VIOLATION"
    UNTAGGED_RESOURCE = "UNTAGGED_RESOURCE"
    ORPHANED_RESOURCE = "ORPHANED_RESOURCE"
    ACQUISITION_MISS = "ACQUISITION_MISS"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AnomalyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ResourceDiscoverySource(str, Enum):
    CLOUDFORMATION = "cloudformation"
    TAGS = "tags"
    NAMING_CONVENTION = "naming_convention"
    MANUAL = "manual"
    INFERRED = "inferred"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"