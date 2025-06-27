"""Data models for Budget Guard DynamoDB entities."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from shared.constants import (
    ProductType, AnomalyType, Severity, AnomalyStatus,
    ResourceDiscoverySource, Confidence
)


@dataclass
class Product:
    """Product data model."""
    id: str
    name: str
    type: ProductType
    team_id: str
    monthly_budget: float
    target_reduction: Optional[float] = None
    cost_center: Optional[str] = None
    accounts: List[str] = field(default_factory=list)
    repos: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        return {
            'PK': f'PRODUCT#{self.id}',
            'SK': 'METADATA',
            'id': self.id,
            'name': self.name,
            'type': self.type.value,
            'teamId': self.team_id,
            'monthlyBudget': self.monthly_budget,
            'targetReduction': self.target_reduction,
            'costCenter': self.cost_center,
            'accounts': self.accounts,
            'repos': self.repos,
            'components': self.components,
            'createdAt': self.created_at or datetime.utcnow().isoformat(),
            'updatedAt': self.updated_at or datetime.utcnow().isoformat()
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'Product':
        """Create from DynamoDB item."""
        return cls(
            id=item['id'],
            name=item['name'],
            type=ProductType(item['type']),
            team_id=item['teamId'],
            monthly_budget=float(item['monthlyBudget']),
            target_reduction=float(item.get('targetReduction')) if item.get('targetReduction') else None,
            cost_center=item.get('costCenter'),
            accounts=item.get('accounts', []),
            repos=item.get('repos', []),
            components=item.get('components', []),
            created_at=item.get('createdAt'),
            updated_at=item.get('updatedAt')
        )


@dataclass
class DailyMetric:
    """Daily cost metric data model."""
    date: str
    product_id: str
    daily_cost: float
    resource_count: int
    by_service: Dict[str, float]
    by_component: Dict[str, float]
    by_account: Optional[Dict[str, float]] = None
    created_at: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        # TTL set to 90 days from now
        ttl = int((datetime.utcnow().timestamp())) + (90 * 24 * 60 * 60)
        
        return {
            'PK': f'METRIC#{self.date}',
            'SK': f'PRODUCT#{self.product_id}',
            'date': self.date,
            'productId': self.product_id,
            'dailyCost': self.daily_cost,
            'resourceCount': self.resource_count,
            'byService': self.by_service,
            'byComponent': self.by_component,
            'byAccount': self.by_account or {},
            'createdAt': self.created_at or datetime.utcnow().isoformat(),
            'ttl': ttl
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'DailyMetric':
        """Create from DynamoDB item."""
        return cls(
            date=item['date'],
            product_id=item['productId'],
            daily_cost=float(item['dailyCost']),
            resource_count=int(item['resourceCount']),
            by_service={k: float(v) for k, v in item.get('byService', {}).items()},
            by_component={k: float(v) for k, v in item.get('byComponent', {}).items()},
            by_account={k: float(v) for k, v in item.get('byAccount', {}).items()} if item.get('byAccount') else None,
            created_at=item.get('createdAt')
        )


@dataclass
class Anomaly:
    """Anomaly data model."""
    id: str
    product_id: str
    type: AnomalyType
    severity: Severity
    status: AnomalyStatus
    cost_impact: float
    resource: str
    detected_at: str
    context: Optional[Dict[str, Any]] = None
    routing: Optional[Dict[str, Any]] = None
    resolution: Optional[str] = None
    resolved_at: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        return {
            'PK': f'ANOMALY#{self.detected_at[:10]}#{self.id}',
            'SK': 'METADATA',
            'id': self.id,
            'productId': self.product_id,
            'type': self.type.value,
            'severity': self.severity.value,
            'status': self.status.value,
            'costImpact': self.cost_impact,
            'resource': self.resource,
            'detectedAt': self.detected_at,
            'context': self.context or {},
            'routing': self.routing or {},
            'resolution': self.resolution,
            'resolvedAt': self.resolved_at
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'Anomaly':
        """Create from DynamoDB item."""
        return cls(
            id=item['id'],
            product_id=item['productId'],
            type=AnomalyType(item['type']),
            severity=Severity(item['severity']),
            status=AnomalyStatus(item['status']),
            cost_impact=float(item['costImpact']),
            resource=item['resource'],
            detected_at=item['detectedAt'],
            context=item.get('context'),
            routing=item.get('routing'),
            resolution=item.get('resolution'),
            resolved_at=item.get('resolvedAt')
        )


@dataclass
class ResourceMapping:
    """Resource ownership mapping data model."""
    resource_arn: str
    type: str  # 'dedicated' or 'shared'
    primary_product: str
    consumers: Optional[List[Dict[str, Any]]] = None
    discovery_source: ResourceDiscoverySource = ResourceDiscoverySource.TAGS
    confidence: Confidence = Confidence.MEDIUM
    last_validated: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        return {
            'PK': f'RESOURCE#{self.resource_arn}',
            'SK': 'MAPPING',
            'resourceArn': self.resource_arn,
            'type': self.type,
            'primaryProduct': self.primary_product,
            'consumers': self.consumers or [],
            'discoverySource': self.discovery_source.value,
            'confidence': self.confidence.value,
            'lastValidated': self.last_validated or datetime.utcnow().isoformat(),
            'metadata': self.metadata or {}
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'ResourceMapping':
        """Create from DynamoDB item."""
        return cls(
            resource_arn=item['resourceArn'],
            type=item['type'],
            primary_product=item['primaryProduct'],
            consumers=item.get('consumers'),
            discovery_source=ResourceDiscoverySource(item['discoverySource']),
            confidence=Confidence(item['confidence']),
            last_validated=item.get('lastValidated'),
            metadata=item.get('metadata')
        )