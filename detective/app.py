"""
The Detective - Anomaly Detection Service
Identifies cost anomalies and budget violations
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from statistics import mean, stdev

import boto3
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import (
    get_env_var, get_dynamodb_resource, get_current_date,
    get_current_timestamp, calculate_percentage_change,
    query_items, batch_write_items, get_date_range
)
from shared.constants import (
    PRODUCTS_TABLE, METRICS_TABLE, ANOMALIES_TABLE, RESOURCE_MAPPING_TABLE,
    AnomalyType, Severity, AnomalyStatus,
    COST_SPIKE_THRESHOLD_PERCENT, COST_SPIKE_THRESHOLD_ABSOLUTE,
    NEW_RESOURCE_COST_THRESHOLD, BUDGET_WARNING_THRESHOLD,
    BUDGET_CRITICAL_THRESHOLD, CRITICAL_COST_IMPACT,
    HIGH_COST_IMPACT, MEDIUM_COST_IMPACT, ANOMALY_LOOKBACK_DAYS,
    REQUIRED_TAGS
)
from shared.models import DailyMetric, Anomaly, Product

logger = Logger()


class Detective:
    """The Detective service for anomaly detection."""
    
    def __init__(self):
        self.products_table = get_env_var('PRODUCTS_TABLE', PRODUCTS_TABLE)
        self.metrics_table = get_env_var('METRICS_TABLE', METRICS_TABLE)
        self.anomalies_table = get_env_var('ANOMALIES_TABLE', ANOMALIES_TABLE)
        self.resource_mapping_table = get_env_var('RESOURCE_MAPPING_TABLE', RESOURCE_MAPPING_TABLE)
        self.dynamodb = get_dynamodb_resource()
        
    def process_metric_stream(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process DynamoDB stream records from Metrics table."""
        logger.info(f"Processing {len(records)} metric records")
        
        results = {
            'records_processed': 0,
            'anomalies_detected': 0,
            'errors': []
        }
        
        for record in records:
            try:
                # Only process INSERT and MODIFY events
                if record['eventName'] not in ['INSERT', 'MODIFY']:
                    continue
                
                # Get the new image
                new_image = record.get('dynamodb', {}).get('NewImage', {})
                if not new_image:
                    continue
                
                # Convert DynamoDB format to regular dict
                metric_data = self._unmarshall_dynamodb_item(new_image)
                
                # Skip if not a metric record
                if not metric_data.get('PK', '').startswith('METRIC#'):
                    continue
                
                metric = DailyMetric.from_dynamodb_item(metric_data)
                
                # Detect anomalies
                anomalies = self._detect_anomalies(metric)
                
                # Save anomalies
                if anomalies:
                    self._save_anomalies(anomalies)
                    results['anomalies_detected'] += len(anomalies)
                
                results['records_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing record: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.info(f"Detective processing complete: {results}")
        return results
    
    def _detect_anomalies(self, metric: DailyMetric) -> List[Anomaly]:
        """Detect anomalies for a metric."""
        anomalies = []
        
        # Get product details
        product = self._get_product(metric.product_id)
        if not product:
            logger.warning(f"Product not found: {metric.product_id}")
            return anomalies
        
        # Get historical metrics
        historical_metrics = self._get_historical_metrics(
            metric.product_id,
            days=ANOMALY_LOOKBACK_DAYS
        )
        
        # 1. Check for cost spikes
        cost_spike_anomaly = self._check_cost_spike(metric, historical_metrics)
        if cost_spike_anomaly:
            anomalies.append(cost_spike_anomaly)
        
        # 2. Check for budget violations
        budget_anomaly = self._check_budget_violation(metric, product)
        if budget_anomaly:
            anomalies.append(budget_anomaly)
        
        # 3. Check for new expensive resources
        new_resource_anomalies = self._check_new_resources(metric, historical_metrics)
        anomalies.extend(new_resource_anomalies)
        
        # 4. Check for missing resources
        missing_resource_anomalies = self._check_missing_resources(metric, historical_metrics)
        anomalies.extend(missing_resource_anomalies)
        
        # 5. Check acquisition targets (if applicable)
        if product.type.value == 'ACQUISITION' and product.target_reduction:
            acquisition_anomaly = self._check_acquisition_target(metric, product, historical_metrics)
            if acquisition_anomaly:
                anomalies.append(acquisition_anomaly)
        
        # 6. Check for untagged resources
        untagged_anomalies = self._check_untagged_resources(metric.product_id)
        anomalies.extend(untagged_anomalies)
        
        return anomalies
    
    def _check_cost_spike(
        self, metric: DailyMetric, historical: List[DailyMetric]
    ) -> Optional[Anomaly]:
        """Check for cost spikes."""
        if not historical:
            return None
        
        # Calculate rolling average and standard deviation
        costs = [m.daily_cost for m in historical]
        if len(costs) < 7:  # Need at least a week of data
            return None
        
        avg_cost = mean(costs)
        std_cost = stdev(costs) if len(costs) > 1 else 0
        
        # Check for spike
        percentage_change = calculate_percentage_change(avg_cost, metric.daily_cost)
        absolute_change = metric.daily_cost - avg_cost
        
        # Detect spike based on percentage OR absolute threshold
        is_spike = (
            percentage_change > COST_SPIKE_THRESHOLD_PERCENT or
            absolute_change > COST_SPIKE_THRESHOLD_ABSOLUTE
        )
        
        # Also check for statistical anomaly (> 3 standard deviations)
        if std_cost > 0:
            z_score = (metric.daily_cost - avg_cost) / std_cost
            is_spike = is_spike or z_score > 3
        
        if is_spike:
            # Determine severity
            severity = self._calculate_severity(absolute_change)
            
            # Find the service causing the spike
            service_changes = {}
            if historical:
                last_metric = historical[-1]
                for service, cost in metric.by_service.items():
                    last_cost = last_metric.by_service.get(service, 0)
                    change = cost - last_cost
                    if change > 50:  # Significant change
                        service_changes[service] = change
            
            return Anomaly(
                id=str(uuid.uuid4()),
                product_id=metric.product_id,
                type=AnomalyType.COST_SPIKE,
                severity=severity,
                status=AnomalyStatus.ACTIVE,
                cost_impact=absolute_change,
                resource=f"product/{metric.product_id}",
                detected_at=get_current_timestamp(),
                context={
                    'current_cost': metric.daily_cost,
                    'average_cost': avg_cost,
                    'percentage_change': percentage_change,
                    'service_changes': service_changes,
                    'date': metric.date
                }
            )
        
        return None
    
    def _check_budget_violation(self, metric: DailyMetric, product: Product) -> Optional[Anomaly]:
        """Check for budget violations."""
        # Calculate month-to-date spend
        current_date = datetime.strptime(metric.date, '%Y-%m-%d')
        month_start = current_date.replace(day=1).strftime('%Y-%m-%d')
        
        mtd_metrics = self._get_metrics_range(
            metric.product_id,
            month_start,
            metric.date
        )
        
        mtd_spend = sum(m.daily_cost for m in mtd_metrics)
        
        # Project to end of month
        days_in_month = 30  # Simplified
        days_elapsed = current_date.day
        projected_spend = (mtd_spend / days_elapsed) * days_in_month if days_elapsed > 0 else 0
        
        # Check against budget
        budget_percentage = projected_spend / product.monthly_budget if product.monthly_budget > 0 else 0
        
        if budget_percentage >= BUDGET_CRITICAL_THRESHOLD:
            severity = Severity.CRITICAL
        elif budget_percentage >= BUDGET_WARNING_THRESHOLD:
            severity = Severity.HIGH
        else:
            return None
        
        return Anomaly(
            id=str(uuid.uuid4()),
            product_id=metric.product_id,
            type=AnomalyType.BUDGET_VIOLATION,
            severity=severity,
            status=AnomalyStatus.ACTIVE,
            cost_impact=projected_spend - product.monthly_budget,
            resource=f"product/{metric.product_id}",
            detected_at=get_current_timestamp(),
            context={
                'mtd_spend': mtd_spend,
                'projected_spend': projected_spend,
                'monthly_budget': product.monthly_budget,
                'budget_percentage': budget_percentage * 100,
                'date': metric.date
            }
        )
    
    def _check_new_resources(
        self, metric: DailyMetric, historical: List[DailyMetric]
    ) -> List[Anomaly]:
        """Check for new expensive resources."""
        anomalies = []
        
        if not historical:
            return anomalies
        
        # Get services that appeared today but not in historical average
        historical_services = set()
        for h in historical:
            historical_services.update(h.by_service.keys())
        
        new_services = set(metric.by_service.keys()) - historical_services
        
        for service in new_services:
            cost = metric.by_service[service]
            if cost >= NEW_RESOURCE_COST_THRESHOLD:
                severity = self._calculate_severity(cost)
                
                anomaly = Anomaly(
                    id=str(uuid.uuid4()),
                    product_id=metric.product_id,
                    type=AnomalyType.NEW_RESOURCE,
                    severity=severity,
                    status=AnomalyStatus.ACTIVE,
                    cost_impact=cost,
                    resource=f"service/{service}",
                    detected_at=get_current_timestamp(),
                    context={
                        'service': service,
                        'daily_cost': cost,
                        'date': metric.date
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _check_missing_resources(
        self, metric: DailyMetric, historical: List[DailyMetric]
    ) -> List[Anomaly]:
        """Check for resources that disappeared but still incur costs."""
        anomalies = []
        
        if not historical or len(historical) < 7:
            return anomalies
        
        # Get services that were present historically but missing today
        current_services = set(metric.by_service.keys())
        
        # Look at last week's services
        last_week_services = set()
        for h in historical[-7:]:
            last_week_services.update(h.by_service.keys())
        
        missing_services = last_week_services - current_services
        
        for service in missing_services:
            # Check if the service had significant cost
            avg_cost = mean([h.by_service.get(service, 0) for h in historical[-7:]])
            
            if avg_cost >= 100:  # Significant service
                anomaly = Anomaly(
                    id=str(uuid.uuid4()),
                    product_id=metric.product_id,
                    type=AnomalyType.MISSING_RESOURCE,
                    severity=Severity.MEDIUM,
                    status=AnomalyStatus.ACTIVE,
                    cost_impact=avg_cost,
                    resource=f"service/{service}",
                    detected_at=get_current_timestamp(),
                    context={
                        'service': service,
                        'previous_avg_cost': avg_cost,
                        'date': metric.date
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _check_acquisition_target(
        self, metric: DailyMetric, product: Product, historical: List[DailyMetric]
    ) -> Optional[Anomaly]:
        """Check if acquisition product is meeting reduction targets."""
        if not historical or len(historical) < 30:
            return None
        
        # Compare current cost to baseline (first week average)
        baseline_costs = [h.daily_cost for h in historical[:7]]
        baseline_avg = mean(baseline_costs)
        
        # Calculate actual reduction
        actual_reduction = (baseline_avg - metric.daily_cost) / baseline_avg if baseline_avg > 0 else 0
        
        # Check if meeting target
        if actual_reduction < product.target_reduction * 0.8:  # 80% of target
            shortfall = (product.target_reduction - actual_reduction) * baseline_avg
            
            return Anomaly(
                id=str(uuid.uuid4()),
                product_id=metric.product_id,
                type=AnomalyType.ACQUISITION_MISS,
                severity=Severity.HIGH,
                status=AnomalyStatus.ACTIVE,
                cost_impact=shortfall,
                resource=f"product/{metric.product_id}",
                detected_at=get_current_timestamp(),
                context={
                    'baseline_cost': baseline_avg,
                    'current_cost': metric.daily_cost,
                    'target_reduction': product.target_reduction * 100,
                    'actual_reduction': actual_reduction * 100,
                    'date': metric.date
                }
            )
        
        return None
    
    def _check_untagged_resources(self, product_id: str) -> List[Anomaly]:
        """Check for untagged resources."""
        anomalies = []
        
        # Query resource mappings for this product
        table = self.dynamodb.Table(self.resource_mapping_table)
        response = table.query(
            IndexName='product-index',
            KeyConditionExpression=Key('primaryProduct').eq(product_id)
        )
        
        for item in response.get('Items', []):
            metadata = item.get('metadata', {})
            tags = metadata.get('tags', {})
            
            # Check for missing required tags
            missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]
            
            if missing_tags:
                anomaly = Anomaly(
                    id=str(uuid.uuid4()),
                    product_id=product_id,
                    type=AnomalyType.UNTAGGED_RESOURCE,
                    severity=Severity.LOW,
                    status=AnomalyStatus.ACTIVE,
                    cost_impact=0,  # Would need to look up actual cost
                    resource=item['resourceArn'],
                    detected_at=get_current_timestamp(),
                    context={
                        'missing_tags': missing_tags,
                        'existing_tags': tags
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies[:5]  # Limit to 5 to avoid spam
    
    def _calculate_severity(self, cost_impact: float) -> Severity:
        """Calculate severity based on cost impact."""
        if cost_impact >= CRITICAL_COST_IMPACT:
            return Severity.CRITICAL
        elif cost_impact >= HIGH_COST_IMPACT:
            return Severity.HIGH
        elif cost_impact >= MEDIUM_COST_IMPACT:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _get_product(self, product_id: str) -> Optional[Product]:
        """Get product details."""
        table = self.dynamodb.Table(self.products_table)
        response = table.get_item(
            Key={
                'PK': f'PRODUCT#{product_id}',
                'SK': 'METADATA'
            }
        )
        
        if 'Item' in response:
            return Product.from_dynamodb_item(response['Item'])
        return None
    
    def _get_historical_metrics(self, product_id: str, days: int) -> List[DailyMetric]:
        """Get historical metrics for a product."""
        start_date, end_date = get_date_range(days)
        return self._get_metrics_range(product_id, start_date, end_date)
    
    def _get_metrics_range(self, product_id: str, start_date: str, end_date: str) -> List[DailyMetric]:
        """Get metrics for a date range."""
        metrics = []
        
        # Query each day (in production, would use batch query)
        current = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        
        table = self.dynamodb.Table(self.metrics_table)
        
        while current <= end:
            date_str = current.strftime('%Y-%m-%d')
            
            response = table.get_item(
                Key={
                    'PK': f'METRIC#{date_str}',
                    'SK': f'PRODUCT#{product_id}'
                }
            )
            
            if 'Item' in response:
                metrics.append(DailyMetric.from_dynamodb_item(response['Item']))
            
            current += timedelta(days=1)
        
        return metrics
    
    def _save_anomalies(self, anomalies: List[Anomaly]):
        """Save anomalies to DynamoDB."""
        items = [anomaly.to_dynamodb_item() for anomaly in anomalies]
        if items:
            batch_write_items(self.anomalies_table, items)
    
    def _unmarshall_dynamodb_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB item format to regular dict."""
        from boto3.dynamodb.types import TypeDeserializer
        deserializer = TypeDeserializer()
        return {k: deserializer.deserialize(v) for k, v in item.items()}


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for Detective service."""
    detective = Detective()
    
    try:
        # Process DynamoDB stream records
        records = event.get('Records', [])
        results = detective.process_metric_stream(records)
        
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Detective execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }