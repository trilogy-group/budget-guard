"""
The Scout - Data Collection Service
Aggregates cost and resource data from all AWS accounts
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import (
    get_env_var, get_client_with_assumed_role, batch_write_items,
    get_current_date, get_resource_tags, parse_arn, float_to_decimal,
    scan_items
)
from shared.constants import (
    PRODUCTS_TABLE, METRICS_TABLE, RESOURCE_MAPPING_TABLE,
    TRACKED_AWS_SERVICES, ResourceDiscoverySource, Confidence
)
from shared.models import DailyMetric, ResourceMapping, Product

logger = Logger()


class Scout:
    """The Scout service for data collection."""
    
    def __init__(self):
        self.master_role_name = get_env_var('MASTER_ROLE_NAME', 'BudgetGuardRole')
        self.products_table = get_env_var('PRODUCTS_TABLE', PRODUCTS_TABLE)
        self.metrics_table = get_env_var('METRICS_TABLE', METRICS_TABLE)
        self.resource_mapping_table = get_env_var('RESOURCE_MAPPING_TABLE', RESOURCE_MAPPING_TABLE)
        self.ce_client = boto3.client('ce')
        
    def collect_all_data(self) -> Dict[str, Any]:
        """Main entry point for data collection."""
        logger.info("Starting Scout data collection")
        
        # Get all products
        products = self._get_all_products()
        logger.info(f"Found {len(products)} products to process")
        
        # Collect metrics for each product
        results = {
            'products_processed': 0,
            'metrics_collected': 0,
            'resources_discovered': 0,
            'errors': []
        }
        
        for product in products:
            try:
                # Collect cost data
                metrics = self._collect_product_metrics(product)
                if metrics:
                    self._save_metrics(metrics)
                    results['metrics_collected'] += 1
                
                # Discover resources
                resources = self._discover_product_resources(product)
                self._save_resource_mappings(resources)
                results['resources_discovered'] += len(resources)
                
                results['products_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing product {product.id}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.info(f"Scout collection complete: {results}")
        return results
    
    def _get_all_products(self) -> List[Product]:
        """Get all products from DynamoDB."""
        items = scan_items(self.products_table)
        products = []
        
        for item in items:
            if item.get('SK') == 'METADATA' and item.get('PK', '').startswith('PRODUCT#'):
                products.append(Product.from_dynamodb_item(item))
        
        return products
    
    def _collect_product_metrics(self, product: Product) -> Optional[DailyMetric]:
        """Collect cost metrics for a product."""
        logger.info(f"Collecting metrics for product: {product.id}")
        
        end_date = datetime.utcnow().date()
        start_date = end_date - timedelta(days=1)
        
        # Prepare filters for Cost Explorer
        filters = []
        
        # Add account filters
        if product.accounts:
            filters.append({
                'Dimensions': {
                    'Key': 'LINKED_ACCOUNT',
                    'Values': product.accounts
                }
            })
        
        # Add tag filters
        tag_filters = []
        tag_filters.append({
            'Tags': {
                'Key': 'Product',
                'Values': [product.id]
            }
        })
        
        if tag_filters:
            filters.extend(tag_filters)
        
        # Combine filters
        cost_filter = None
        if len(filters) == 1:
            cost_filter = filters[0]
        elif len(filters) > 1:
            cost_filter = {'And': filters}
        
        try:
            # Get cost data grouped by service
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost', 'UsageQuantity'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                    {'Type': 'TAG', 'Key': 'Component'}
                ],
                Filter=cost_filter
            )
            
            # Process the response
            by_service = defaultdict(float)
            by_component = defaultdict(float)
            total_cost = 0.0
            
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    
                    # Parse service and component from keys
                    service = None
                    component = None
                    
                    for key in group['Keys']:
                        if key.startswith('SERVICE$'):
                            service = key.replace('SERVICE$', '')
                        elif key.startswith('Component$'):
                            component = key.replace('Component$', '')
                    
                    if service:
                        by_service[service] += cost
                    if component:
                        by_component[component] += cost
                    
                    total_cost += cost
            
            # Count resources (simplified - in production, would query each service)
            resource_count = self._estimate_resource_count(product)
            
            return DailyMetric(
                date=start_date.strftime('%Y-%m-%d'),
                product_id=product.id,
                daily_cost=total_cost,
                resource_count=resource_count,
                by_service=dict(by_service),
                by_component=dict(by_component)
            )
            
        except Exception as e:
            logger.error(f"Error getting cost data for product {product.id}: {e}")
            return None
    
    def _discover_product_resources(self, product: Product) -> List[ResourceMapping]:
        """Discover resources belonging to a product."""
        logger.info(f"Discovering resources for product: {product.id}")
        
        resources = []
        
        for account_id in product.accounts:
            try:
                # Get resources using Resource Groups Tagging API
                tagging_client = get_client_with_assumed_role(
                    'resourcegroupstaggingapi',
                    account_id,
                    self.master_role_name
                )
                
                # Query resources with Product tag
                response = tagging_client.get_resources(
                    TagFilters=[
                        {
                            'Key': 'Product',
                            'Values': [product.id]
                        }
                    ]
                )
                
                for resource in response['ResourceTagMappingList']:
                    arn = resource['ResourceARN']
                    tags = {tag['Key']: tag['Value'] for tag in resource['Tags']}
                    
                    # Determine if resource is shared
                    is_shared = self._is_shared_resource(arn, tags)
                    
                    mapping = ResourceMapping(
                        resource_arn=arn,
                        type='shared' if is_shared else 'dedicated',
                        primary_product=product.id,
                        discovery_source=ResourceDiscoverySource.TAGS,
                        confidence=Confidence.HIGH if 'Product' in tags else Confidence.MEDIUM,
                        metadata={
                            'tags': tags,
                            'account_id': account_id
                        }
                    )
                    
                    resources.append(mapping)
                
                # Also check CloudFormation stacks
                cf_resources = self._discover_cloudformation_resources(
                    account_id, product
                )
                resources.extend(cf_resources)
                
            except Exception as e:
                logger.error(f"Error discovering resources in account {account_id}: {e}")
        
        return resources
    
    def _discover_cloudformation_resources(
        self, account_id: str, product: Product
    ) -> List[ResourceMapping]:
        """Discover resources from CloudFormation stacks."""
        resources = []
        
        try:
            cf_client = get_client_with_assumed_role(
                'cloudformation',
                account_id,
                self.master_role_name
            )
            
            # List stacks with product tags
            response = cf_client.list_stacks(
                StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE']
            )
            
            for stack in response['StackSummaries']:
                stack_name = stack['StackName']
                
                # Get stack tags
                stack_response = cf_client.describe_stacks(
                    StackName=stack_name
                )
                
                if stack_response['Stacks']:
                    stack_tags = {
                        tag['Key']: tag['Value']
                        for tag in stack_response['Stacks'][0].get('Tags', [])
                    }
                    
                    if stack_tags.get('Product') == product.id:
                        # Get stack resources
                        resources_response = cf_client.list_stack_resources(
                            StackName=stack_name
                        )
                        
                        for resource in resources_response['StackResourceSummaries']:
                            if resource.get('PhysicalResourceId'):
                                mapping = ResourceMapping(
                                    resource_arn=resource['PhysicalResourceId'],
                                    type='dedicated',
                                    primary_product=product.id,
                                    discovery_source=ResourceDiscoverySource.CLOUDFORMATION,
                                    confidence=Confidence.HIGH,
                                    metadata={
                                        'stack_name': stack_name,
                                        'logical_id': resource['LogicalResourceId'],
                                        'resource_type': resource['ResourceType']
                                    }
                                )
                                resources.append(mapping)
        
        except Exception as e:
            logger.warning(f"Error discovering CloudFormation resources: {e}")
        
        return resources
    
    def _is_shared_resource(self, arn: str, tags: Dict[str, str]) -> bool:
        """Determine if a resource is shared across products."""
        # RDS instances with 'shared' in name
        if 'rds' in arn and 'shared' in arn.lower():
            return True
        
        # Resources tagged as shared
        if tags.get('ResourceType') == 'shared':
            return True
        
        # Load balancers serving multiple products
        if 'elasticloadbalancing' in arn:
            # Would need additional logic to check target groups
            return False
        
        return False
    
    def _estimate_resource_count(self, product: Product) -> int:
        """Estimate resource count for a product."""
        # In production, would query each service API
        # For now, return a reasonable estimate based on cost
        return 50  # Placeholder
    
    def _save_metrics(self, metric: DailyMetric):
        """Save metrics to DynamoDB."""
        item = metric.to_dynamodb_item()
        batch_write_items(self.metrics_table, [item])
    
    def _save_resource_mappings(self, mappings: List[ResourceMapping]):
        """Save resource mappings to DynamoDB."""
        items = [mapping.to_dynamodb_item() for mapping in mappings]
        if items:
            batch_write_items(self.resource_mapping_table, items, batch_size=25)


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for Scout service."""
    scout = Scout()
    
    try:
        results = scout.collect_all_data()
        
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Scout execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }