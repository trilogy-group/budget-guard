"""
The Investigator - Context Enrichment Service
Adds context to anomalies for actionable insights
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

import boto3
import requests
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import (
    get_env_var, get_dynamodb_resource, get_current_timestamp,
    parse_arn
)
from shared.constants import (
    ANOMALIES_TABLE, PRODUCTS_TABLE, AnomalyType
)
from shared.models import Anomaly, Product

logger = Logger()


class Investigator:
    """The Investigator service for context enrichment."""
    
    def __init__(self):
        self.anomalies_table = get_env_var('ANOMALIES_TABLE', ANOMALIES_TABLE)
        self.products_table = get_env_var('PRODUCTS_TABLE', PRODUCTS_TABLE)
        self.github_token = get_env_var('GITHUB_TOKEN', '')
        self.jenkins_url = get_env_var('JENKINS_URL', '')
        self.jenkins_token = get_env_var('JENKINS_TOKEN', '')
        self.dynamodb = get_dynamodb_resource()
        self.cloudtrail = boto3.client('cloudtrail')
        
    def process_anomaly_stream(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process DynamoDB stream records from Anomalies table."""
        logger.info(f"Processing {len(records)} anomaly records for enrichment")
        
        results = {
            'records_processed': 0,
            'anomalies_enriched': 0,
            'errors': []
        }
        
        for record in records:
            try:
                # Only process INSERT events (new anomalies)
                if record['eventName'] != 'INSERT':
                    continue
                
                # Get the new image
                new_image = record.get('dynamodb', {}).get('NewImage', {})
                if not new_image:
                    continue
                
                # Convert DynamoDB format to regular dict
                anomaly_data = self._unmarshall_dynamodb_item(new_image)
                
                # Skip if not an anomaly record or already has context
                if not anomaly_data.get('PK', '').startswith('ANOMALY#'):
                    continue
                
                # Skip if already enriched
                if anomaly_data.get('context', {}).get('enriched'):
                    continue
                
                anomaly = Anomaly.from_dynamodb_item(anomaly_data)
                
                # Enrich the anomaly
                enriched_anomaly = self._enrich_anomaly(anomaly)
                
                # Update the anomaly record
                self._update_anomaly(enriched_anomaly)
                
                results['anomalies_enriched'] += 1
                results['records_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing anomaly record: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.info(f"Investigator processing complete: {results}")
        return results
    
    def _enrich_anomaly(self, anomaly: Anomaly) -> Anomaly:
        """Enrich an anomaly with context."""
        logger.info(f"Enriching anomaly {anomaly.id} of type {anomaly.type}")
        
        # Get product details
        product = self._get_product(anomaly.product_id)
        if not product:
            logger.warning(f"Product not found: {anomaly.product_id}")
            return anomaly
        
        # Initialize context if not present
        if not anomaly.context:
            anomaly.context = {}
        
        # Add enrichment based on anomaly type
        if anomaly.type == AnomalyType.COST_SPIKE:
            self._enrich_cost_spike(anomaly, product)
        elif anomaly.type == AnomalyType.NEW_RESOURCE:
            self._enrich_new_resource(anomaly, product)
        elif anomaly.type == AnomalyType.BUDGET_VIOLATION:
            self._enrich_budget_violation(anomaly, product)
        elif anomaly.type == AnomalyType.UNTAGGED_RESOURCE:
            self._enrich_untagged_resource(anomaly, product)
        elif anomaly.type == AnomalyType.ACQUISITION_MISS:
            self._enrich_acquisition_miss(anomaly, product)
        
        # Common enrichments for all types
        self._add_recent_deployments(anomaly, product)
        self._add_recent_commits(anomaly, product)
        self._add_cloudtrail_events(anomaly, product)
        self._find_related_anomalies(anomaly)
        self._suggest_probable_cause(anomaly)
        
        # Mark as enriched
        anomaly.context['enriched'] = True
        anomaly.context['enriched_at'] = get_current_timestamp()
        
        return anomaly
    
    def _enrich_cost_spike(self, anomaly: Anomaly, product: Product):
        """Enrich cost spike anomaly."""
        # Analyze service changes
        service_changes = anomaly.context.get('service_changes', {})
        
        if service_changes:
            # Find the top contributor
            top_service = max(service_changes.items(), key=lambda x: x[1])
            anomaly.context['top_contributor'] = {
                'service': top_service[0],
                'cost_increase': top_service[1]
            }
        
        # Check for auto-scaling events
        if 'EC2' in service_changes or 'AutoScaling' in service_changes:
            anomaly.context['possible_causes'] = anomaly.context.get('possible_causes', [])
            anomaly.context['possible_causes'].append('Auto-scaling activity detected')
    
    def _enrich_new_resource(self, anomaly: Anomaly, product: Product):
        """Enrich new resource anomaly."""
        service = anomaly.context.get('service', '')
        
        # Map service to resource type
        resource_type_map = {
            'AmazonEC2': 'EC2 instances',
            'AmazonRDS': 'RDS databases',
            'AWSLambda': 'Lambda functions',
            'AmazonECS': 'ECS services',
            'ElasticLoadBalancing': 'Load balancers'
        }
        
        resource_type = resource_type_map.get(service, 'resources')
        anomaly.context['resource_type'] = resource_type
        
        # Add creation source hint
        anomaly.context['creation_hints'] = [
            f"Check recent deployments for new {resource_type}",
            "Review CloudFormation stack updates",
            "Check auto-scaling configurations"
        ]
    
    def _enrich_budget_violation(self, anomaly: Anomaly, product: Product):
        """Enrich budget violation anomaly."""
        # Calculate days until budget exhausted
        budget_percentage = anomaly.context.get('budget_percentage', 0) / 100
        current_day = datetime.now().day
        days_in_month = 30
        
        if budget_percentage > 0:
            days_until_exhausted = (1 - budget_percentage) / (budget_percentage / current_day)
            anomaly.context['days_until_budget_exhausted'] = max(0, int(days_until_exhausted))
        
        # Add spending trend
        anomaly.context['spending_trend'] = 'accelerating' if budget_percentage > (current_day / days_in_month) else 'normal'
    
    def _enrich_untagged_resource(self, anomaly: Anomaly, product: Product):
        """Enrich untagged resource anomaly."""
        # Parse resource ARN for details
        try:
            arn_parts = parse_arn(anomaly.resource)
            anomaly.context['resource_details'] = {
                'service': arn_parts['service'],
                'region': arn_parts['region'],
                'account': arn_parts['account'],
                'resource_type': arn_parts['resource'].split('/')[0] if '/' in arn_parts['resource'] else arn_parts['resource']
            }
        except Exception as e:
            logger.warning(f"Failed to parse ARN {anomaly.resource}: {e}")
    
    def _enrich_acquisition_miss(self, anomaly: Anomaly, product: Product):
        """Enrich acquisition miss anomaly."""
        # Calculate monetary impact
        baseline_cost = anomaly.context.get('baseline_cost', 0)
        target_reduction = anomaly.context.get('target_reduction', 0) / 100
        actual_reduction = anomaly.context.get('actual_reduction', 0) / 100
        
        monthly_shortfall = baseline_cost * 30 * (target_reduction - actual_reduction)
        anomaly.context['monthly_shortfall'] = monthly_shortfall
        
        # Add improvement suggestions
        anomaly.context['improvement_suggestions'] = [
            "Review and optimize largest cost drivers",
            "Consider reserved instances or savings plans",
            "Implement auto-scaling for variable workloads",
            "Review and remove unused resources"
        ]
    
    def _add_recent_deployments(self, anomaly: Anomaly, product: Product):
        """Add recent deployment information."""
        deployments = []
        
        # Check GitHub deployments
        if self.github_token and product.repos:
            for repo in product.repos[:3]:  # Limit to 3 repos
                try:
                    deployments.extend(self._get_github_deployments(repo, anomaly.detected_at))
                except Exception as e:
                    logger.warning(f"Failed to get GitHub deployments for {repo}: {e}")
        
        # Check Jenkins builds
        if self.jenkins_url and self.jenkins_token:
            try:
                deployments.extend(self._get_jenkins_builds(product.id, anomaly.detected_at))
            except Exception as e:
                logger.warning(f"Failed to get Jenkins builds: {e}")
        
        if deployments:
            # Sort by timestamp and get most recent
            deployments.sort(key=lambda x: x['timestamp'], reverse=True)
            anomaly.context['recent_deployments'] = deployments[:5]
    
    def _add_recent_commits(self, anomaly: Anomaly, product: Product):
        """Add recent commit information."""
        commits = []
        
        if self.github_token and product.repos:
            for repo in product.repos[:3]:  # Limit to 3 repos
                try:
                    commits.extend(self._get_github_commits(repo, anomaly.detected_at))
                except Exception as e:
                    logger.warning(f"Failed to get GitHub commits for {repo}: {e}")
        
        if commits:
            # Sort by timestamp and get most recent
            commits.sort(key=lambda x: x['timestamp'], reverse=True)
            anomaly.context['recent_commits'] = commits[:10]
    
    def _add_cloudtrail_events(self, anomaly: Anomaly, product: Product):
        """Add relevant CloudTrail events."""
        try:
            # Look for events around anomaly detection time
            end_time = datetime.fromisoformat(anomaly.detected_at.replace('Z', '+00:00'))
            start_time = end_time - timedelta(hours=2)
            
            events = []
            
            # Query CloudTrail for each account
            for account_id in product.accounts[:2]:  # Limit to 2 accounts
                try:
                    response = self.cloudtrail.lookup_events(
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50
                    )
                    
                    # Filter for relevant events
                    relevant_events = []
                    for event in response.get('Events', []):
                        event_name = event.get('EventName', '')
                        
                        # Look for resource creation/modification events
                        if any(action in event_name for action in [
                            'Create', 'Launch', 'Run', 'Start', 'Update', 'Modify',
                            'Scale', 'Resize', 'Allocate'
                        ]):
                            relevant_events.append({
                                'event_name': event_name,
                                'event_time': event['EventTime'].isoformat(),
                                'username': event.get('Username', 'Unknown'),
                                'source': event.get('EventSource', '')
                            })
                    
                    events.extend(relevant_events)
                    
                except Exception as e:
                    logger.warning(f"Failed to query CloudTrail for account {account_id}: {e}")
            
            if events:
                # Sort by timestamp and get most recent
                events.sort(key=lambda x: x['event_time'], reverse=True)
                anomaly.context['cloudtrail_events'] = events[:10]
                
        except Exception as e:
            logger.warning(f"Failed to get CloudTrail events: {e}")
    
    def _find_related_anomalies(self, anomaly: Anomaly):
        """Find related anomalies."""
        try:
            # Query for other anomalies around the same time
            table = self.dynamodb.Table(self.anomalies_table)
            
            # Use the date from the anomaly PK
            anomaly_date = anomaly.detected_at[:10]
            
            response = table.query(
                IndexName='product-status-index',
                KeyConditionExpression=Key('productId').eq(anomaly.product_id) & Key('status').eq('ACTIVE')
            )
            
            related = []
            anomaly_time = datetime.fromisoformat(anomaly.detected_at.replace('Z', '+00:00'))
            
            for item in response.get('Items', []):
                if item['id'] == anomaly.id:
                    continue
                
                other_time = datetime.fromisoformat(item['detectedAt'].replace('Z', '+00:00'))
                time_diff = abs((anomaly_time - other_time).total_seconds())
                
                # Consider anomalies within 4 hours as related
                if time_diff <= 4 * 3600:
                    related.append({
                        'id': item['id'],
                        'type': item['type'],
                        'cost_impact': float(item.get('costImpact', 0)),
                        'time_difference_minutes': int(time_diff / 60)
                    })
            
            if related:
                anomaly.context['related_anomalies'] = related[:5]
                
        except Exception as e:
            logger.warning(f"Failed to find related anomalies: {e}")
    
    def _suggest_probable_cause(self, anomaly: Anomaly):
        """Suggest probable cause based on context."""
        probable_causes = []
        
        # Analyze based on anomaly type and context
        if anomaly.type == AnomalyType.COST_SPIKE:
            # Check for recent deployments
            if anomaly.context.get('recent_deployments'):
                probable_causes.append({
                    'cause': 'Recent deployment',
                    'confidence': 'high',
                    'evidence': f"{len(anomaly.context['recent_deployments'])} deployments in last 2 hours"
                })
            
            # Check for auto-scaling
            if 'auto_scaling_change' in str(anomaly.context):
                probable_causes.append({
                    'cause': 'Auto-scaling activity',
                    'confidence': 'high',
                    'evidence': 'Auto-scaling configuration changes detected'
                })
            
            # Check for CloudTrail events
            if anomaly.context.get('cloudtrail_events'):
                scale_events = [e for e in anomaly.context['cloudtrail_events'] 
                               if 'Scale' in e['event_name'] or 'Resize' in e['event_name']]
                if scale_events:
                    probable_causes.append({
                        'cause': 'Manual scaling operation',
                        'confidence': 'medium',
                        'evidence': f"{len(scale_events)} scaling events detected"
                    })
        
        elif anomaly.type == AnomalyType.NEW_RESOURCE:
            if anomaly.context.get('recent_deployments'):
                probable_causes.append({
                    'cause': 'Deployment created new resources',
                    'confidence': 'high',
                    'evidence': 'Deployment occurred before resource appearance'
                })
        
        # Default cause if none found
        if not probable_causes:
            probable_causes.append({
                'cause': 'Unknown - requires manual investigation',
                'confidence': 'low',
                'evidence': 'No automated cause detected'
            })
        
        anomaly.context['probable_causes'] = probable_causes
    
    def _get_github_deployments(self, repo_url: str, detected_at: str) -> List[Dict[str, Any]]:
        """Get recent GitHub deployments."""
        # Extract owner and repo from URL
        parts = repo_url.rstrip('/').split('/')
        owner = parts[-2]
        repo = parts[-1]
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Get deployments
        url = f'https://api.github.com/repos/{owner}/{repo}/deployments'
        response = requests.get(url, headers=headers, timeout=5)
        
        deployments = []
        if response.status_code == 200:
            for deployment in response.json()[:5]:  # Limit to 5 most recent
                created_at = datetime.fromisoformat(deployment['created_at'].replace('Z', '+00:00'))
                detected_time = datetime.fromisoformat(detected_at.replace('Z', '+00:00'))
                
                # Only include deployments within 2 hours before anomaly
                if (detected_time - created_at).total_seconds() <= 2 * 3600:
                    deployments.append({
                        'id': deployment['id'],
                        'environment': deployment.get('environment', 'unknown'),
                        'timestamp': deployment['created_at'],
                        'creator': deployment.get('creator', {}).get('login', 'unknown'),
                        'ref': deployment.get('ref', 'unknown')
                    })
        
        return deployments
    
    def _get_github_commits(self, repo_url: str, detected_at: str) -> List[Dict[str, Any]]:
        """Get recent GitHub commits."""
        # Extract owner and repo from URL
        parts = repo_url.rstrip('/').split('/')
        owner = parts[-2]
        repo = parts[-1]
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Calculate time window
        detected_time = datetime.fromisoformat(detected_at.replace('Z', '+00:00'))
        since = (detected_time - timedelta(hours=4)).isoformat()
        
        # Get commits
        url = f'https://api.github.com/repos/{owner}/{repo}/commits'
        params = {'since': since}
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        commits = []
        if response.status_code == 200:
            for commit in response.json()[:10]:  # Limit to 10 most recent
                commits.append({
                    'sha': commit['sha'][:8],
                    'message': commit['commit']['message'].split('\n')[0][:100],
                    'author': commit['commit']['author']['name'],
                    'timestamp': commit['commit']['author']['date']
                })
        
        return commits
    
    def _get_jenkins_builds(self, product_id: str, detected_at: str) -> List[Dict[str, Any]]:
        """Get recent Jenkins builds."""
        # This is a placeholder - would need actual Jenkins API integration
        return []
    
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
    
    def _update_anomaly(self, anomaly: Anomaly):
        """Update anomaly record with enriched context."""
        table = self.dynamodb.Table(self.anomalies_table)
        
        table.update_item(
            Key={
                'PK': anomaly.to_dynamodb_item()['PK'],
                'SK': anomaly.to_dynamodb_item()['SK']
            },
            UpdateExpression='SET #ctx = :context',
            ExpressionAttributeNames={
                '#ctx': 'context'
            },
            ExpressionAttributeValues={
                ':context': anomaly.context
            }
        )
    
    def _unmarshall_dynamodb_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB item format to regular dict."""
        from boto3.dynamodb.types import TypeDeserializer
        deserializer = TypeDeserializer()
        return {k: deserializer.deserialize(v) for k, v in item.items()}


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for Investigator service."""
    investigator = Investigator()
    
    try:
        # Process DynamoDB stream records
        records = event.get('Records', [])
        results = investigator.process_anomaly_stream(records)
        
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Investigator execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }