"""
The Dispatcher - Alert Routing Service
Routes alerts to appropriate teams with smart filtering
"""

import os
import json
from datetime import datetime, time, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

import boto3
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from slack_sdk.webhook import WebhookClient
import requests

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import (
    get_env_var, get_dynamodb_resource, get_current_timestamp
)
from shared.constants import (
    ANOMALIES_TABLE, PRODUCTS_TABLE,
    Severity, AnomalyStatus, AnomalyType,
    CRITICAL_COST_IMPACT, HIGH_COST_IMPACT, MEDIUM_COST_IMPACT
)
from shared.models import Anomaly, Product

logger = Logger()


class Dispatcher:
    """The Dispatcher service for alert routing."""
    
    def __init__(self):
        self.anomalies_table = get_env_var('ANOMALIES_TABLE', ANOMALIES_TABLE)
        self.products_table = get_env_var('PRODUCTS_TABLE', PRODUCTS_TABLE)
        self.slack_webhook_url = get_env_var('SLACK_WEBHOOK_URL', '')
        self.pagerduty_token = get_env_var('PAGERDUTY_TOKEN', '')
        self.pagerduty_service_id = get_env_var('PAGERDUTY_SERVICE_ID', '')
        self.teams_webhook_url = get_env_var('TEAMS_WEBHOOK_URL', '')
        self.alert_email = get_env_var('ALERT_EMAIL', '')
        self.dynamodb = get_dynamodb_resource()
        self.ses = boto3.client('ses')
        
        # Alert suppression cache (in production, use DynamoDB or Redis)
        self.suppression_cache = {}
        
    def process_anomaly_stream(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process DynamoDB stream records from Anomalies table."""
        logger.info(f"Processing {len(records)} anomaly records for dispatch")
        
        results = {
            'records_processed': 0,
            'alerts_sent': 0,
            'alerts_suppressed': 0,
            'errors': []
        }
        
        # Group anomalies by product for batching
        anomalies_by_product = defaultdict(list)
        
        for record in records:
            try:
                # Process MODIFY events where context was added
                if record['eventName'] != 'MODIFY':
                    continue
                
                # Get old and new images
                old_image = record.get('dynamodb', {}).get('OldImage', {})
                new_image = record.get('dynamodb', {}).get('NewImage', {})
                
                if not new_image:
                    continue
                
                # Convert DynamoDB format
                old_data = self._unmarshall_dynamodb_item(old_image) if old_image else {}
                new_data = self._unmarshall_dynamodb_item(new_image)
                
                # Check if this is an enriched anomaly (context added)
                if not old_data.get('context', {}).get('enriched') and new_data.get('context', {}).get('enriched'):
                    anomaly = Anomaly.from_dynamodb_item(new_data)
                    
                    # Check if already routed
                    if anomaly.routing and anomaly.routing.get('notifiedChannels'):
                        continue
                    
                    anomalies_by_product[anomaly.product_id].append(anomaly)
                
                results['records_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing dispatch record: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Process anomalies by product
        for product_id, anomalies in anomalies_by_product.items():
            try:
                # Get product details
                product = self._get_product(product_id)
                if not product:
                    logger.warning(f"Product not found: {product_id}")
                    continue
                
                # Route alerts
                routed_count = self._route_alerts(product, anomalies)
                results['alerts_sent'] += routed_count
                results['alerts_suppressed'] += len(anomalies) - routed_count
                
            except Exception as e:
                error_msg = f"Error routing alerts for product {product_id}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.info(f"Dispatcher processing complete: {results}")
        return results
    
    def _route_alerts(self, product: Product, anomalies: List[Anomaly]) -> int:
        """Route alerts for anomalies."""
        routed_count = 0
        
        # Group by severity and type
        critical_anomalies = [a for a in anomalies if a.severity == Severity.CRITICAL]
        high_anomalies = [a for a in anomalies if a.severity == Severity.HIGH]
        medium_anomalies = [a for a in anomalies if a.severity == Severity.MEDIUM]
        low_anomalies = [a for a in anomalies if a.severity == Severity.LOW]
        
        # Process critical anomalies immediately
        for anomaly in critical_anomalies:
            if self._should_alert(anomaly):
                self._send_critical_alert(product, anomaly)
                routed_count += 1
        
        # Process high severity anomalies
        for anomaly in high_anomalies:
            if self._should_alert(anomaly):
                self._send_high_alert(product, anomaly)
                routed_count += 1
        
        # Batch medium severity anomalies
        if medium_anomalies and self._is_business_hours():
            filtered_medium = [a for a in medium_anomalies if self._should_alert(a)]
            if filtered_medium:
                self._send_batched_alert(product, filtered_medium, Severity.MEDIUM)
                routed_count += len(filtered_medium)
        
        # Low severity go to daily digest (not implemented here)
        # In production, would store these for later digest
        
        return routed_count
    
    def _should_alert(self, anomaly: Anomaly) -> bool:
        """Determine if an alert should be sent."""
        # Check suppression rules
        
        # 1. Known deployments
        if anomaly.context.get('recent_deployments'):
            # Check if deployment was tagged as expected
            for deployment in anomaly.context['recent_deployments']:
                if 'expected_cost_increase' in deployment.get('ref', '').lower():
                    logger.info(f"Suppressing alert for {anomaly.id} - expected deployment")
                    return False
        
        # 2. Duplicate suppression
        cache_key = f"{anomaly.product_id}:{anomaly.type}:{anomaly.severity}"
        last_alert_time = self.suppression_cache.get(cache_key)
        
        if last_alert_time:
            time_diff = (datetime.now() - last_alert_time).total_seconds()
            
            # Suppress if same type/severity alert sent in last hour
            if time_diff < 3600:
                logger.info(f"Suppressing duplicate alert for {anomaly.id}")
                return False
        
        # 3. Business hours check for non-critical
        if anomaly.severity not in [Severity.CRITICAL, Severity.HIGH]:
            if not self._is_business_hours():
                logger.info(f"Suppressing non-critical alert outside business hours: {anomaly.id}")
                return False
        
        # Update suppression cache
        self.suppression_cache[cache_key] = datetime.now()
        
        return True
    
    def _send_critical_alert(self, product: Product, anomaly: Anomaly):
        """Send critical alert via PagerDuty and Slack."""
        logger.info(f"Sending critical alert for anomaly {anomaly.id}")
        
        notified_channels = []
        
        # 1. Send to PagerDuty
        if self.pagerduty_token and self.pagerduty_service_id:
            try:
                self._send_pagerduty_alert(product, anomaly)
                notified_channels.append('pagerduty')
            except Exception as e:
                logger.error(f"Failed to send PagerDuty alert: {e}")
        
        # 2. Send to Slack
        if self.slack_webhook_url:
            try:
                self._send_slack_alert(product, anomaly, urgent=True)
                notified_channels.append('slack')
            except Exception as e:
                logger.error(f"Failed to send Slack alert: {e}")
        
        # 3. Send email
        if self.alert_email:
            try:
                self._send_email_alert(product, anomaly)
                notified_channels.append('email')
            except Exception as e:
                logger.error(f"Failed to send email alert: {e}")
        
        # Update anomaly with routing info
        self._update_anomaly_routing(anomaly, product.team_id, notified_channels)
    
    def _send_high_alert(self, product: Product, anomaly: Anomaly):
        """Send high severity alert via Slack."""
        logger.info(f"Sending high alert for anomaly {anomaly.id}")
        
        notified_channels = []
        
        # Send to Slack
        if self.slack_webhook_url:
            try:
                self._send_slack_alert(product, anomaly, urgent=False)
                notified_channels.append('slack')
            except Exception as e:
                logger.error(f"Failed to send Slack alert: {e}")
        
        # Send to Teams if configured
        if self.teams_webhook_url:
            try:
                self._send_teams_alert(product, anomaly)
                notified_channels.append('teams')
            except Exception as e:
                logger.error(f"Failed to send Teams alert: {e}")
        
        # Update anomaly with routing info
        self._update_anomaly_routing(anomaly, product.team_id, notified_channels)
    
    def _send_batched_alert(self, product: Product, anomalies: List[Anomaly], severity: Severity):
        """Send batched alerts for multiple anomalies."""
        logger.info(f"Sending batched alert for {len(anomalies)} {severity} anomalies")
        
        notified_channels = []
        
        # Create summary message
        summary = self._create_batch_summary(product, anomalies)
        
        # Send to Slack
        if self.slack_webhook_url:
            try:
                webhook = WebhookClient(self.slack_webhook_url)
                webhook.send(blocks=summary['slack_blocks'])
                notified_channels.append('slack')
            except Exception as e:
                logger.error(f"Failed to send batched Slack alert: {e}")
        
        # Update anomalies with routing info
        for anomaly in anomalies:
            self._update_anomaly_routing(anomaly, product.team_id, notified_channels)
    
    def _send_pagerduty_alert(self, product: Product, anomaly: Anomaly):
        """Send alert to PagerDuty."""
        headers = {
            'Authorization': f'Token token={self.pagerduty_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/vnd.pagerduty+json;version=2'
        }
        
        # Create incident
        incident_data = {
            'incident': {
                'type': 'incident',
                'title': f"[{anomaly.severity}] {product.name}: {anomaly.type.value}",
                'service': {
                    'id': self.pagerduty_service_id,
                    'type': 'service_reference'
                },
                'urgency': 'high',
                'body': {
                    'type': 'incident_body',
                    'details': self._format_anomaly_details(anomaly)
                }
            }
        }
        
        response = requests.post(
            'https://api.pagerduty.com/incidents',
            headers=headers,
            json=incident_data,
            timeout=5
        )
        response.raise_for_status()
    
    def _send_slack_alert(self, product: Product, anomaly: Anomaly, urgent: bool = False):
        """Send alert to Slack."""
        webhook = WebhookClient(self.slack_webhook_url)
        
        # Create message blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{'🚨 CRITICAL' if urgent else '⚠️'} Cost Anomaly Detected"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Product:*\n{product.name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Type:*\n{anomaly.type.value}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{anomaly.severity.value}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Cost Impact:*\n${anomaly.cost_impact:,.2f}/day"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n{self._format_anomaly_summary(anomaly)}"
                }
            }
        ]
        
        # Add probable cause if available
        if anomaly.context.get('probable_causes'):
            cause = anomaly.context['probable_causes'][0]
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Probable Cause:*\n{cause['cause']} ({cause['confidence']} confidence)"
                }
            })
        
        # Add actions
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge"
                    },
                    "style": "primary",
                    "value": f"acknowledge_{anomaly.id}"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Details"
                    },
                    "url": f"https://console.aws.amazon.com/cost-management/home"
                }
            ]
        })
        
        webhook.send(blocks=blocks)
    
    def _send_teams_alert(self, product: Product, anomaly: Anomaly):
        """Send alert to Microsoft Teams."""
        message = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Cost Anomaly: {product.name}",
            "themeColor": "FF0000" if anomaly.severity == Severity.CRITICAL else "FF9900",
            "sections": [
                {
                    "activityTitle": f"Cost Anomaly Detected - {anomaly.type.value}",
                    "activitySubtitle": f"Product: {product.name}",
                    "facts": [
                        {"name": "Severity", "value": anomaly.severity.value},
                        {"name": "Cost Impact", "value": f"${anomaly.cost_impact:,.2f}/day"},
                        {"name": "Detection Time", "value": anomaly.detected_at}
                    ],
                    "text": self._format_anomaly_summary(anomaly)
                }
            ]
        }
        
        response = requests.post(self.teams_webhook_url, json=message, timeout=5)
        response.raise_for_status()
    
    def _send_email_alert(self, product: Product, anomaly: Anomaly):
        """Send email alert via SES."""
        subject = f"[{anomaly.severity}] Budget Guard Alert: {product.name}"
        
        body_html = f"""
        <html>
        <body>
            <h2>Cost Anomaly Detected</h2>
            <table>
                <tr><td><strong>Product:</strong></td><td>{product.name}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{anomaly.type.value}</td></tr>
                <tr><td><strong>Severity:</strong></td><td>{anomaly.severity.value}</td></tr>
                <tr><td><strong>Cost Impact:</strong></td><td>${anomaly.cost_impact:,.2f}/day</td></tr>
            </table>
            <h3>Details</h3>
            <p>{self._format_anomaly_details(anomaly)}</p>
        </body>
        </html>
        """
        
        self.ses.send_email(
            Source=self.alert_email,
            Destination={'ToAddresses': [self.alert_email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': body_html}}
            }
        )
    
    def _create_batch_summary(self, product: Product, anomalies: List[Anomaly]) -> Dict[str, Any]:
        """Create summary for batched alerts."""
        total_impact = sum(a.cost_impact for a in anomalies)
        
        # Group by type
        by_type = defaultdict(list)
        for anomaly in anomalies:
            by_type[anomaly.type.value].append(anomaly)
        
        # Create Slack blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 Cost Anomaly Summary - {product.name}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{len(anomalies)} anomalies detected*\nTotal impact: ${total_impact:,.2f}/day"
                }
            }
        ]
        
        # Add breakdown by type
        for anomaly_type, type_anomalies in by_type.items():
            type_impact = sum(a.cost_impact for a in type_anomalies)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"• *{anomaly_type}*: {len(type_anomalies)} anomalies (${type_impact:,.2f}/day)"
                }
            })
        
        return {
            'slack_blocks': blocks,
            'summary_text': f"{len(anomalies)} anomalies detected with total impact ${total_impact:,.2f}/day"
        }
    
    def _format_anomaly_summary(self, anomaly: Anomaly) -> str:
        """Format anomaly summary for alerts."""
        summary_parts = []
        
        if anomaly.type == AnomalyType.COST_SPIKE:
            change = anomaly.context.get('percentage_change', 0)
            summary_parts.append(f"Cost increased by {change:.1f}%")
            
            if anomaly.context.get('top_contributor'):
                top = anomaly.context['top_contributor']
                summary_parts.append(f"Main driver: {top['service']} (+${top['cost_increase']:.2f})")
        
        elif anomaly.type == AnomalyType.BUDGET_VIOLATION:
            percentage = anomaly.context.get('budget_percentage', 0)
            summary_parts.append(f"Budget usage at {percentage:.1f}%")
            
            days_left = anomaly.context.get('days_until_budget_exhausted')
            if days_left is not None:
                summary_parts.append(f"Budget will be exhausted in {days_left} days")
        
        elif anomaly.type == AnomalyType.NEW_RESOURCE:
            service = anomaly.context.get('service', 'Unknown')
            cost = anomaly.context.get('daily_cost', 0)
            summary_parts.append(f"New {service} resources detected")
            summary_parts.append(f"Daily cost: ${cost:.2f}")
        
        return " | ".join(summary_parts)
    
    def _format_anomaly_details(self, anomaly: Anomaly) -> str:
        """Format detailed anomaly information."""
        details = [self._format_anomaly_summary(anomaly)]
        
        # Add recent deployments
        if anomaly.context.get('recent_deployments'):
            details.append("\nRecent Deployments:")
            for dep in anomaly.context['recent_deployments'][:3]:
                details.append(f"  - {dep['environment']}: {dep['ref']} by {dep['creator']}")
        
        # Add CloudTrail events
        if anomaly.context.get('cloudtrail_events'):
            details.append("\nRelevant AWS Activities:")
            for event in anomaly.context['cloudtrail_events'][:3]:
                details.append(f"  - {event['event_name']} by {event['username']}")
        
        return "\n".join(details)
    
    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        now = datetime.now()
        
        # Business hours: Monday-Friday, 8 AM - 6 PM
        if now.weekday() >= 5:  # Weekend
            return False
        
        current_time = now.time()
        return time(8, 0) <= current_time <= time(18, 0)
    
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
    
    def _update_anomaly_routing(self, anomaly: Anomaly, team_id: str, channels: List[str]):
        """Update anomaly with routing information."""
        table = self.dynamodb.Table(self.anomalies_table)
        
        routing_info = {
            'team': team_id,
            'notifiedChannels': channels,
            'notifiedAt': get_current_timestamp()
        }
        
        table.update_item(
            Key={
                'PK': anomaly.to_dynamodb_item()['PK'],
                'SK': anomaly.to_dynamodb_item()['SK']
            },
            UpdateExpression='SET routing = :routing',
            ExpressionAttributeValues={
                ':routing': routing_info
            }
        )
    
    def _unmarshall_dynamodb_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB item format to regular dict."""
        from boto3.dynamodb.types import TypeDeserializer
        deserializer = TypeDeserializer()
        return {k: deserializer.deserialize(v) for k, v in item.items()}


def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for Dispatcher service."""
    dispatcher = Dispatcher()
    
    try:
        # Process DynamoDB stream records
        records = event.get('Records', [])
        results = dispatcher.process_anomaly_stream(records)
        
        return {
            'statusCode': 200,
            'body': json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Dispatcher execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }