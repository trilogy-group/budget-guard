"""Shared utility functions for Budget Guard services."""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger

logger = Logger()


def get_env_var(name: str, default: Optional[str] = None) -> str:
    """Get environment variable or raise error if not found and no default."""
    value = os.environ.get(name, default)
    if value is None:
        raise ValueError(f"Environment variable {name} is required")
    return value


def get_dynamodb_client():
    """Get DynamoDB client with proper configuration."""
    return boto3.client('dynamodb')


def get_dynamodb_resource():
    """Get DynamoDB resource with proper configuration."""
    return boto3.resource('dynamodb')


def decimal_to_float(obj):
    """Convert Decimal objects to float for JSON serialization."""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: decimal_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decimal_to_float(v) for v in obj]
    return obj


def float_to_decimal(obj):
    """Convert float objects to Decimal for DynamoDB storage."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: float_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [float_to_decimal(v) for v in obj]
    return obj


def get_current_date() -> str:
    """Get current date in YYYY-MM-DD format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def get_current_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def get_date_range(days: int) -> tuple[str, str]:
    """Get date range for the past N days."""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    return start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")


def calculate_percentage_change(old_value: float, new_value: float) -> float:
    """Calculate percentage change between two values."""
    if old_value == 0:
        return 100.0 if new_value > 0 else 0.0
    return ((new_value - old_value) / old_value) * 100


def assume_role(account_id: str, role_name: str) -> Dict[str, Any]:
    """Assume a role in another AWS account."""
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"BudgetGuard-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        )
        return response['Credentials']
    except ClientError as e:
        logger.error(f"Failed to assume role {role_arn}: {e}")
        raise


def get_client_with_assumed_role(service: str, account_id: str, role_name: str):
    """Get AWS client with assumed role credentials."""
    credentials = assume_role(account_id, role_name)
    
    return boto3.client(
        service,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


def batch_write_items(table_name: str, items: List[Dict[str, Any]], batch_size: int = 25):
    """Batch write items to DynamoDB."""
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(table_name)
    
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=float_to_decimal(item))


def query_items(table_name: str, key_condition: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
    """Query items from DynamoDB."""
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(table_name)
    
    items = []
    last_evaluated_key = None
    
    while True:
        if last_evaluated_key:
            kwargs['ExclusiveStartKey'] = last_evaluated_key
            
        response = table.query(
            KeyConditionExpression=key_condition,
            **kwargs
        )
        
        items.extend(response['Items'])
        
        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
    
    return [decimal_to_float(item) for item in items]


def scan_items(table_name: str, **kwargs) -> List[Dict[str, Any]]:
    """Scan items from DynamoDB."""
    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(table_name)
    
    items = []
    last_evaluated_key = None
    
    while True:
        if last_evaluated_key:
            kwargs['ExclusiveStartKey'] = last_evaluated_key
            
        response = table.scan(**kwargs)
        
        items.extend(response['Items'])
        
        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
    
    return [decimal_to_float(item) for item in items]


def parse_arn(arn: str) -> Dict[str, str]:
    """Parse an AWS ARN into its components."""
    parts = arn.split(':')
    
    if len(parts) < 6:
        raise ValueError(f"Invalid ARN format: {arn}")
    
    return {
        'arn': parts[0],
        'partition': parts[1],
        'service': parts[2],
        'region': parts[3],
        'account': parts[4],
        'resource': ':'.join(parts[5:])
    }


def get_resource_tags(resource_arn: str, session=None) -> Dict[str, str]:
    """Get tags for a resource using the Resource Groups Tagging API."""
    if session:
        tagging = session.client('resourcegroupstaggingapi')
    else:
        tagging = boto3.client('resourcegroupstaggingapi')
    
    try:
        response = tagging.get_resources(
            ResourceARNList=[resource_arn]
        )
        
        if response['ResourceTagMappingList']:
            tags = response['ResourceTagMappingList'][0]['Tags']
            return {tag['Key']: tag['Value'] for tag in tags}
    except ClientError as e:
        logger.warning(f"Failed to get tags for {resource_arn}: {e}")
    
    return {}


def send_to_slack(webhook_url: str, message: Dict[str, Any]):
    """Send a message to Slack via webhook."""
    import requests
    
    try:
        response = requests.post(webhook_url, json=message, timeout=5)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")
        raise