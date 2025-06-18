#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, Optional, List
from datetime import datetime
import csv
from splunklib.client import connect
from splunklib.binding import HTTPError


class SplunkAPIClient:
    """
    Client for interacting with Splunk REST API using the Splunk Python SDK.
    """
    
    def __init__(self):
        """Initialize Splunk client using environment variables or prompts."""
        # Get Splunk connection parameters
        self.host = get_env_or_prompt("HOST", "Enter Splunk host", "DD_AIRLIFT_SPLK_")
        self.port = int(get_env_or_prompt("PORT", "Enter Splunk port", "DD_AIRLIFT_SPLK_"))
        self.username = get_env_or_prompt("USERNAME", "Enter Splunk username", "DD_AIRLIFT_SPLK_")
        self.password = get_env_or_prompt("PASSWORD", "Enter Splunk password", "DD_AIRLIFT_SPLK_")
        self.scheme = get_env_or_prompt("SCHEME", "Enter scheme (http/https)", "DD_AIRLIFT_SPLK_") or "https"
        
        # Connect to Splunk
        try:
            print(f"Connecting to Splunk at {self.scheme}://{self.host}:{self.port}...")
            self.service = connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                scheme=self.scheme
            )
            print(f"Successfully connected to Splunk as {self.username}")
        except Exception as e:
            print(f"Error connecting to Splunk: {str(e)}")
            sys.exit(1)
    
    def get_formatted_users(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk users.
        
        Returns:
            List of dictionaries containing user information
        """
        try:
            print("Fetching Splunk users...")
            
            # Use the service.get() method to access the authentication/users endpoint
            response = self.service.get('authentication/users', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            users = []
            if 'entry' in data:
                for entry in data['entry']:
                    user_data = {
                        'name': entry.get('name', ''),
                        'title': entry.get('content', {}).get('realname', ''),
                        'email': entry.get('content', {}).get('email', ''),
                        'roles': ', '.join(entry.get('content', {}).get('roles', [])),
                        'capabilities': ', '.join(entry.get('content', {}).get('capabilities', [])),
                        'default_app': entry.get('content', {}).get('defaultApp', ''),
                        'default_app_is_user_override': entry.get('content', {}).get('defaultAppIsUserOverride', ''),
                        'default_app_source_role': entry.get('content', {}).get('defaultAppSourceRole', ''),
                        'timezone': entry.get('content', {}).get('tz', ''),
                        'restart_background_jobs': entry.get('content', {}).get('restart_background_jobs', ''),
                        'type': entry.get('content', {}).get('type', ''),
                        'force_change_pass': entry.get('content', {}).get('force_change_pass', ''),
                        'last_successful_login': entry.get('content', {}).get('last_successful_login', ''),
                        'locked_out': entry.get('content', {}).get('locked-out', ''),
                        'password_change_time': entry.get('content', {}).get('password_change_time', ''),
                        'author': entry.get('author', ''),
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', ''),
                        'links_alternate': entry.get('links', {}).get('alternate', ''),
                        'links_list': entry.get('links', {}).get('list', ''),
                        'links_edit': entry.get('links', {}).get('edit', ''),
                        'links_remove': entry.get('links', {}).get('remove', ''),
                        'links_disable': entry.get('links', {}).get('disable', '')
                    }
                    users.append(user_data)
            
            print(f"Found {len(users)} users")
            return users
            
        except Exception as e:
            print(f"Error fetching users: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def export_to_csv(self, data: List[Dict[str, Any]], filename: str, s3_client: Optional['S3Client'] = None) -> None:
        """
        Export data to CSV file and optionally upload to S3.
        
        Args:
            data: List of dictionaries to export
            filename: Name of the CSV file to create
            s3_client: Optional S3Client instance for uploading to S3
        """
        if not data:
            print(f"No data to export for {filename}")
            return
        
        try:
            # Write CSV file
            print(f"Writing {len(data)} records to {filename}")
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # Get fieldnames from the first record
                fieldnames = list(data[0].keys())
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Write data rows
                for row in data:
                    writer.writerow(row)
            
            print(f"Successfully wrote {filename}")
            
            # Upload to S3 if client is provided
            if s3_client:
                try:
                    # Generate S3 key with timestamp
                    # timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    s3_key = filename # f"splunk_exports/{timestamp}/{filename}"
                    
                    s3_uri = s3_client.upload_csv(filename, s3_key)
                    print(f"CSV uploaded to S3: {s3_uri}")
                    
                except Exception as e:
                    print(f"Warning: Failed to upload {filename} to S3: {str(e)}")
                    
        except Exception as e:
            print(f"Error writing CSV file {filename}: {str(e)}")
            raise

class S3Client:
    def __init__(self, bucket_name: Optional[str] = None):
        """
        Initialize S3 client for uploading CSV files.
        
        Args:
            bucket_name: S3 bucket name (optional, will use AWS_S3_BUCKET env var or prompt)
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            raise ImportError("boto3 is required. Install with: pip install boto3")
        
        self.bucket_name = bucket_name or get_env_or_prompt('AWS_S3_BUCKET', 'Enter S3 bucket name for CSV storage')
        
        try:
            self.s3_client = boto3.client('s3')
            # Test credentials by listing buckets
            self.s3_client.list_buckets()
            print(f"Successfully connected to S3. Using bucket: {self.bucket_name}")
        except NoCredentialsError:
            print("Error: AWS credentials not found. Configure AWS credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY") 
            print("  - IAM role (if running on EC2)")
            sys.exit(1)
        except Exception as e:
            print(f"Error connecting to S3: {str(e)}")
            sys.exit(1)
    
    def upload_csv(self, file_path: str, s3_key: str) -> str:
        """
        Upload a CSV file to S3.
        
        Args:
            file_path: Local path to the CSV file
            s3_key: S3 object key (path) for the uploaded file
            
        Returns:
            S3 URI of the uploaded file
        """
        try:
            print(f"Uploading {file_path} to s3://{self.bucket_name}/{s3_key}")
            
            self.s3_client.upload_file(
                file_path, 
                self.bucket_name, 
                s3_key,
                ExtraArgs={'ContentType': 'text/csv'}
            )
            
            s3_uri = f"s3://{self.bucket_name}/{s3_key}"
            print(f"Successfully uploaded to {s3_uri}")
            return s3_uri
            
        except Exception as e:
            print(f"Error uploading {file_path} to S3: {str(e)}")
            raise
    
    def check_object_exists(self, s3_key: str) -> bool:
        """
        Check if an object exists in S3.
        
        Args:
            s3_key: S3 object key to check
            
        Returns:
            True if object exists, False otherwise
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=s3_key)
            return True
        except:
            return False

def get_datadog_org_info():
    """Get Datadog organization information using the API."""
    try:
        from datadog_api_client import ApiClient, Configuration
        from datadog_api_client.v1.api.organizations_api import OrganizationsApi
        
        dd_api_key = os.environ.get("DD_API_KEY")
        dd_app_key = os.environ.get("DD_APP_KEY")
        dd_site = os.environ.get("DD_SITE", "datadoghq.com")
        
        if not dd_api_key or not dd_app_key:
            return "API keys not configured", dd_site
        
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = dd_api_key
        configuration.api_key["appKeyAuth"] = dd_app_key
        
        # Set the server based on DD_SITE
        if dd_site != "datadoghq.com":
            configuration.server_variables["site"] = dd_site
        
        with ApiClient(configuration) as api_client:
            api_instance = OrganizationsApi(api_client)
            # List organizations to get the current org info
            response = api_instance.list_orgs()
            
            if response.orgs and len(response.orgs) > 0:
                # Get the first org (usually the current one)
                org = response.orgs[0]
                org_name = org.name if hasattr(org, 'name') and org.name else "Unknown"
                return org_name, dd_site
            else:
                return "No organization found", dd_site
                
    except ImportError:
        return "datadog-api-client not installed", dd_site
    except Exception as e:
        return f"API Error: {str(e)[:30]}...", dd_site

def get_s3_bucket_info():
    """Get S3 bucket information and connectivity status."""
    bucket_name = os.environ.get("AWS_S3_BUCKET")
    
    if not bucket_name:
        return "Not configured", "N/A"
    
    try:
        # Try to initialize S3Client which will verify connectivity
        s3_client = S3Client(bucket_name)
        return bucket_name, "Connected"
    except ImportError:
        return bucket_name, "boto3 not installed"
    except Exception as e:
        # Extract meaningful error message
        error_str = str(e).lower()
        if "credentials" in error_str:
            return bucket_name, "No AWS credentials"
        elif "access denied" in error_str or "forbidden" in error_str:
            return bucket_name, "Access denied"
        elif "does not exist" in error_str or "not found" in error_str:
            return bucket_name, "Bucket not found"
        else:
            return bucket_name, "Connection failed"

def display_banner():
    """Display the Airlift banner with configuration details."""
    banner = """
████████████████████████████████████████████████████████████████████████████████
██                                                                            ██
██       █████╗ ██╗██████╗ ██╗     ██╗███████╗████████╗                       ██
██      ██╔══██╗██║██╔══██╗██║     ██║██╔════╝╚══██╔══╝                       ██
██      ███████║██║██████╔╝██║     ██║█████╗     ██║                          ██
██      ██╔══██║██║██╔══██╗██║     ██║██╔══╝     ██║                          ██
██      ██║  ██║██║██║  ██║███████╗██║██║        ██║                          ██
██      ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝        ╚═╝                          ██
██                                                                            ██
████████████████████████████████████████████████████████████████████████████████
"""
    
    print(banner)
    
    # Get configuration details
    splunk_host = os.environ.get("DD_AIRLIFT_SPLK_HOST", "Not configured")
    splunk_port = os.environ.get("DD_AIRLIFT_SPLK_PORT", "8089")
    
    # Get Datadog organization information via API
    dd_org, dd_site = get_datadog_org_info()
    
    # Get S3 bucket information and connectivity status
    s3_bucket, s3_status = get_s3_bucket_info()
    
    # Format each line to exactly 77 characters (79 total with borders)
    splunk_line = f"  Splunk Server: {splunk_host}:{splunk_port}"
    splunk_line = f"{splunk_line:<77}"
    
    dd_org_line = f"  Datadog Org:   {dd_org}"
    dd_org_line = f"{dd_org_line:<77}"
    
    dd_site_line = f"  Datadog Site:  {dd_site}"
    dd_site_line = f"{dd_site_line:<77}"
    
    s3_line = f"  S3 Bucket:     {s3_bucket} Status: {s3_status}"
    s3_line = f"{s3_line:<77}"
    
    config_info = f"""
Configuration Details:
┌─────────────────────────────────────────────────────────────────────────────┐
│{splunk_line}│
│{dd_org_line}│
│{dd_site_line}│
│{s3_line}│
└─────────────────────────────────────────────────────────────────────────────┘
"""
    
    print(config_info)

def get_env_or_prompt(env_var: str, prompt: str, prefix: str = "") -> str:
    """
    Get value from environment variable or prompt user for input.
    
    Args:
        env_var: Base environment variable name
        prompt: Prompt to show user if env var not found
        prefix: Optional prefix to add to env var name (e.g., 'DD_AIRLIFT_SPLK_')
    """
    # Try with prefix first, then without
    if prefix:
        value = os.environ.get(f"{prefix}{env_var}")
        if value:
            return value
    return os.environ.get(env_var) or input(f"{prompt}: ").strip()

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Export Splunk data to CSV files and optionally upload to S3.')
    parser.add_argument('--config', action='store_true', help='Enable config category export')
    parser.add_argument('--content', action='store_true', help='Enable content category export')
    parser.add_argument('--usage', action='store_true', help='Enable usage category export')
    parser.add_argument('--all', action='store_true', help='Enable all categories')
    return parser.parse_args()

def cleanup_existing_csvs() -> None:
    """Delete existing CSV files from previous runs."""
    csv_files = [
        'splunk_config_users.csv'
    ]
    
    for csv_file in csv_files:
        try:
            if os.path.exists(csv_file):
                os.remove(csv_file)
                print(f"Removed existing file: {csv_file}")
        except Exception as e:
            print(f"Warning: Could not remove {csv_file}: {str(e)}")

def main():
    """Main function to export Splunk data to CSV files and optionally upload to S3."""
    # Display banner
    display_banner()
    
    # Parse command line arguments
    args = parse_args()
    
    # If no categories are specified, show help and exit
    if not any([args.config, args.content, args.usage, args.all]):
        print("Error: No categories enabled. Use --config, --content, --usage, or --all to enable categories.")
        print("Run with --help for more information.")
        sys.exit(1)
    
    # Initialize Splunk client
    splunk_client = SplunkAPIClient()
    
    # Initialize S3 client for uploading CSVs to S3 (optional - only if bucket is configured)
    s3_client = None
    try:
        # Check if S3 bucket is configured via environment variable
        s3_bucket = os.environ.get('AWS_S3_BUCKET')
        if s3_bucket:
            print(f"\nS3 bucket configured: {s3_bucket}")
            s3_client = S3Client(s3_bucket)
        else:
            # Ask user if they want to use S3 for CSV storage
            use_s3 = input("\nWould you like to upload CSVs to S3? (y/N): ").strip().lower()
            if use_s3 in ['y', 'yes']:
                s3_client = S3Client()
            else:
                print("Skipping S3 upload.")
    except Exception as e:
        print(f"Warning: Could not initialize S3 client: {str(e)}")
        print("Continuing without S3 upload.")
    
    # Define the data to export and their categories
    data_configs = [
        {
            "name": "splunk_config_users",
            "getter": splunk_client.get_formatted_users,
            "category": "config"
        },
        {
            "name": "splunk_config_roles",
            "getter": splunk_client.get_formatted_roles,
            "category": "config"
        },
        {
            "name": "splunk_config_addons",
            "getter": splunk_client.get_formatted_addons,
            "category": "config"
        },
        {
            "name": "splunk_config_inputs",
            "getter": splunk_client.get_formatted_inputs,
            "category": "config"
        },
        {
            "name": "splunk_config_indexes",
            "getter": splunk_client.get_formatted_indexes,
            "category": "config"
        },
        {
            "name": "splunk_content_apps",
            "getter": splunk_client.get_formatted_app_content,
            "category": "content"
        },
        {
            "name": "splunk_content_alerts",
            "getter": splunk_client.get_formatted_alerts,
            "category": "content"
        },
        {
            "name": "splunk_content_reports",
            "getter": splunk_client.get_formatted_reports,
            "category": "content"
        },
        {
            "name": "splunk_content_detection_rules",
            "getter": splunk_client.get_formatted_detection_rules,
            "category": "content"
        },
        {
            "name": "splunk_content_analytic_stories",
            "getter": splunk_client.get_formatted_analytic_stories,
            "category": "content"
        },
        {
            "name": "splunk_content_playbook_responses",
            "getter": splunk_client.get_formatted_playbook_responses,
            "category": "content"
        },
        {
            "name": "splunk_usage_license",
            "getter": splunk_client.get_formatted_license_usage,
            "category": "usage"
        },
        {
            "name": "splunk_usage_index_volumes",
            "getter": lambda: splunk_client.get_formatted_index_usage(days=30),
            "category": "usage"
        },
        {
            "name": "splunk_usage_sourcetype_volumes",
            "getter": lambda: splunk_client.get_formatted_sourcetype_usage(days=30),
            "category": "usage"
        },
        {
            "name": "splunk_usage_user_logins",
            "getter": lambda: splunk_client.get_formatted_user_logins(days=30),
            "category": "usage"
        }
    ]
    
    # Filter data configs based on enabled categories
    enabled_categories = []
    if args.all:
        enabled_categories = ["config", "content", "usage"]
    else:
        if args.config:
            enabled_categories.append("config")
        if args.content:
            enabled_categories.append("content")
        if args.usage:
            enabled_categories.append("usage")
    
    filtered_configs = [
        config for config in data_configs
        if config["category"] in enabled_categories
    ]
    
    print(f"\nEnabled categories: {', '.join(enabled_categories)}")
    print(f"Processing {len(filtered_configs)} data configurations")
    
    # Print all configurations that will be processed
    print("\nConfigurations to be processed:")
    for config in filtered_configs:
        print(f"- {config['name']} (category: {config['category']})")
    
    # Clean up existing CSVs
    cleanup_existing_csvs()
    
    # Process each data configuration
    current_category = None
    current_item = None
    for i, config in enumerate(filtered_configs):
        # If we're starting a new category, pause for review
        if current_category != config["category"]:
            if current_category is not None:
                print(f"\n{'='*80}")
                print(f"Completed {current_category} category.")
                print(f"Review the output above and press Enter to continue with {config['category']} category...")
                input()
            current_category = config["category"]
            print(f"\n{'='*80}")
            print(f"Starting {current_category} category...")
            print(f"{'='*80}")
        
        # If we're moving to a new item within the same category, pause for review
        if current_item is not None:
            print(f"\n{'-'*80}")
            print(f"Completed {current_item}.")
            # Get the next item name if available
            next_item = filtered_configs[i]['name'] if i < len(filtered_configs) else None
            if next_item:
                print(f"Review the output above and press Enter to continue with {next_item}...")
            else:
                print("Review the output above and press Enter to continue...")
            input()
        
        current_item = config["name"]
        
        try:
            print(f"\n{'='*80}")
            print(f"Processing {config['name']}...")
            print(f"{'='*80}")
            
            # Get the data
            print(f"Calling getter function for {config['name']}...")
            data = config["getter"]()
            print(f"Got {len(data)} entries for {config['name']}")
            
            if not data:
                print(f"No data found for {config['name']}, skipping CSV export")
                continue
            
            # Export to CSV (and optionally upload to S3)
            csv_filename = f"{config['name']}.csv"
            print(f"Exporting to {csv_filename}...")
            try:
                splunk_client.export_to_csv(data, csv_filename, s3_client=s3_client)
                print(f"Successfully exported to {csv_filename}")
                if s3_client:
                    print(f"CSV uploaded to S3 for {csv_filename}")
            except Exception as e:
                print(f"Error exporting to CSV: {str(e)}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                continue
            

            
        except Exception as e:
            print(f"Error processing {config['name']}: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            continue
    
    # Final pause after all categories are complete
    print(f"\n{'='*80}")
    print("All categories completed.")
    print("Review the output above and press Enter to exit...")
    input()

if __name__ == "__main__":
    main() 