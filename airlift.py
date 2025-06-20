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
        self.scheme = get_env_or_prompt("SCHEME", "Enter scheme (http/https) [default: https]", "DD_AIRLIFT_SPLK_") or "https"
        
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
    
    def get_formatted_indexes(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk indexes.
        
        Returns:
            List of dictionaries containing index information
        """
        try:
            print("Fetching Splunk indexes...")
            
            # Use the service.get() method to access the data/indexes endpoint
            response = self.service.get('data/indexes', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            indexes = []
            if 'entry' in data:
                for entry in data['entry']:
                    index_data = {
                        'name': entry.get('name', ''),
                        'current_db_size_mb': entry.get('content', {}).get('currentDBSizeMB', ''),
                        'max_data_size': entry.get('content', {}).get('maxDataSize', ''),
                        'max_hot_buckets': entry.get('content', {}).get('maxHotBuckets', ''),
                        'max_warm_db_count': entry.get('content', {}).get('maxWarmDBCount', ''),
                        'max_total_data_size_mb': entry.get('content', {}).get('maxTotalDataSizeMB', ''),
                        'home_path': entry.get('content', {}).get('homePath', ''),
                        'cold_path': entry.get('content', {}).get('coldPath', ''),
                        'thawed_path': entry.get('content', {}).get('thawedPath', ''),
                        'bloom_filter_total_size_kb': entry.get('content', {}).get('bloomfilterTotalSizeKB', ''),
                        'bucket_rebuild_memory_hint': entry.get('content', {}).get('bucketRebuildMemoryHint', ''),
                        'compress_rawdata': entry.get('content', {}).get('compressRawdata', ''),
                        'enable_real_time_search': entry.get('content', {}).get('enableRealtimeSearch', ''),
                        'frozen_time_period_in_secs': entry.get('content', {}).get('frozenTimePeriodInSecs', ''),
                        'max_concurrent_optimizes': entry.get('content', {}).get('maxConcurrentOptimizes', ''),
                        'max_data_size_mb': entry.get('content', {}).get('maxDataSizeMB', ''),
                        'max_hot_idle_secs': entry.get('content', {}).get('maxHotIdleSecs', ''),
                        'max_hot_span_secs': entry.get('content', {}).get('maxHotSpanSecs', ''),
                        'max_mem_mb': entry.get('content', {}).get('maxMemMB', ''),
                        'max_meta_entries': entry.get('content', {}).get('maxMetaEntries', ''),
                        'max_time_unreplicated_no_acks': entry.get('content', {}).get('maxTimeUnreplicatedNoAcks', ''),
                        'max_time_unreplicated_with_acks': entry.get('content', {}).get('maxTimeUnreplicatedWithAcks', ''),
                        'min_raw_file_sync_secs': entry.get('content', {}).get('minRawFileSyncSecs', ''),
                        'min_stream_group_queue_size': entry.get('content', {}).get('minStreamGroupQueueSize', ''),
                        'partial_service_meta_period': entry.get('content', {}).get('partialServiceMetaPeriod', ''),
                        'quarantine_future_secs': entry.get('content', {}).get('quarantineFutureSecs', ''),
                        'quarantine_past_secs': entry.get('content', {}).get('quarantinePastSecs', ''),
                        'raw_chunk_size_bytes': entry.get('content', {}).get('rawChunkSizeBytes', ''),
                        'replication_factor': entry.get('content', {}).get('repFactor', ''),
                        'rotate_period_in_secs': entry.get('content', {}).get('rotatePeriodInSecs', ''),
                        'service_meta_period': entry.get('content', {}).get('serviceMetaPeriod', ''),
                        'sync_meta': entry.get('content', {}).get('syncMeta', ''),
                        'throttle_check_period': entry.get('content', {}).get('throttleCheckPeriod', ''),
                        'total_event_count': entry.get('content', {}).get('totalEventCount', ''),
                        'disabled': entry.get('content', {}).get('disabled', ''),
                        'is_internal': entry.get('content', {}).get('isInternal', ''),
                        'is_ready': entry.get('content', {}).get('isReady', ''),
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
                    indexes.append(index_data)
            
            print(f"Found {len(indexes)} indexes")
            return indexes
            
        except Exception as e:
            print(f"Error fetching indexes: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_apps(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk apps.
        
        Returns:
            List of dictionaries containing app information
        """
        try:
            print("Fetching Splunk apps...")
            
            # Use the service.get() method to access the apps/local endpoint
            response = self.service.get('apps/local', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            apps = []
            if 'entry' in data:
                for entry in data['entry']:
                    app_data = {
                        'name': entry.get('name', ''),
                        'label': entry.get('content', {}).get('label', ''),
                        'description': entry.get('content', {}).get('description', ''),
                        'version': entry.get('content', {}).get('version', ''),
                        'author': entry.get('content', {}).get('author', ''),
                        'disabled': entry.get('content', {}).get('disabled', ''),
                        'visible': entry.get('content', {}).get('visible', ''),
                        'configured': entry.get('content', {}).get('configured', ''),
                        'state_change_requires_restart': entry.get('content', {}).get('stateChangeRequiresRestart', ''),
                        'check_for_updates': entry.get('content', {}).get('check_for_updates', ''),
                        'update_homepage': entry.get('content', {}).get('update.homepage', ''),
                        'update_checksum': entry.get('content', {}).get('update.checksum', ''),
                        'update_version': entry.get('content', {}).get('update.version', ''),
                        'install_source_checksum': entry.get('content', {}).get('install_source_checksum', ''),
                        'install_source_local_checksum': entry.get('content', {}).get('install_source_local_checksum', ''),
                        'managed_by_deployment_client': entry.get('content', {}).get('managedByDeploymentClient', ''),
                        'show_in_nav': entry.get('content', {}).get('show_in_nav', ''),
                        'source_location': entry.get('content', {}).get('sourceLocation', ''),
                        'template': entry.get('content', {}).get('template', ''),
                        'triggers_reload': entry.get('content', {}).get('triggers_reload', ''),
                        'refresh_period_secs': entry.get('content', {}).get('refresh.display.view', ''),
                        'ui_prefs_optimized': entry.get('content', {}).get('ui.is_prefs_optimized', ''),
                        'ui_is_visible': entry.get('content', {}).get('ui.is_visible', ''),
                        'ui_label': entry.get('content', {}).get('ui.label', ''),
                        'entry_author': entry.get('author', ''),
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', ''),
                        'links_alternate': entry.get('links', {}).get('alternate', ''),
                        'links_list': entry.get('links', {}).get('list', ''),
                        'links_edit': entry.get('links', {}).get('edit', ''),
                        'links_remove': entry.get('links', {}).get('remove', ''),
                        'links_disable': entry.get('links', {}).get('disable', ''),
                        'links_package': entry.get('links', {}).get('_package', ''),
                        'links_reload': entry.get('links', {}).get('_reload', '')
                    }
                    apps.append(app_data)
            
            print(f"Found {len(apps)} apps")
            return apps
            
        except Exception as e:
            print(f"Error fetching apps: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_dashboards(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk dashboards (views).
        
        Returns:
            List of dictionaries containing dashboard information
        """
        try:
            print("Fetching Splunk dashboards...")
            
            # Use the service.get() method to access the data/ui/views endpoint
            response = self.service.get('data/ui/views', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            dashboards = []
            if 'entry' in data:
                for entry in data['entry']:
                    dashboard_data = {
                        'name': entry.get('name', ''),
                        'label': entry.get('content', {}).get('label', ''),
                        'description': entry.get('content', {}).get('description', ''),
                        'version': entry.get('content', {}).get('version', ''),
                        'app': entry.get('acl', {}).get('app', ''),
                        'owner': entry.get('acl', {}).get('owner', ''),
                        'sharing': entry.get('acl', {}).get('sharing', ''),
                        'modifiable': entry.get('acl', {}).get('modifiable', ''),
                        'removable': entry.get('acl', {}).get('removable', ''),
                        'can_write': entry.get('acl', {}).get('can_write', ''),
                        'can_change_perms': entry.get('acl', {}).get('can_change_perms', ''),
                        'can_share_app': entry.get('acl', {}).get('can_share_app', ''),
                        'can_share_global': entry.get('acl', {}).get('can_share_global', ''),
                        'can_share_user': entry.get('acl', {}).get('can_share_user', ''),
                        'perms_read': ', '.join(entry.get('acl', {}).get('perms', {}).get('read', [])),
                        'perms_write': ', '.join(entry.get('acl', {}).get('perms', {}).get('write', [])),
                        'is_scheduled': entry.get('content', {}).get('isScheduled', ''),
                        'cron_schedule': entry.get('content', {}).get('cron_schedule', ''),
                        'schedule_priority': entry.get('content', {}).get('schedule_priority', ''),
                        'next_scheduled_time': entry.get('content', {}).get('next_scheduled_time', ''),
                        'dispatch_earliest_time': entry.get('content', {}).get('dispatch.earliest_time', ''),
                        'dispatch_latest_time': entry.get('content', {}).get('dispatch.latest_time', ''),
                        'dispatch_ttl': entry.get('content', {}).get('dispatch.ttl', ''),
                        'request_ui_dispatch_app': entry.get('content', {}).get('request.ui_dispatch_app', ''),
                        'request_ui_dispatch_view': entry.get('content', {}).get('request.ui_dispatch_view', ''),
                        'root_node': entry.get('content', {}).get('rootNode', ''),
                        'is_visible': entry.get('content', {}).get('isVisible', ''),
                        'display_view': entry.get('content', {}).get('displayView', ''),
                        'vsid': entry.get('content', {}).get('vsid', ''),
                        'entry_author': entry.get('author', ''),
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', ''),
                        'links_alternate': entry.get('links', {}).get('alternate', ''),
                        'links_list': entry.get('links', {}).get('list', ''),
                        'links_edit': entry.get('links', {}).get('edit', ''),
                        'links_remove': entry.get('links', {}).get('remove', ''),
                        'links_move': entry.get('links', {}).get('move', ''),
                        'links_reload': entry.get('links', {}).get('_reload', ''),
                        'links_acl': entry.get('links', {}).get('acl', '')
                    }
                    dashboards.append(dashboard_data)
            
            print(f"Found {len(dashboards)} dashboards")
            return dashboards
            
        except Exception as e:
            print(f"Error fetching dashboards: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_reports(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk reports (saved searches that are not alerts).
        
        Returns:
            List of dictionaries containing report information
        """
        try:
            print("Fetching Splunk reports...")
            
            # Use the service.get() method to access the saved/searches endpoint
            response = self.service.get('saved/searches', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            reports = []
            if 'entry' in data:
                for entry in data['entry']:
                    content = entry.get('content', {})
                    
                    # Check if this saved search is a report (not an alert)
                    # Reports are saved searches that are either:
                    # 1. Not scheduled, OR
                    # 2. Scheduled but don't have alert actions
                    is_scheduled = content.get('is_scheduled', '0') == '1'
                    has_actions = content.get('actions', '') != ''
                    has_action_fields = any(key.startswith('action.') for key in content.keys())
                    
                    is_alert = is_scheduled and (has_actions or has_action_fields)
                    is_report = not is_alert  # Reports are non-alerts
                    
                    # Only include entries that are reports
                    if is_report:
                        report_data = {
                            # Basic Information (8 columns)
                            'name': entry.get('name', ''),
                            'title': content.get('title', ''),
                            'description': content.get('description', ''),
                            'search': content.get('search', ''),
                            'app': entry.get('acl', {}).get('app', ''),
                            'owner': entry.get('acl', {}).get('owner', ''),
                            'sharing': entry.get('acl', {}).get('sharing', ''),
                            'disabled': content.get('disabled', ''),
                            
                            # Permissions (4 columns)
                            'can_write': entry.get('acl', {}).get('can_write', ''),
                            'can_share_app': entry.get('acl', {}).get('can_share_app', ''),
                            'perms_read': ', '.join(entry.get('acl', {}).get('perms', {}).get('read', [])),
                            'perms_write': ', '.join(entry.get('acl', {}).get('perms', {}).get('write', [])),
                            
                            # Scheduling (6 columns)
                            'is_scheduled': content.get('is_scheduled', ''),
                            'cron_schedule': content.get('cron_schedule', ''),
                            'next_scheduled_time': content.get('next_scheduled_time', ''),
                            'dispatch_earliest_time': content.get('dispatch.earliest_time', ''),
                            'dispatch_latest_time': content.get('dispatch.latest_time', ''),
                            'dispatch_ttl': content.get('dispatch.ttl', ''),
                            
                            # Performance & Limits (4 columns)
                            'dispatch_max_count': content.get('dispatch.max_count', ''),
                            'dispatch_max_time': content.get('dispatch.max_time', ''),
                            'max_concurrent': content.get('max_concurrent', ''),
                            'workload_pool': content.get('workload_pool', ''),
                            
                            # UI & Visibility (3 columns)
                            'is_visible': content.get('is_visible', ''),
                            'embed_enabled': content.get('embed.enabled', ''),
                            'vsid': content.get('vsid', ''),
                            
                            # Auto-summarization (2 columns)
                            'auto_summarize': content.get('auto_summarize', ''),
                            'auto_summarize_cron_schedule': content.get('auto_summarize.cron_schedule', ''),
                            
                            # Metadata (3 columns)
                            'updated': entry.get('updated', ''),
                            'published': entry.get('published', ''),
                            'id': entry.get('id', '')
                        }
                        reports.append(report_data)
            
            print(f"Found {len(reports)} reports")
            return reports
            
        except Exception as e:
            print(f"Error fetching reports: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_license_usage(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk license usage.
        
        Returns:
            List of dictionaries containing license usage information
        """
        try:
            print("Fetching Splunk license usage...")
            
            # Use the service.get() method to access the licenser/usage endpoint
            response = self.service.get('licenser/usage', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            license_usage = []
            if 'entry' in data:
                for entry in data['entry']:
                    content = entry.get('content', {})
                    usage_data = {
                        # Basic Information (5 columns)
                        'name': entry.get('name', ''),
                        'pool_name': content.get('pool_name', ''),
                        'stack_name': content.get('stack_name', ''),
                        'type': content.get('type', ''),
                        'slave_id': content.get('slave_id', ''),
                        
                        # License Limits (5 columns)
                        'quota': content.get('quota', ''),
                        'quota_bytes': content.get('quota_bytes', ''),
                        'used': content.get('used', ''),
                        'used_bytes': content.get('used_bytes', ''),
                        'used_pct': content.get('used_pct', ''),
                        
                        # Time Information (4 columns)
                        'window_period': content.get('window_period', ''),
                        'earliest_time': content.get('earliest_time', ''),
                        'latest_time': content.get('latest_time', ''),
                        'last_reset_time': content.get('last_reset_time', ''),
                        
                        # Status & Warnings (4 columns)
                        'is_pooled': content.get('is_pooled', ''),
                        'warning_count': content.get('warning_count', ''),
                        'violation_count': content.get('violation_count', ''),
                        'status': content.get('status', ''),
                        
                        # Volume Details (4 columns)
                        'average_usage': content.get('average_usage', ''),
                        'max_usage': content.get('max_usage', ''),
                        'volume_used': content.get('volume_used', ''),
                        'volume_quota': content.get('volume_quota', ''),
                        
                        # Features (3 columns)
                        'feature_name': content.get('feature_name', ''),
                        'feature_used': content.get('feature_used', ''),
                        'feature_quota': content.get('feature_quota', ''),
                        
                        # Metadata (5 columns)
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', ''),
                        'author': entry.get('author', ''),
                        'links_list': entry.get('links', {}).get('list', '')
                    }
                    license_usage.append(usage_data)
            
            print(f"Found {len(license_usage)} license usage entries")
            return license_usage
            
        except Exception as e:
            print(f"Error fetching license usage: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_user_logins(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk user logins from audit logs.
        
        Returns:
            List of dictionaries containing user login information
        """
        try:
            print("Fetching Splunk user login activity...")
            
            # First, let's check if the _audit index exists and has any data
            print("Step 1: Checking _audit index availability...")
            basic_audit_query = 'search index=_audit | head 10'
            
            # Execute basic audit check
            basic_job = self.service.jobs.create(basic_audit_query)
            while not basic_job.is_done():
                time.sleep(0.5)
            
            basic_results_stream = basic_job.results(output_mode='json')
            basic_results_data = basic_results_stream.read()
            if isinstance(basic_results_data, bytes):
                basic_results_data = basic_results_data.decode('utf-8')
            
            import json
            basic_parsed_results = json.loads(basic_results_data)
            basic_results_list = basic_parsed_results.get('results', [])
            
            print(f"Found {len(basic_results_list)} audit events in _audit index")
            
            if len(basic_results_list) == 0:
                print("WARNING: No audit events found in _audit index. This could mean:")
                print("  1. Audit logging is not enabled")
                print("  2. The _audit index doesn't exist")
                print("  3. You don't have permissions to read the _audit index")
                print("  4. No audit events have been generated yet")
                return []
            
            # Step 2: Check for login events specifically
            print("Step 2: Checking for login events...")
            login_check_query = 'search index=_audit action=login | head 10'
            
            login_job = self.service.jobs.create(login_check_query)
            while not login_job.is_done():
                time.sleep(0.5)
            
            login_results_stream = login_job.results(output_mode='json')
            login_results_data = login_results_stream.read()
            if isinstance(login_results_data, bytes):
                login_results_data = login_results_data.decode('utf-8')
            
            login_parsed_results = json.loads(login_results_data)
            login_results_list = login_parsed_results.get('results', [])
            
            print(f"Found {len(login_results_list)} login events in _audit index")
            
            if len(login_results_list) == 0:
                print("WARNING: No login events found. Trying alternative search...")
                # Try alternative search patterns
                alt_queries = [
                    'search index=_audit "login" | head 10',
                    'search index=_audit action="login" | head 10',
                    'search index=_audit sourcetype=audittrail action=login | head 10'
                ]
                
                for i, alt_query in enumerate(alt_queries):
                    print(f"  Trying alternative query {i+1}: {alt_query}")
                    alt_job = self.service.jobs.create(alt_query)
                    while not alt_job.is_done():
                        time.sleep(0.5)
                    
                    alt_results_stream = alt_job.results(output_mode='json')
                    alt_results_data = alt_results_stream.read()
                    if isinstance(alt_results_data, bytes):
                        alt_results_data = alt_results_data.decode('utf-8')
                    
                    alt_parsed_results = json.loads(alt_results_data)
                    alt_results_list = alt_parsed_results.get('results', [])
                    
                    print(f"  Alternative query {i+1} found {len(alt_results_list)} results")
                    if len(alt_results_list) > 0:
                        break
                
                if len(alt_results_list) == 0:
                    print("No login events found with any search pattern.")
                    return []
            
            # Step 3: Run the main aggregation query
            print("Step 3: Running main aggregation query...")
            # Search for authentication events in the audit index
            search_query = '''
            search index=_audit action=login 
            | eval login_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
            | stats 
                count as login_count,
                min(_time) as first_login_time,
                max(_time) as last_login_time,
                values(info) as login_info,
                values(clientip) as client_ips,
                values(host) as splunk_hosts,
                values(method) as auth_methods,
                dc(clientip) as unique_ip_count,
                dc(host) as unique_host_count
            by user
            | eval 
                first_login=strftime(first_login_time, "%Y-%m-%d %H:%M:%S"),
                last_login=strftime(last_login_time, "%Y-%m-%d %H:%M:%S"),
                days_active=round((last_login_time - first_login_time) / 86400, 1)
            | sort - last_login_time
            '''
            
            # Execute the search
            job = self.service.jobs.create(search_query)
            
            # Wait for the job to complete
            while not job.is_done():
                time.sleep(0.5)
            
            # Get the results - need to read and parse the JSON response
            results_stream = job.results(output_mode='json')
            
            # Read the entire response and parse as JSON
            results_data = results_stream.read()
            if isinstance(results_data, bytes):
                results_data = results_data.decode('utf-8')
            
            # Parse JSON response
            import json
            parsed_results = json.loads(results_data)
            
            user_logins = []
            # Extract results from the parsed JSON structure
            if 'results' in parsed_results:
                results_list = parsed_results['results']
            else:
                results_list = parsed_results if isinstance(parsed_results, list) else []
            
            for result in results_list:
                # Handle potential missing fields gracefully
                login_data = {
                    'user': result.get('user', ''),
                    'login_count': result.get('login_count', '0'),
                    'first_login': result.get('first_login', ''),
                    'last_login': result.get('last_login', ''),
                    'days_active': result.get('days_active', '0'),
                    'unique_ip_count': result.get('unique_ip_count', '0'),
                    'unique_host_count': result.get('unique_host_count', '0'),
                    'client_ips': result.get('client_ips', ''),
                    'splunk_hosts': result.get('splunk_hosts', ''),
                    'auth_methods': result.get('auth_methods', ''),
                    'login_info': result.get('login_info', ''),
                    # Additional fields for context
                    'avg_logins_per_day': str(round(float(result.get('login_count', '0')) / max(float(result.get('days_active', '1')), 1), 2)),
                    'is_recent_user': 'Yes' if result.get('last_login_time', '0') and (time.time() - float(result.get('last_login_time', '0'))) < 604800 else 'No',  # 7 days
                    'is_frequent_user': 'Yes' if int(result.get('login_count', '0')) >= 10 else 'No',
                    'multi_ip_user': 'Yes' if int(result.get('unique_ip_count', '0')) > 1 else 'No',
                    'multi_host_user': 'Yes' if int(result.get('unique_host_count', '0')) > 1 else 'No'
                }
                
                user_logins.append(login_data)
            
            print(f"Found {len(user_logins)} users with login activity")
            return user_logins
            
        except Exception as e:
            print(f"Error fetching user logins: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_addons(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk add-ons (apps that provide data inputs).
        
        Returns:
            List of dictionaries containing add-on information
        """
        try:
            print("Fetching Splunk add-ons...")
            
            # Use the service.get() method to access the apps/local endpoint
            response = self.service.get('apps/local', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            addons = []
            if 'entry' in data:
                for entry in data['entry']:
                    content = entry.get('content', {})
                    
                    # Filter for add-ons (apps that are typically add-ons have certain characteristics)
                    # Add-ons usually:
                    # 1. Have "TA-" or "Splunk_TA_" prefix in name
                    # 2. Are not visible in navigation
                    # 3. Provide data inputs or technology add-ons
                    app_name = entry.get('name', '')
                    is_addon = (
                        app_name.startswith('TA-') or 
                        app_name.startswith('Splunk_TA_') or
                        app_name.startswith('DA-') or
                        'addon' in app_name.lower() or
                        'add-on' in content.get('label', '').lower() or
                        'technology add-on' in content.get('description', '').lower()
                    )
                    
                    # Only include actual add-ons, skip regular apps
                    if not is_addon:
                        continue
                    
                    addon_data = {
                        # Basic Information (7 columns) - removed is_addon since all are add-ons now
                        'name': app_name,
                        'label': content.get('label', ''),
                        'description': content.get('description', ''),
                        'version': content.get('version', ''),
                        'author': content.get('author', ''),
                        'disabled': content.get('disabled', ''),
                        'visible': content.get('visible', ''),
                        
                        # Configuration & Status (6 columns)
                        'configured': content.get('configured', ''),
                        'state_change_requires_restart': content.get('stateChangeRequiresRestart', ''),
                        'managed_by_deployment_client': content.get('managedByDeploymentClient', ''),
                        'show_in_nav': content.get('show_in_nav', ''),
                        'source_location': content.get('sourceLocation', ''),
                        'template': content.get('template', ''),
                        
                        # Update Information (4 columns)
                        'check_for_updates': content.get('check_for_updates', ''),
                        'update_homepage': content.get('update.homepage', ''),
                        'update_version': content.get('update.version', ''),
                        'update_checksum': content.get('update.checksum', ''),
                        
                        # Installation Details (4 columns)
                        'install_source_checksum': content.get('install_source_checksum', ''),
                        'install_source_local_checksum': content.get('install_source_local_checksum', ''),
                        'triggers_reload': content.get('triggers_reload', ''),
                        'refresh_period_secs': content.get('refresh.display.view', ''),
                        
                        # UI Settings (4 columns)
                        'ui_prefs_optimized': content.get('ui.is_prefs_optimized', ''),
                        'ui_is_visible': content.get('ui.is_visible', ''),
                        'ui_label': content.get('ui.label', ''),
                        'entry_author': entry.get('author', ''),
                        
                        # Metadata (5 columns) - added addon_type to reach 30 columns
                        'addon_type': 'Technology Add-on' if app_name.startswith(('TA-', 'Splunk_TA_')) else 'Data Add-on' if app_name.startswith('DA-') else 'Other Add-on',
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', ''),
                        'links_package': entry.get('links', {}).get('_package', '')
                    }
                    addons.append(addon_data)
            
            # Sort by addon type, then by name
            addons.sort(key=lambda x: (x['addon_type'], x['name']))
            
            print(f"Found {len(addons)} add-ons total")
            tech_addons = len([a for a in addons if a['addon_type'] == 'Technology Add-on'])
            data_addons = len([a for a in addons if a['addon_type'] == 'Data Add-on'])
            other_addons = len([a for a in addons if a['addon_type'] == 'Other Add-on'])
            
            print(f"  - {tech_addons} Technology Add-ons")
            print(f"  - {data_addons} Data Add-ons") 
            print(f"  - {other_addons} Other Add-ons")
            return addons
            
        except Exception as e:
            print(f"Error fetching add-ons: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_formatted_inputs(self) -> List[Dict[str, Any]]:
        """
        Get formatted list of Splunk data inputs.
        
        Returns:
            List of dictionaries containing input information
        """
        try:
            print("Fetching Splunk data inputs...")
            
            # Use the service.get() method to access the data/inputs endpoint
            response = self.service.get('data/inputs', output_mode='json')
            
            if response.status != 200:
                raise Exception(f"HTTP {response.status}: {response.reason}")
                
            # Parse the JSON response
            data = json.loads(response.body.read().decode('utf-8'))
            
            inputs = []
            if 'entry' in data:
                for entry in data['entry']:
                    content = entry.get('content', {})
                    
                    # Parse the input name to extract type and details
                    input_name = entry.get('name', '')
                    input_type = input_name.split('://')[0] if '://' in input_name else 'unknown'
                    input_path = input_name.split('://', 1)[1] if '://' in input_name else input_name
                    
                    input_data = {
                        # Basic Information (8 columns)
                        'name': input_name,
                        'type': input_type,
                        'path': input_path,
                        'title': content.get('title', ''),
                        'description': content.get('description', ''),
                        'disabled': content.get('disabled', ''),
                        'host': content.get('host', ''),
                        'index': content.get('index', ''),
                        
                        # Source Configuration (6 columns)
                        'source': content.get('source', ''),
                        'sourcetype': content.get('sourcetype', ''),
                        'source_host': content.get('_rcvr', ''),
                        'check_index': content.get('check-index', ''),
                        'check_path': content.get('check-path', ''),
                        'move_policy': content.get('move_policy', ''),
                        
                        # Monitoring Settings (5 columns)
                        'recursive': content.get('recursive', ''),
                        'followTail': content.get('followTail', ''),
                        'ignoreOlderThan': content.get('ignoreOlderThan', ''),
                        'whitelist': content.get('whitelist', ''),
                        'blacklist': content.get('blacklist', ''),
                        
                        # Processing Settings (5 columns)
                        'crcSalt': content.get('crcSalt', ''),
                        'initCrcLength': content.get('initCrcLength', ''),
                        'time_before_close': content.get('time-before-close', ''),
                        'multiline_event_extra_waittime': content.get('multiline-event-extra-waittime', ''),
                        'persistent_queue_size': content.get('persistent-queue-size', ''),
                        
                        # Network/Protocol Settings (3 columns) - for network inputs
                        'connection_host': content.get('connection_host', ''),
                        'restrictToHost': content.get('restrictToHost', ''),
                        'acceptFrom': content.get('acceptFrom', ''),
                        
                        # Metadata (3 columns)
                        'updated': entry.get('updated', ''),
                        'published': entry.get('published', ''),
                        'id': entry.get('id', '')
                    }
                    inputs.append(input_data)
            
            # Sort by input type, then by name
            inputs.sort(key=lambda x: (x['type'], x['name']))
            
            print(f"Found {len(inputs)} data inputs total")
            
            # Count by input type
            input_types = {}
            for inp in inputs:
                inp_type = inp['type']
                input_types[inp_type] = input_types.get(inp_type, 0) + 1
            
            for inp_type, count in sorted(input_types.items()):
                print(f"  - {count} {inp_type} inputs")
            
            return inputs
            
        except Exception as e:
            print(f"Error fetching inputs: {str(e)}")
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
                    # Use filename as S3 key to ensure consistent overwriting on subsequent runs
                    s3_key = filename
                    
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
    
    s3_line = f"  S3 Bucket:     {s3_bucket} ({s3_status})"
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
    """Delete existing CSV files from previous runs to ensure fresh data."""
    # List of all possible CSV files that might be generated
    csv_files = [
        # Config category
        'splunk_config_users.csv',
        'splunk_config_indexes.csv',
        'splunk_config_roles.csv',
        'splunk_config_addons.csv',
        'splunk_config_inputs.csv',
        # Content category
        'splunk_content_apps.csv',
        'splunk_content_dashboards.csv',
        'splunk_content_reports.csv',
        'splunk_content_detection_rules.csv',
        'splunk_content_analytic_stories.csv',
        'splunk_content_playbook_responses.csv',
        # Usage category
        'splunk_usage_license.csv',
        'splunk_usage_index_volumes.csv',
        'splunk_usage_sourcetype_volumes.csv',
        'splunk_usage_user_logins.csv'
    ]
    
    removed_count = 0
    for csv_file in csv_files:
        try:
            if os.path.exists(csv_file):
                os.remove(csv_file)
                print(f"Removed existing file: {csv_file}")
                removed_count += 1
        except Exception as e:
            print(f"Warning: Could not remove {csv_file}: {str(e)}")
    
    if removed_count == 0:
        print("No existing CSV files found to clean up.")
    else:
        print(f"Cleaned up {removed_count} existing CSV file(s).")

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
            "name": "splunk_config_indexes",
            "getter": splunk_client.get_formatted_indexes,
            "category": "config"
        },
        {
            "name": "splunk_content_apps",
            "getter": splunk_client.get_formatted_apps,
            "category": "content"
        },
        {
            "name": "splunk_content_dashboards",
            "getter": splunk_client.get_formatted_dashboards,
            "category": "content"
        },
        {
            "name": "splunk_content_reports",
            "getter": splunk_client.get_formatted_reports,
            "category": "content"
        },

        {
            "name": "splunk_usage_license",
            "getter": splunk_client.get_formatted_license_usage,
            "category": "usage"
        },
        {
            "name": "splunk_usage_user_logins",
            "getter": splunk_client.get_formatted_user_logins,
            "category": "usage"
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

        ## TODO - Implement these methods in SplunkAPIClient class
        # {
        #     "name": "splunk_config_roles",
        #     "getter": splunk_client.get_formatted_roles,
        #     "category": "config"
        # },
        # {
        #     "name": "splunk_content_alerts",
        #     "getter": splunk_client.get_formatted_alerts,
        #     "category": "content"
        # },
        # {
        #     "name": "splunk_content_reports",
        #     "getter": splunk_client.get_formatted_reports,
        #     "category": "content"
        # },
        # {
        #     "name": "splunk_content_detection_rules",
        #     "getter": splunk_client.get_formatted_detection_rules,
        #     "category": "content"
        # },
        # {
        #     "name": "splunk_content_analytic_stories",
        #     "getter": splunk_client.get_formatted_analytic_stories,
        #     "category": "content"
        # },
        # {
        #     "name": "splunk_content_playbook_responses",
        #     "getter": splunk_client.get_formatted_playbook_responses,
        #     "category": "content"
        # },
        # {
        #     "name": "splunk_usage_index_volumes",
        #     "getter": lambda: splunk_client.get_formatted_index_usage(days=30),
        #     "category": "usage"
        # },
        # {
        #     "name": "splunk_usage_sourcetype_volumes",
        #     "getter": lambda: splunk_client.get_formatted_sourcetype_usage(days=30),
        #     "category": "usage"
        # },
        # {
        #     "name": "splunk_usage_user_logins",
        #     "getter": lambda: splunk_client.get_formatted_user_logins(days=30),
        #     "category": "usage"
        # }
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
    
    # Clean up existing CSVs to ensure fresh data on each run
    print("\nCleaning up existing CSV files...")
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