class SplunkAPIClient:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """Initialize Splunk API client with connection details."""
        # Try environment variables first, then use provided values or prompt
        self.host = os.environ.get("DD_AIRLIFT_SPLK_HOST") or host or input("Enter Splunk host: ").strip()
        self.port = int(os.environ.get("DD_AIRLIFT_SPLK_PORT") or port or input("Enter Splunk port [8089]: ").strip() or "8089")
        self.username = os.environ.get("DD_AIRLIFT_SPLK_USERNAME") or username or input("Enter Splunk username: ").strip()
        self.password = os.environ.get("DD_AIRLIFT_SPLK_PASSWORD") or password or input("Enter Splunk password: ").strip()
        
        if not all([self.host, self.username, self.password]):
            print("Error: Required connection details not provided:", file=sys.stderr)
            if not self.host:
                print("  - Host", file=sys.stderr)
            if not self.username:
                print("  - Username", file=sys.stderr)
            if not self.password:
                print("  - Password", file=sys.stderr)
            sys.exit(1)
            
        self.service = None
        self._connect()

    def _connect(self):
        """Establish connection to Splunk instance."""
        try:
            self.service = connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                scheme="https"
            )
            print(f"Successfully connected to Splunk instance at {self.host}:{self.port}")
        except Exception as e:
            print(f"Error connecting to Splunk: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_apps(self) -> List[Dict[str, Any]]:
        """Get list of installed apps."""
        try:
            apps = []
            for app in self.service.apps:
                content = app.content
                app_info = {
                    "name": app.name,
                    "label": content.get("label", ""),
                    "version": content.get("version", ""),
                    "description": content.get("description", ""),
                    "author": content.get("author", ""),
                    "is_visible": content.get("visible", True),
                    "check_for_updates": content.get("check_for_updates", False),
                    "state": content.get("state", "")
                }
                apps.append(app_info)
            return {"entry": apps}
        except Exception as e:
            print(f"Error getting apps: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_saved_searches(self) -> Dict[str, Any]:
        """Get list of saved searches, excluding reports."""
        try:
            searches = []
            for saved_search in self.service.saved_searches:
                try:
                    # Get the content dictionary which contains all properties
                    content = saved_search.content
                    
                    # Skip if this is a report
                    if any([
                        content.get("is_report", False),  # Explicitly marked as report
                        content.get("report_type"),       # Has report type
                        "report" in content.get("search", "").lower(),  # Search contains "report"
                        content.get("display.general.type") == "report",  # Display type is report
                        content.get("display.general.type") == "dashboard",  # Display type is dashboard
                        content.get("display.general.type") == "visualization"  # Display type is visualization
                    ]):
                        continue
                    
                    search_info = {
                        "name": saved_search.name,
                        "search": content.get("search", ""),
                        "description": content.get("description", ""),
                        "is_scheduled": content.get("is_scheduled", False),
                        "is_visible": content.get("is_visible", False),
                        "app": content.get("app", ""),
                        "owner": content.get("owner", ""),
                        "creator": content.get("creator", ""),
                        "created": content.get("created", ""),
                        "modified": content.get("modified", ""),
                        "cron_schedule": content.get("cron_schedule", ""),
                        "next_scheduled_time": content.get("next_scheduled_time", ""),
                        "is_alert": content.get("is_alert", False),
                        "alert_type": content.get("alert_type", ""),
                        "alert_condition": content.get("alert_condition", ""),
                        "disabled": content.get("disabled", False)
                    }
                    searches.append(search_info)
                except Exception as e:
                    print(f"Warning: Could not process saved search {saved_search.name}: {str(e)}")
                    continue
            
            print(f"\nFound {len(searches)} saved searches (excluding reports)")
            return {"entry": searches}
        except Exception as e:
            print(f"Error getting saved searches: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_detection_rules(self) -> List[Dict[str, Any]]:
        """Get list of detection rules."""
        try:
            rules = []
            # Get installed apps to check for ES and Security Essentials
            installed_apps = [app.name for app in self.service.apps]
            print(f"Installed apps: {', '.join(installed_apps)}")
            
            es_installed = "SplunkEnterpriseSecuritySuite" in installed_apps
            security_essentials_installed = "SplunkSecurityEssentials" in installed_apps
            print(f"Enterprise Security app installed: {es_installed}")
            print(f"Security Essentials app installed: {security_essentials_installed}")

            # Define endpoints to try
            endpoints = ["search"]  # Always try search app
            if es_installed:
                endpoints.append("SplunkEnterpriseSecuritySuite")
            if security_essentials_installed:
                endpoints.append("SplunkSecurityEssentials")

            # Define search patterns
            search_patterns = [
                "title=* - Rule",
                "search_type=detection",
                "search_type=correlation",
                "is_alert=1"
            ]
            if es_installed:
                search_patterns.append("app=SplunkEnterpriseSecuritySuite")

            # Try each endpoint and pattern combination
            for endpoint in endpoints:
                print(f"Trying endpoint: /servicesNS/{self.username}/{endpoint}/saved/searches")
                for pattern in search_patterns:
                    print(f"Trying search pattern: {pattern}")
                    try:
                        saved_searches = self.service.saved_searches.list(
                            app=endpoint,
                            search=pattern,
                            count=0
                        )
                        print(f"Found {len(saved_searches)} entries with pattern: {pattern}")
                        
                        for search in saved_searches:
                            rule_info = {
                                "name": search.name,
                                "search": search["search"],
                                "description": search["description"],
                                "app": search["app"],
                                "owner": search["owner"],
                                "type": "detection_rule"
                            }
                            rules.append(rule_info)
                    except HTTPError as e:
                        print(f"Warning: Error accessing {endpoint} with pattern {pattern}: {str(e)}")
                        continue

            return rules
        except Exception as e:
            print(f"Error getting detection rules: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_dashboards(self) -> Dict[str, Any]:
        """Get list of dashboards."""
        try:
            # Use a set to track unique dashboards
            seen_dashboards = set()
            dashboards = []
            
            # First get all apps
            apps = self.service.apps.list()
            print(f"\nFound {len(apps)} total apps")
            
            # Create a set of app names for quick lookup
            app_names = {app.name for app in apps if app.name}
            print(f"App names: {', '.join(sorted(app_names))}")
            
            # Filter out add-ons (TA, SA, DA)
            non_addon_apps = []
            for app in apps:
                app_name = app.name
                if not app_name:
                    continue
                    
                # Skip if it's an add-on
                if any([
                    app_name.startswith("TA-"),  # Technical Add-on
                    app_name.startswith("SA-"),  # Supporting Add-on
                    app_name.startswith("DA-"),  # Data Add-on
                    "addon" in app_name.lower(),
                    app.content.get("is_addon", False),
                    "add-on" in app.content.get("description", "").lower()
                ]):
                    print(f"Skipping add-on: {app_name}")
                    continue
                    
                non_addon_apps.append(app)
            
            print(f"Found {len(non_addon_apps)} non-addon apps")
            
            # First process dashboards in apps
            for app in non_addon_apps:
                try:
                    app_name = app.name
                    if not app_name:
                        continue
                        
                    # Get app properties
                    app_props = app.content
                    
                    # Skip disabled apps
                    if not app_props.get("visible", True):
                        print(f"Skipping disabled app: {app_name}")
                        continue
                        
                    print(f"\nProcessing app: {app_name}")
                    
                    # Try different endpoints to find dashboards
                    endpoints = [
                        f"/servicesNS/{self.username}/{app_name}/data/ui/views",
                        f"/servicesNS/{self.username}/{app_name}/data/ui/nav",
                        f"/servicesNS/{self.username}/{app_name}/data/ui/panels"
                    ]
                    
                    for endpoint in endpoints:
                        try:
                            print(f"Trying endpoint: {endpoint}")
                            
                            # Get the response using the SDK's get method with JSON output
                            try:
                                response = self.service.get(
                                    endpoint,
                                    count=0,
                                    output_mode='json'  # Explicitly request JSON format
                                )
                                # Parse the JSON response
                                response_text = response.body.read().decode('utf-8')
                                response_dict = json.loads(response_text)
                            except Exception as e:
                                print(f"Warning: Could not get response from {endpoint}: {str(e)}")
                                continue
                            
                            # Parse the views from the response
                            entries = response_dict.get("entry", [])
                            print(f"Found {len(entries)} entries in {endpoint}")
                            
                            for entry in entries:
                                try:
                                    entry_name = entry.get("name")
                                    entry_content = entry.get("content", {})
                                    
                                    # Skip if not a dashboard
                                    if not any([
                                        entry_content.get("isDashboard", False),
                                        entry_content.get("type") == "dashboard",
                                        "dashboard" in entry_content.get("type", "").lower(),
                                        entry_content.get("display.general.type") == "dashboard"
                                    ]):
                                        print(f"Skipping {entry_name} - not a dashboard")
                                        continue
                                    
                                    # Create a unique key for this dashboard
                                    dashboard_key = f"{app_name}:{entry_name}"
                                    
                                    # Skip if we've already seen this dashboard
                                    if dashboard_key in seen_dashboards:
                                        print(f"Skipping duplicate dashboard: {entry_name} in app {app_name}")
                                        continue
                                    
                                    # Add to seen set
                                    seen_dashboards.add(dashboard_key)
                                    
                                    dashboard_info = {
                                        "name": entry_name,
                                        "label": entry_content.get("label", ""),
                                        "description": entry_content.get("description", ""),
                                        "app": app_name,  # Always use the current app name
                                        "owner": entry_content.get("owner", ""),
                                        "creator": entry_content.get("creator", ""),
                                        "created": entry_content.get("created", ""),
                                        "modified": entry_content.get("modified", ""),
                                        "is_visible": entry_content.get("is_visible", True),
                                        "version": entry_content.get("version", ""),
                                        "display_type": "dashboard",
                                        "disabled": entry_content.get("disabled", False)
                                    }
                                    dashboards.append(dashboard_info)
                                    print(f"Found dashboard: {entry_name} in app {app_name}")
                                except Exception as e:
                                    print(f"Warning: Could not process entry {entry_name} in app {app_name}: {str(e)}")
                                    continue
                                    
                        except Exception as e:
                            print(f"Warning: Could not access {endpoint} for app {app_name}: {str(e)}")
                            continue
                            
                except Exception as e:
                    print(f"Warning: Could not process app {app_name}: {str(e)}")
                    continue
            
            # Now look for dashboards that aren't part of an app
            print("\nLooking for dashboards not part of an app...")
            try:
                # Try the search app first
                endpoint = f"/servicesNS/{self.username}/search/data/ui/views"
                response = self.service.get(
                    endpoint,
                    count=0,
                    output_mode='json'
                )
                response_text = response.body.read().decode('utf-8')
                response_dict = json.loads(response_text)
                
                entries = response_dict.get("entry", [])
                print(f"Found {len(entries)} entries in search app")
                
                for entry in entries:
                    try:
                        entry_name = entry.get("name")
                        entry_content = entry.get("content", {})
                        
                        # Skip if not a dashboard
                        if not any([
                            entry_content.get("isDashboard", False),
                            entry_content.get("type") == "dashboard",
                            "dashboard" in entry_content.get("type", "").lower(),
                            entry_content.get("display.general.type") == "dashboard"
                        ]):
                            continue
                        
                        # Skip if we've already seen this dashboard
                        dashboard_key = f"search:{entry_name}"
                        if dashboard_key in seen_dashboards:
                            continue
                        
                        # Add to seen set
                        seen_dashboards.add(dashboard_key)
                        
                        dashboard_info = {
                            "name": entry_name,
                            "label": entry_content.get("label", ""),
                            "description": entry_content.get("description", ""),
                            "app": "search",  # These are in the search app
                            "owner": entry_content.get("owner", ""),
                            "creator": entry_content.get("creator", ""),
                            "created": entry_content.get("created", ""),
                            "modified": entry_content.get("modified", ""),
                            "is_visible": entry_content.get("is_visible", True),
                            "version": entry_content.get("version", ""),
                            "display_type": "dashboard",
                            "disabled": entry_content.get("disabled", False)
                        }
                        dashboards.append(dashboard_info)
                        print(f"Found standalone dashboard: {entry_name}")
                    except Exception as e:
                        print(f"Warning: Could not process standalone dashboard {entry_name}: {str(e)}")
                        continue
                        
            except Exception as e:
                print(f"Warning: Could not access standalone dashboards: {str(e)}")
            
            print(f"\nFound {len(dashboards)} total dashboards")
            return {"entry": dashboards}
        except Exception as e:
            print(f"Error getting dashboards: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get list of alerts."""
        try:
            alerts = []
            for saved_search in self.service.saved_searches:
                if saved_search["is_scheduled"]:
                    alert_info = {
                        "name": saved_search.name,
                        "search": saved_search["search"],
                        "description": saved_search["description"],
                        "schedule": saved_search["schedule"],
                        "app": saved_search["app"],
                        "owner": saved_search["owner"]
                    }
                    alerts.append(alert_info)
            return alerts
        except Exception as e:
            print(f"Error getting alerts: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_reports(self) -> Dict[str, Any]:
        """Get all reports as shown in the Splunk UI reports page."""
        try:
            reports = []
            for saved_search in self.service.saved_searches:
                try:
                    content = saved_search.content
                    
                    # Check if this is a report
                    is_report = any([
                        content.get("is_report", False),  # Explicitly marked as report
                        content.get("report_type"),       # Has report type
                        "report" in content.get("search", "").lower(),  # Search contains "report"
                        content.get("display.general.type") == "report",  # Display type is report
                        content.get("display.general.type") == "dashboard",  # Display type is dashboard
                        content.get("display.general.type") == "visualization"  # Display type is visualization
                    ])
                    
                    if not is_report:
                        continue
                    
                    # Extract schedule information
                    schedule = content.get("schedule", {})
                    cron_schedule = schedule.get("cron_schedule", "")
                    next_scheduled_time = schedule.get("next_scheduled_time", "")
                    
                    report_info = {
                        "name": saved_search.name,
                        "search": content.get("search", ""),
                        "description": content.get("description", ""),
                        "owner": content.get("owner", ""),
                        "creator": content.get("creator", ""),
                        "created": content.get("created", ""),
                        "modified": content.get("modified", ""),
                        "is_scheduled": bool(schedule),
                        "cron_schedule": cron_schedule,
                        "next_scheduled_time": next_scheduled_time,
                        "app": content.get("app", ""),
                        "disabled": content.get("disabled", False),
                        "report_type": content.get("report_type", ""),
                        "display_type": content.get("display.general.type", ""),
                        "is_alert": content.get("is_alert", False),
                        "alert_type": content.get("alert_type", ""),
                        "alert_condition": content.get("alert_condition", "")
                    }
                    reports.append(report_info)
                except Exception as e:
                    print(f"Warning: Could not process report {saved_search.name}: {str(e)}")
                    continue
            
            print(f"\nFound {len(reports)} reports")
            return {"entry": reports}
        except Exception as e:
            print(f"Error getting reports: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def get_users(self) -> Dict[str, Any]:
        """Get all users and their roles."""
        return self._make_request("GET", "/services/authentication/users")

    def get_roles(self) -> Dict[str, Any]:
        """Get all roles and their capabilities."""
        return self._make_request("GET", "/services/authorization/roles")

    def get_addons(self) -> Dict[str, Any]:
        """Get all installed add-ons."""
        # Get all apps first
        all_apps = self._make_request("GET", "/services/apps/local")
        
        # Filter for add-ons (typically add-ons have 'addon' in their name or are marked as add-ons)
        addons = {
            "entry": [
                entry for entry in all_apps.get("entry", [])
                if any([
                    "addon" in entry.get("name", "").lower(),
                    entry.get("content", {}).get("is_addon", False),
                    "add-on" in entry.get("content", {}).get("description", "").lower()
                ])
            ]
        }
        
        # Copy over the paging and messages from the original response
        addons["paging"] = all_apps.get("paging", {})
        addons["messages"] = all_apps.get("messages", [])
        
        return addons

    def get_inputs(self) -> Dict[str, Any]:
        """Get all configured inputs (data collection)."""
        return self._make_request("GET", "/services/data/inputs")

    def get_indexes(self) -> Dict[str, Any]:
        """Get all indexes and their configurations."""
        return self._make_request("GET", "/services/data/indexes")

    def get_props(self) -> Dict[str, Any]:
        """Get all props.conf configurations."""
        return self._make_request("GET", "/services/properties")

    def get_transforms(self) -> Dict[str, Any]:
        """Get all transforms.conf configurations."""
        return self._make_request("GET", "/services/data/transforms")

    def get_license_usage(self) -> Dict[str, Any]:
        """Get license usage information."""
        return self._make_request("GET", "/services/licenser/usage")

    def get_index_usage(self, days: int = 30) -> Dict[str, Any]:
        """
        Get index usage statistics with daily volumes.
        
        Args:
            days: Number of days to look back (default: 30)
        """
        earliest_time = f"-{days}d"
        search = """
        search index=* 
        | stats count by index 
        | sort - count
        """
        print(f"\nExecuting index usage search: {search}")
        try:
            # Create and execute the search job
            job = self.service.jobs.create(search, earliest_time=earliest_time, exec_mode='blocking')
            
            # Get the results
            results = []
            for result in job.results():
                results.append({
                    "index": result.get("index", ""),
                    "count": int(result.get("count", 0))
                })
            
            return {"results": results}
        except Exception as e:
            print(f"Error executing index usage search: {str(e)}")
            return {"results": []}

    def get_sourcetype_usage(self, days: int = 30) -> Dict[str, Any]:
        """
        Get sourcetype usage statistics with daily volumes.
        
        Args:
            days: Number of days to look back (default: 30)
        """
        earliest_time = f"-{days}d"
        search = """
        search index=* 
        | stats count by sourcetype 
        | sort - count
        """
        print(f"\nExecuting sourcetype usage search: {search}")
        try:
            # Create and execute the search job
            job = self.service.jobs.create(search, earliest_time=earliest_time, exec_mode='blocking')
            
            # Get the results
            results = []
            for result in job.results():
                results.append({
                    "sourcetype": result.get("sourcetype", ""),
                    "count": int(result.get("count", 0))
                })
            
            return {"results": results}
        except Exception as e:
            print(f"Error executing sourcetype usage search: {str(e)}")
            return {"results": []}

    def get_user_logins(self, days: int = 30) -> Dict[str, Any]:
        """
        Get user login statistics across multiple time periods.
        
        Args:
            days: Number of days to look back (default: 30)
        """
        search = """
        search index=_audit 
        | eval action=if(sourcetype="splunkd_audit", action, if(sourcetype="splunk_web_access", "login", action))
        | search action=login OR action="user.login"
        | eval time_period=case(
            _time > relative_time(now(), "-1d@d"), "last_24h",
            _time > relative_time(now(), "-7d@d"), "last_7d",
            _time > relative_time(now(), "-30d@d"), "last_30d",
            _time > relative_time(now(), "-180d@d"), "last_180d"
        )
        | stats count by user time_period
        | eval count=tonumber(count)
        | stats 
            sum(eval(if(time_period="last_24h",count,0))) as logins_24h,
            sum(eval(if(time_period="last_7d",count,0))) as logins_7d,
            sum(eval(if(time_period="last_30d",count,0))) as logins_30d,
            sum(eval(if(time_period="last_180d",count,0))) as logins_180d
        by user
        | sort - logins_30d
        """
        print(f"\nExecuting user logins search: {search}")
        try:
            # Create and execute the search job
            job = self.service.jobs.create(search, exec_mode='blocking')
            
            # Get the results
            results = []
            for result in job.results():
                results.append({
                    "user": result.get("user", ""),
                    "logins_24h": int(result.get("logins_24h", 0)),
                    "logins_7d": int(result.get("logins_7d", 0)),
                    "logins_30d": int(result.get("logins_30d", 0)),
                    "logins_180d": int(result.get("logins_180d", 0))
                })
            
            if not results:
                print("Warning: No login events found in _audit index")
                # Return a default entry for the admin user if no results found
                return {
                    "results": [{
                        "user": "admin",
                        "logins_24h": 0,
                        "logins_7d": 0,
                        "logins_30d": 0,
                        "logins_180d": 0
                    }]
                }
            
            return {"results": results}
        except Exception as e:
            print(f"Error executing user logins search: {str(e)}")
            # Return a default entry for the admin user on error
            return {
                "results": [{
                    "user": "admin",
                    "logins_24h": 0,
                    "logins_7d": 0,
                    "logins_30d": 0,
                    "logins_180d": 0
                }]
            }

    def _convert_epoch_to_datetime(self, epoch: int) -> str:
        """Convert epoch timestamp to YYYY-MM-DD HH:MM:SS format."""
        if not epoch:
            return ""
        try:
            return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return ""

    def _format_users_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format users response into tabular data."""
        # First get login counts for the last 180 days
        login_counts = {}
        try:
            login_data = self.get_user_logins(days=180)
            for result in login_data.get("results", []):
                login_counts[result.get("user", "")] = result.get("count", 0)
        except Exception as e:
            print(f"Warning: Could not get login counts: {str(e)}")

        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            username = entry.get("name", "")
            table_data.append({
                "username": username,
                "realname": content.get("realname", ""),
                "email": content.get("email", ""),
                "roles": ",".join(content.get("roles", [])),
                "last_successful_login": self._convert_epoch_to_datetime(content.get("last_successful_login", "")),
                "logins_last_180_days": login_counts.get(username, 0),
                "status": content.get("status", "")
            })
        return table_data

    def _format_roles_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format roles response into tabular data."""
        # First get all users to count role assignments
        role_counts = {}
        try:
            users_data = self.get_users()
            for entry in users_data.get("entry", []):
                content = entry.get("content", {})
                roles = content.get("roles", [])
                for role in roles:
                    role_counts[role] = role_counts.get(role, 0) + 1
        except Exception as e:
            print(f"Warning: Could not get user role counts: {str(e)}")

        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            role_name = entry.get("name", "")
            table_data.append({
                "role_name": role_name,
                "description": content.get("description", ""),
                "capabilities": ",".join(content.get("capabilities", [])),
                "imported_roles": ",".join(content.get("imported_roles", [])),
                "srchIndexesAllowed": ",".join(content.get("srchIndexesAllowed", [])),
                "srchIndexesDefault": ",".join(content.get("srchIndexesDefault", [])),
                "user_count": role_counts.get(role_name, 0)
            })
        return table_data

    def _format_apps_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format apps response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            table_data.append({
                "app_name": entry.get("name", ""),
                "label": content.get("label", ""),
                "version": content.get("version", ""),
                "description": content.get("description", ""),
                "author": content.get("author", ""),
                "is_visible": content.get("visible", False),
                "is_configured": content.get("configured", False),
                "is_managed": content.get("managed", False)
            })
        return table_data

    def _format_addons_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format addons response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            table_data.append({
                "addon_name": entry.get("name", ""),
                "label": content.get("label", ""),
                "version": content.get("version", ""),
                "description": content.get("description", ""),
                "author": content.get("author", ""),
                "is_visible": content.get("visible", False),
                "is_configured": content.get("configured", False),
                "is_managed": content.get("managed", False)
            })
        return table_data

    def _format_inputs_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format inputs response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            table_data.append({
                "input_name": entry.get("name", ""),
                "input_type": content.get("type", ""),
                "host": content.get("host", ""),
                "index": content.get("index", ""),
                "sourcetype": content.get("sourcetype", ""),
                "disabled": content.get("disabled", False),
                "interval": content.get("interval", ""),
                "source": content.get("source", "")
            })
        return table_data

    def _format_indexes_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format indexes response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            table_data.append({
                "index_name": entry.get("name", ""),
                "homePath": content.get("homePath", ""),
                "coldPath": content.get("coldPath", ""),
                "thawedPath": content.get("thawedPath", ""),
                "maxTotalDataSizeMB": content.get("maxTotalDataSizeMB", 0),
                "frozenTimePeriodInSecs": content.get("frozenTimePeriodInSecs", 0),
                "disabled": content.get("disabled", False),
                "assureUTF8": content.get("assureUTF8", False)
            })
        return table_data

    def _format_saved_searches_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format saved searches response into tabular data."""
        table_data = []
        entries = response.get("entry", [])
        print(f"\nFormatting {len(entries)} saved searches into table data")
        
        for entry in entries:
            try:
                table_data.append({
                    "search_name": entry.get("name", ""),
                    "search_query": entry.get("search", ""),
                    "description": entry.get("description", ""),
                    "owner": entry.get("owner", ""),
                    "creator": entry.get("creator", ""),
                    "created": self._convert_epoch_to_datetime(entry.get("created", "")),
                    "modified": self._convert_epoch_to_datetime(entry.get("modified", "")),
                    "is_scheduled": entry.get("is_scheduled", False),
                    "cron_schedule": entry.get("cron_schedule", ""),
                    "next_scheduled_time": self._convert_epoch_to_datetime(entry.get("next_scheduled_time", "")),
                    "is_alert": entry.get("is_alert", False),
                    "alert_type": entry.get("alert_type", ""),
                    "alert_condition": entry.get("alert_condition", ""),
                    "app": entry.get("app", ""),
                    "disabled": entry.get("disabled", False)
                })
            except Exception as e:
                print(f"Warning: Could not format saved search {entry.get('name', 'unknown')}: {str(e)}")
                continue
        
        print(f"\nFormatted {len(table_data)} saved searches into table data")
        if table_data:
            print("Sample of first saved search:")
            print(json.dumps(table_data[0], indent=2))
        return table_data

    def _format_license_usage_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format license usage response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            table_data.append({
                "stack_id": content.get("stack_id", ""),
                "quota": content.get("quota", 0),
                "used": content.get("used", 0),
                "remaining": content.get("remaining", 0),
                "violation": content.get("violation", False),
                "status": content.get("status", ""),
                "window_period": self._convert_epoch_to_datetime(content.get("window_period", ""))
            })
        return table_data

    def _format_search_results_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format search results into tabular data."""
        print(f"\nSearch results: {json.dumps(response.get('results', []), indent=2)}")
        table_data = []
        for result in response.get("results", []):
            table_data.append({
                "user": result.get("user", ""),
                "logins_24h": int(result.get("logins_24h", 0)),
                "logins_7d": int(result.get("logins_7d", 0)),
                "logins_30d": int(result.get("logins_30d", 0)),
                "logins_180d": int(result.get("logins_180d", 0))
            })
        return table_data

    def _format_index_usage_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format index usage response into tabular data."""
        table_data = []
        print(f"\nIndex usage results: {json.dumps(response.get('results', []), indent=2)}")
        for result in response.get("results", []):
            table_data.append({
                "index": result.get("index", ""),
                "total_events": int(result.get("count", 0))
            })
        return table_data

    def _format_sourcetype_usage_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format sourcetype usage response into tabular data."""
        table_data = []
        print(f"\nSourcetype usage results: {json.dumps(response.get('results', []), indent=2)}")
        for result in response.get("results", []):
            table_data.append({
                "sourcetype": result.get("sourcetype", ""),
                "total_events": int(result.get("count", 0))
            })
        return table_data

    def get_formatted_users(self) -> List[Dict[str, Any]]:
        """Get users data in tabular format."""
        response = self.get_users()
        return self._format_users_table(response)

    def get_formatted_roles(self) -> List[Dict[str, Any]]:
        """Get roles data in tabular format."""
        response = self.get_roles()
        return self._format_roles_table(response)

    def get_formatted_apps(self) -> List[Dict[str, Any]]:
        """Get apps data in tabular format."""
        response = self.get_apps()
        return self._format_apps_table(response)

    def get_formatted_addons(self) -> List[Dict[str, Any]]:
        """Get addons data in tabular format."""
        response = self.get_addons()
        return self._format_addons_table(response)

    def get_formatted_inputs(self) -> List[Dict[str, Any]]:
        """Get inputs data in tabular format."""
        response = self.get_inputs()
        return self._format_inputs_table(response)

    def get_formatted_indexes(self) -> List[Dict[str, Any]]:
        """Get indexes data in tabular format."""
        response = self.get_indexes()
        return self._format_indexes_table(response)

    def get_formatted_saved_searches(self) -> List[Dict[str, Any]]:
        """Get saved searches data in tabular format."""
        print("\nGetting formatted saved searches data...")
        response = self.get_saved_searches()
        # Convert list response to expected dictionary format
        if isinstance(response, list):
            response = {"entry": response}
        formatted_data = self._format_saved_searches_table(response)
        print(f"Formatted saved searches data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first saved search:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def get_formatted_license_usage(self) -> List[Dict[str, Any]]:
        """Get license usage data in tabular format."""
        response = self.get_license_usage()
        return self._format_license_usage_table(response)

    def get_formatted_index_usage(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get index usage data in tabular format."""
        response = self.get_index_usage(days)
        return self._format_index_usage_table(response)

    def get_formatted_sourcetype_usage(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get sourcetype usage data in tabular format."""
        response = self.get_sourcetype_usage(days)
        return self._format_sourcetype_usage_table(response)

    def get_formatted_user_logins(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get user login data in tabular format."""
        response = self.get_user_logins(days)
        return self._format_search_results_table(response)

    def _format_dashboards_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format dashboards response into tabular data."""
        table_data = []
        for entry in response.get("entry", []):
            content = entry.get("content", {})
            acl = entry.get("acl", {})
            table_data.append({
                "dashboard_name": entry.get("name", ""),
                "label": content.get("label", ""),
                "description": content.get("description", ""),
                "author": entry.get("author", ""),
                "created": entry.get("updated", ""),  # Using updated as created timestamp
                "modified": entry.get("updated", ""),  # Using updated as modified timestamp
                "app": acl.get("app", ""),
                "is_visible": content.get("isVisible", False),
                "version": content.get("version", ""),
                "owner": acl.get("owner", "")
            })
        return table_data

    def _format_alerts_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format alerts response into tabular data."""
        table_data = []
        entries = response.get("entry", [])
        print(f"\nFormatting {len(entries)} alerts into table data")
        
        for entry in entries:
            content = entry.get("content", {})
            print(f"\nProcessing alert: {entry.get('name', 'unknown')}")
            print(f"Content: {json.dumps(content, indent=2)}")
            
            table_data.append({
                "alert_name": entry.get("name", ""),
                "search_query": content.get("search", ""),
                "description": content.get("description", ""),
                "owner": content.get("owner", ""),
                "creator": content.get("creator", ""),
                "created": self._convert_epoch_to_datetime(content.get("created", "")),
                "modified": self._convert_epoch_to_datetime(content.get("modified", "")),
                "alert_type": content.get("alert_type", ""),
                "alert_condition": content.get("alert_condition", ""),
                "app": content.get("app", ""),
                "disabled": content.get("disabled", False)
            })
        
        print(f"\nFormatted {len(table_data)} alerts into table data")
        return table_data

    def get_formatted_dashboards(self) -> List[Dict[str, Any]]:
        """Get dashboards data in tabular format."""
        response = self.get_dashboards()
        return self._format_dashboards_table(response)

    def get_formatted_alerts(self) -> List[Dict[str, Any]]:
        """Get alerts data in tabular format."""
        response = self.get_alerts()
        return self._format_alerts_table(response)

    def get_formatted_reports(self) -> List[Dict[str, Any]]:
        """Get reports data in tabular format."""
        print("\nGetting formatted reports data...")
        response = self.get_reports()
        formatted_data = self._format_reports_table(response)
        print(f"Formatted reports data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first report:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def export_to_csv(self, data: List[Dict[str, Any]], filename: str, chunk_size: int = 1000, 
                      s3_client: Optional['S3Client'] = None) -> None:
        """
        Export data to CSV file(s) and optionally upload to S3.
        
        Args:
            data: List of dictionaries to export
            filename: Base filename for CSV output
            chunk_size: Number of records per chunk (default: 1000)
            s3_client: Optional S3Client for uploading CSVs to S3
        """
        if not data:
            print(f"No data to export to {filename}")
            return
            
        # Calculate number of chunks needed
        total_records = len(data)
        num_chunks = (total_records + chunk_size - 1) // chunk_size
        
        for chunk_num in range(num_chunks):
            start_idx = chunk_num * chunk_size
            end_idx = min((chunk_num + 1) * chunk_size, total_records)
            chunk_data = data[start_idx:end_idx]
            
            # Generate chunk filename
            if num_chunks > 1:
                chunk_filename = f"{os.path.splitext(filename)[0]}_chunk{chunk_num + 1}.csv"
            else:
                chunk_filename = filename
                
            # Write CSV file locally
            with open(chunk_filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=chunk_data[0].keys())
                writer.writeheader()
                writer.writerows(chunk_data)
            print(f"Exported {len(chunk_data)} rows to {chunk_filename}")
            
            # Upload to S3 if S3 client is provided
            if s3_client:
                try:
                    # Use the filename as the S3 key (path)
                    s3_key = f"airlift-csv/{chunk_filename}"
                    s3_uri = s3_client.upload_csv(chunk_filename, s3_key)
                    
                except Exception as e:
                    print(f"Warning: Could not upload {chunk_filename} to S3: {str(e)}")
                    continue

    def print_summary(self, data: List[Dict[str, Any]], title: str) -> None:
        """Print a summary of the data."""
        if not data:
            print(f"\n{title}: No data available")
            return
            
        print(f"\n{title}:")
        print(f"Total entries: {len(data)}")
        if len(data) > 0:
            print("\nSample data (first row):")
            print(json.dumps(data[0], indent=2))

    def get_detection_rules(self) -> Dict[str, Any]:
        """Get all Enterprise Security detection rules."""
        # First get the current user's name
        user_info = self._make_request("GET", "/services/authentication/current-context")
        username = user_info.get("entry", [{}])[0].get("content", {}).get("username", "admin")
        
        print(f"\nFetching detection rules for user: {username}")
        
        try:
            # First check if ES app is installed
            apps_response = self.get_apps()
            installed_apps = [entry.get("name", "") for entry in apps_response.get("entry", [])]
            has_es = "SplunkEnterpriseSecuritySuite" in installed_apps
            has_security_essentials = "SplunkSecurityEssentials" in installed_apps
            
            print(f"\nInstalled apps: {', '.join(installed_apps)}")
            print(f"Enterprise Security app installed: {has_es}")
            print(f"Security Essentials app installed: {has_security_essentials}")
            
            # Define endpoints based on installed apps
            endpoints = [f"/servicesNS/{username}/search/saved/searches"]  # Always try search app
            if has_es:
                endpoints.append(f"/servicesNS/{username}/SplunkEnterpriseSecuritySuite/saved/searches")
            if has_security_essentials:
                endpoints.append(f"/servicesNS/{username}/SplunkSecurityEssentials/saved/searches")
            
            all_entries = []
            
            for endpoint in endpoints:
                print(f"\nTrying endpoint: {endpoint}")
                
                # Try different search patterns for each endpoint
                search_patterns = [
                    "title=* - Rule",  # Look for titles ending with " - Rule"
                    "search_type=detection",  # Look for items marked as detection type
                    "search_type=correlation",  # Look for correlation searches
                    "is_alert=1",  # Look for alert-type searches
                ]
                
                # Only add ES-specific pattern if ES is installed
                if has_es:
                    search_patterns.append("app=SplunkEnterpriseSecuritySuite")
                
                for pattern in search_patterns:
                    print(f"Trying search pattern: {pattern}")
                    params = {
                        "count": 0,
                        "search": pattern
                    }
                    
                    try:
                        response = self._make_request("GET", endpoint, params=params)
                        entries = response.get("entry", [])
                        print(f"Found {len(entries)} entries with pattern: {pattern}")
                        
                        # Debug: Print first entry if any found
                        if entries:
                            print("Sample entry:")
                            print(json.dumps(entries[0], indent=2))
                        
                        all_entries.extend(entries)
                    except Exception as e:
                        print(f"Warning: Error with endpoint {endpoint} and pattern {pattern}: {str(e)}")
                        continue
            
            # Remove duplicates based on name
            unique_entries = []
            seen_names = set()
            for entry in all_entries:
                name = entry.get("name", "")
                if name and name not in seen_names:
                    seen_names.add(name)
                    unique_entries.append(entry)
            
            print(f"\nTotal unique detection rules found: {len(unique_entries)}")
            
            # Debug: Print all unique entries
            if unique_entries:
                print("\nAll unique detection rules:")
                for entry in unique_entries:
                    print(f"- {entry.get('name', 'unknown')}")
            
            return {"entry": unique_entries}
            
        except Exception as e:
            print(f"Error fetching detection rules: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return {"entry": []}

    def _format_detection_rules_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format detection rules response into tabular data."""
        table_data = []
        entries = response.get("entry", [])
        print(f"\nFormatting {len(entries)} detection rules into table data")
        
        for entry in entries:
            content = entry.get("content", {})
            print(f"\nProcessing detection rule: {entry.get('name', 'unknown')}")
            
            # Extract schedule information
            schedule = content.get("schedule", {})
            cron_schedule = schedule.get("cron_schedule", "")
            next_scheduled_time = schedule.get("next_scheduled_time", "")
            
            rule_data = {
                "rule_name": entry.get("name", ""),
                "type": "detection_rule",  # Always set type to detection_rule
                "search_query": content.get("search", ""),
                "description": content.get("description", ""),
                "owner": content.get("owner", ""),
                "creator": content.get("creator", ""),
                "created": self._convert_epoch_to_datetime(content.get("created", "")),
                "modified": self._convert_epoch_to_datetime(content.get("modified", "")),
                "is_scheduled": bool(schedule),
                "cron_schedule": cron_schedule,
                "next_scheduled_time": self._convert_epoch_to_datetime(next_scheduled_time),
                "app": content.get("app", ""),
                "disabled": content.get("disabled", False),
                "search_type": content.get("search_type", ""),
                "severity": content.get("severity", ""),
                "risk_score": content.get("risk_score", ""),
                "mitre_attack": content.get("mitre_attack", ""),
                "mitre_technique": content.get("mitre_technique", ""),
                "mitre_tactic": content.get("mitre_tactic", "")
            }
            
            table_data.append(rule_data)
        
        print(f"\nFormatted {len(table_data)} detection rules into table data")
        if table_data:
            print("Sample of first detection rule:")
            print(json.dumps(table_data[0], indent=2))
        return table_data

    def get_analytic_stories(self) -> Dict[str, Any]:
        """Get all Enterprise Security analytic stories."""
        # First get the current user's name
        user_info = self._make_request("GET", "/services/authentication/current-context")
        username = user_info.get("entry", [{}])[0].get("content", {}).get("username", "admin")
        
        print(f"\nFetching analytic stories for user: {username}")
        
        try:
            # Get saved searches from ES app
            endpoint = f"/servicesNS/{username}/SplunkEnterpriseSecuritySuite/saved/searches"
            params = {
                "count": 0,
                "search": "search_type=story"
            }
            
            print(f"\nTrying endpoint: {endpoint}")
            response = self._make_request("GET", endpoint, params=params)
            
            # Debug: Print the raw response
            print("\nAnalytic Stories API Response:")
            print(json.dumps(response, indent=2))
            
            # Debug: Print number of entries found
            entries = response.get("entry", [])
            print(f"\nFound {len(entries)} analytic stories")
            
            return response
            
        except Exception as e:
            print(f"Error fetching analytic stories: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return {"entry": []}

    def get_playbook_responses(self) -> Dict[str, Any]:
        """Get all Enterprise Security playbook responses."""
        # First get the current user's name
        user_info = self._make_request("GET", "/services/authentication/current-context")
        username = user_info.get("entry", [{}])[0].get("content", {}).get("username", "admin")
        
        print(f"\nFetching playbook responses for user: {username}")
        
        try:
            # Get saved searches from ES app
            endpoint = f"/servicesNS/{username}/SplunkEnterpriseSecuritySuite/saved/searches"
            params = {
                "count": 0,
                "search": "search_type=playbook"
            }
            
            print(f"\nTrying endpoint: {endpoint}")
            response = self._make_request("GET", endpoint, params=params)
            
            # Debug: Print the raw response
            print("\nPlaybook Responses API Response:")
            print(json.dumps(response, indent=2))
            
            # Debug: Print number of entries found
            entries = response.get("entry", [])
            print(f"\nFound {len(entries)} playbook responses")
            
            return response
            
        except Exception as e:
            print(f"Error fetching playbook responses: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return {"entry": []}

    def _create_search_job(self, search: str) -> str:
        """Create a search job and return its ID."""
        try:
            # Create the search job
            job = self.service.jobs.create(search, exec_mode='blocking')
            return job.sid
        except Exception as e:
            print(f"Error creating search job: {str(e)}")
            raise

    def _wait_for_search_job(self, search_id: str) -> None:
        """Wait for a search job to complete."""
        try:
            job = self.service.jobs.get(search_id)
            while not job.is_done():
                time.sleep(1)
        except Exception as e:
            print(f"Error waiting for search job: {str(e)}")
            raise

    def _get_search_results(self, search_id: str) -> Dict[str, Any]:
        """Get results from a completed search job."""
        try:
            job = self.service.jobs.get(search_id)
            results = job.results()
            return {"results": results}
        except Exception as e:
            print(f"Error getting search results: {str(e)}")
            raise

    def get_app_content(self) -> Dict[str, Any]:
        """Get content analysis for all installed apps."""
        # First get all installed apps
        apps_response = self.get_apps()
        all_apps = [entry.get("name", "") for entry in apps_response.get("entry", [])]
        
        print(f"\nFound {len(all_apps)} total apps")
        
        # Define default Splunk apps that should be skipped for content analysis
        default_apps = {
            "alert_logevent",
            "alert_webhook",
            "appsbrowser",
            "introspection_generator_addon",
            "journald_input",
            "launcher",
            "learned",
            "python_upgrade_readiness_app",
            "search",
            "server_app"
            "splunk-dashboard-studio",
            "splunk-rolling-upgrade",
            "splunk-visual-exporter",
            "splunk_archiver",
            "splunk_assist",
            "splunk_gdi",
            "splunk_httpinput",
            "splunk_instrumentation",
            "splunk_internal_metrics",
            "splunk_metrics_workspace",
            "splunk_monitoring_console",
            "splunk_rapid_diag",
            "splunk_secure_gateway",
            "SplunkDeploymentServerConfig"
        }
        print(f"Configured to skip content analysis for {len(default_apps)} default Splunk apps")
        
        # Filter out add-ons and disabled apps
        non_addon_apps = []
        for app in all_apps:
            if not app:
                continue
                
            # Get app properties
            app_props = next((entry.get("content", {}) for entry in apps_response.get("entry", []) if entry.get("name") == app), {})
            
            # Skip if it's an add-on
            if any([
                "ta-" in app.lower(),  # Technical Add-on
                "sa-" in app.lower(),  # Supporting Add-on
                "da-" in app.lower(),  # Data Add-on
                "ta_" in app.lower(),  # Technical Add-on with underscore (case-insensitive)
                "sa_" in app.lower(),  # Supporting Add-on with underscore (case-insensitive)
                "da_" in app.lower(),  # Data Add-on with underscore (case-insensitive)
                "input" in app.lower(),  # Input add-ons
                "addon" in app.lower(),
                app_props.get("is_addon", False),
                "add-on" in app_props.get("description", "").lower()
            ]):
                print(f"Skipping add-on: {app}")
                continue
                
            # Skip if app is disabled
            if not app_props.get("visible", True):
                print(f"Skipping disabled app: {app}")
                continue
                
            non_addon_apps.append(app)
        
        print(f"Found {len(non_addon_apps)} enabled non-addon apps")
        print(f"Enabled non-addon apps: {', '.join(sorted(non_addon_apps))}")
        
        all_app_content = []
        seen_kos = set()  # Track unique Knowledge Objects
        
        for app in non_addon_apps:
            print(f"\nAnalyzing content for app: {app}")
            
            # Skip content analysis for default Splunk apps
            if app in default_apps:
                print(f"Skipping content analysis for default app: {app}")
                continue
            
            try:
                # Initialize pagination variables
                offset = 0
                page_size = 100
                total_searches = 0
                
                while True:
                    # Get saved searches for this app with pagination
                    saved_searches = self.service.saved_searches.list(
                        app=app,
                        count=page_size,
                        offset=offset
                    )
                    
                    # If no results, break the loop
                    if not saved_searches:
                        break
                        
                    print(f"Found {len(saved_searches)} saved searches in {app} (offset: {offset})")
                    total_searches += len(saved_searches)
                    
                    for saved_search in saved_searches:
                        try:
                            # Skip if the search doesn't belong to this app
                            if saved_search.content.get("app") != app:
                                print(f"Skipping search {saved_search.name} - belongs to app {saved_search.content.get('app')}")
                                continue
                                
                            # Create a unique key for this Knowledge Object
                            ko_key = f"{saved_search.name}:{app}"
                            
                            # Skip if we've already seen this KO
                            if ko_key in seen_kos:
                                print(f"Skipping duplicate KO: {saved_search.name}")
                                continue
                                
                            content = saved_search.content
                            
                            # Determine the type of content
                            content_type = "report"  # default type
                            
                            # Check for detection rules
                            if saved_search.name.endswith(" - Rule"):
                                content_type = "detection_rule"
                            # Check for analytic stories
                            elif content.get("search_type") == "story":
                                content_type = "analytic_story"
                            # Check for playbook responses
                            elif content.get("search_type") == "playbook":
                                content_type = "playbook_response"
                            # Check for alerts
                            elif any([
                                content.get("alert.track", False),
                                (content.get("actions") and content.get("alert_threshold")),
                                (content.get("alert_comparator") and content.get("alert_type") and content.get("alert_type") != "always")
                            ]):
                                content_type = "alert"
                            
                            # Extract schedule information
                            schedule = content.get("schedule", {})
                            cron_schedule = schedule.get("cron_schedule", "")
                            next_scheduled_time = schedule.get("next_scheduled_time", "")
                            
                            # Simplified content data with only essential fields
                            content_data = {
                                "app_name": app,
                                "content_name": saved_search.name,
                                "type": content_type,
                                "description": content.get("description", ""),
                                "search_query": content.get("search", ""),
                                "disabled": content.get("disabled", False),
                                "owner": content.get("owner", ""),
                                "creator": content.get("creator", ""),
                                "created": self._convert_epoch_to_datetime(content.get("created", "")),
                                "modified": self._convert_epoch_to_datetime(content.get("modified", "")),
                                "app": content.get("app", ""),
                                "disabled": content.get("disabled", False)
                            }
                            
                            # Add to seen set and content list
                            seen_kos.add(ko_key)
                            all_app_content.append(content_data)
                            print(f"Added {content_type}: {saved_search.name}")
                            
                        except Exception as e:
                            print(f"Warning: Could not process saved search {saved_search.name}: {str(e)}")
                            continue
                    
                    # If we got fewer results than the page size, we've reached the end
                    if len(saved_searches) < page_size:
                        break
                        
                    # Increment offset for next page
                    offset += page_size
                
                print(f"Total saved searches processed for {app}: {total_searches}")
                
            except Exception as e:
                print(f"Error analyzing content for app {app}: {str(e)}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                continue
        
        print(f"\nTotal unique Knowledge Objects found: {len(seen_kos)}")
        return {"results": all_app_content}

    def _format_app_content_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format app content response into tabular data."""
        table_data = []
        entries = response.get("results", [])
        print(f"\nFormatting {len(entries)} app content items into table data")
        
        for entry in entries:
            content_data = {
                "app_name": entry.get("app_name", ""),
                "content_name": entry.get("content_name", ""),
                "type": entry.get("type", ""),
                "description": entry.get("description", ""),
                "search_query": entry.get("search_query", ""),
                "disabled": entry.get("disabled", False),
                "cron_schedule": entry.get("cron_schedule", ""),
                "next_scheduled_time": entry.get("next_scheduled_time", ""),
                "owner": entry.get("owner", ""),
                "creator": entry.get("creator", ""),
                "created": self._convert_epoch_to_datetime(entry.get("created", "")),
                "modified": self._convert_epoch_to_datetime(entry.get("modified", "")),
                "search_type": entry.get("search_type", ""),
                "severity": entry.get("severity", ""),
                "risk_score": entry.get("risk_score", ""),
                "mitre_attack": entry.get("mitre_attack", ""),
                "mitre_technique": entry.get("mitre_technique", ""),
                "mitre_tactic": entry.get("mitre_tactic", "")
            }
            
            table_data.append(content_data)
        
        print(f"\nFormatted {len(table_data)} app content items into table data")
        if table_data:
            print("Sample of first app content item:")
            print(json.dumps(table_data[0], indent=2))
        return table_data

    def get_formatted_app_content(self) -> List[Dict[str, Any]]:
        """Get app content data in tabular format."""
        print("\nGetting formatted app content data...")
        response = self.get_app_content()
        formatted_data = self._format_app_content_table(response)
        print(f"Formatted app content data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first app content item:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def get_formatted_detection_rules(self) -> List[Dict[str, Any]]:
        """Get detection rules data in tabular format."""
        print("\nGetting formatted detection rules data...")
        response = self.get_detection_rules()
        formatted_data = self._format_detection_rules_table(response)
        print(f"Formatted detection rules data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first detection rule:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def get_formatted_analytic_stories(self) -> List[Dict[str, Any]]:
        """Get analytic stories data in tabular format."""
        print("\nGetting formatted analytic stories data...")
        response = self.get_analytic_stories()
        formatted_data = self._format_analytic_stories_table(response)
        print(f"Formatted analytic stories data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first analytic story:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def get_formatted_playbook_responses(self) -> List[Dict[str, Any]]:
        """Get playbook responses data in tabular format."""
        print("\nGetting formatted playbook responses data...")
        response = self.get_playbook_responses()
        formatted_data = self._format_playbook_responses_table(response)
        print(f"Formatted playbook responses data length: {len(formatted_data)}")
        if formatted_data:
            print("Sample of first playbook response:")
            print(json.dumps(formatted_data[0], indent=2))
        return formatted_data

    def _format_analytic_stories_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format analytic stories response into tabular data."""
        table_data = []
        entries = response.get("entry", [])
        print(f"\nFormatting {len(entries)} analytic stories into table data")
        
        for entry in entries:
            content = entry.get("content", {})
            print(f"\nProcessing analytic story: {entry.get('name', 'unknown')}")
            
            story_data = {
                "story_name": entry.get("name", ""),
                "description": content.get("description", ""),
                "owner": content.get("owner", ""),
                "creator": content.get("creator", ""),
                "created": self._convert_epoch_to_datetime(content.get("created", "")),
                "modified": self._convert_epoch_to_datetime(content.get("modified", "")),
                "app": content.get("app", ""),
                "disabled": content.get("disabled", False),
                "search_type": content.get("search_type", ""),
                "category": content.get("category", ""),
                "narrative": content.get("narrative", ""),
                "mitre_attack": content.get("mitre_attack", ""),
                "mitre_technique": content.get("mitre_technique", ""),
                "mitre_tactic": content.get("mitre_tactic", "")
            }
            
            table_data.append(story_data)
        
        print(f"\nFormatted {len(table_data)} analytic stories into table data")
        if table_data:
            print("Sample of first analytic story:")
            print(json.dumps(table_data[0], indent=2))
        return table_data

    def _format_playbook_responses_table(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format playbook responses response into tabular data."""
        table_data = []
        entries = response.get("entry", [])
        print(f"\nFormatting {len(entries)} playbook responses into table data")
        
        for entry in entries:
            content = entry.get("content", {})
            print(f"\nProcessing playbook response: {entry.get('name', 'unknown')}")
            
            playbook_data = {
                "playbook_name": entry.get("name", ""),
                "description": content.get("description", ""),
                "owner": content.get("owner", ""),
                "creator": content.get("creator", ""),
                "created": self._convert_epoch_to_datetime(content.get("created", "")),
                "modified": self._convert_epoch_to_datetime(content.get("modified", "")),
                "app": content.get("app", ""),
                "disabled": content.get("disabled", False),
                "search_type": content.get("search_type", ""),
                "category": content.get("category", ""),
                "response_actions": content.get("response_actions", ""),
                "mitre_attack": content.get("mitre_attack", ""),
                "mitre_technique": content.get("mitre_technique", ""),
                "mitre_tactic": content.get("mitre_tactic", "")
            }
            
            table_data.append(playbook_data)
        
        print(f"\nFormatted {len(table_data)} playbook responses into table data")
        if table_data:
            print("Sample of first playbook response:")
            print(json.dumps(table_data[0], indent=2))
        return table_data
