#!/usr/bin/env python3
"""
REST handler for generating demo logs from Splunk UI.

This handler uses PersistentServerConnectionApplication for proper REST support.

Endpoint: /services/ta_fake_tshrt/generate
Methods: GET (status), POST (generate)

POST Parameters:
  - sources: Comma-separated list (default: "all")
  - days: Number of days (default: "14")
  - scenarios: Scenario(s) to include (default: "exfil")
  - start_date: Start date YYYY-MM-DD (default: "2026-01-01")
  - scale: Volume scale factor (default: "1.0")
  - clients: Number of perfmon clients (default: "5")
  - client_interval: Minutes between client metrics (default: "30")
  - full_metrics: Include disk/network for clients (default: "false")
  - orders_per_day: Target orders per day (default: "224")
  - meraki_health_interval: Minutes between health samples (default: "5")
  - no_mr_health: Disable MR health (default: "false")
  - no_ms_health: Disable MS health (default: "false")
  - parallel: Number of parallel workers (default: "4")
  - clean_only: Only delete files, don't generate (default: "false")
"""

import os
import sys
import json
import glob
import subprocess
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
logger = logging.getLogger('generate_logs')

# Splunk imports
try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
    HAS_SPLUNK = True
except ImportError:
    logger.warning("Running outside Splunk environment")
    HAS_SPLUNK = False
    PersistentServerConnectionApplication = object


class GenerateHandler(PersistentServerConnectionApplication):
    """REST handler for log generation using persistent connection."""

    def __init__(self, command_line, command_arg):
        if HAS_SPLUNK:
            super().__init__()
        self.command_line = command_line
        self.command_arg = command_arg

    def handle(self, in_string):
        """
        Main entry point for handling requests.

        Args:
            in_string: JSON string with request data

        Returns:
            dict with 'status' and 'payload' keys
        """
        try:
            request = json.loads(in_string)
            method = request.get('method', 'GET')

            logger.info(f"Received {method} request")

            if method == 'GET':
                return self.handle_get(request)
            elif method == 'POST':
                return self.handle_post(request)
            else:
                return {
                    'status': 405,
                    'payload': {'error': f'Method {method} not allowed'}
                }

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            return {
                'status': 400,
                'payload': {'error': f'Invalid JSON: {e}'}
            }
        except Exception as e:
            logger.exception("Unexpected error")
            return {
                'status': 500,
                'payload': {'error': str(e)}
            }

    def handle_get(self, request):
        """
        Handle GET request - return available options and status.
        """
        return {
            'status': 200,
            'payload': {
                'status': 'ready',
                'sources': {
                    'individual': [
                        'asa', 'meraki', 'aws', 'gcp', 'entraid', 'exchange',
                        'webex', 'webex_ta', 'webex_api', 'wineventlog', 'perfmon',
                        'linux', 'access', 'orders', 'servicebus', 'servicenow',
                        'office_audit'
                    ],
                    'groups': [
                        'all', 'cloud', 'network', 'windows', 'linux',
                        'web', 'email', 'office', 'retail', 'collaboration', 'itsm'
                    ]
                },
                'scenarios': {
                    'attack': ['exfil', 'ransomware_attempt'],
                    'ops': ['memory_leak', 'cpu_runaway', 'disk_filling'],
                    'network': ['firewall_misconfig', 'certificate_expiry'],
                    'meta': ['none', 'all', 'attack', 'ops', 'network']
                },
                'defaults': {
                    'sources': 'all',
                    'days': '14',
                    'scenarios': 'exfil',
                    'start_date': '2026-01-01',
                    'scale': '1.0',
                    'clients': '5',
                    'parallel': '4'
                }
            }
        }

    def handle_post(self, request):
        """
        Handle POST request - generate logs.
        """
        # Parse form data
        form_data = self._parse_form(request.get('form', []))

        # Extract parameters with defaults
        sources = form_data.get('sources', 'all')
        days = form_data.get('days', '14')
        scenarios = form_data.get('scenarios', 'exfil')
        start_date = form_data.get('start_date', '2026-01-01')
        scale = form_data.get('scale', '1.0')
        clients = form_data.get('clients', '5')
        client_interval = form_data.get('client_interval', '30')
        full_metrics = form_data.get('full_metrics', 'false').lower() == 'true'
        orders_per_day = form_data.get('orders_per_day', '224')
        meraki_health_interval = form_data.get('meraki_health_interval', '5')
        no_mr_health = form_data.get('no_mr_health', 'false').lower() == 'true'
        no_ms_health = form_data.get('no_ms_health', 'false').lower() == 'true'
        parallel = form_data.get('parallel', '4')
        clean_only = form_data.get('clean_only', 'false').lower() == 'true'

        logger.info(f"Parameters: sources={sources}, days={days}, scenarios={scenarios}")

        # Paths
        splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')
        app_home = os.path.join(splunk_home, 'etc/apps/TA-FAKE-TSHRT')
        output_dir = os.path.join(app_home, 'bin/output')
        script = os.path.join(app_home, 'bin/main_generate.py')

        try:
            # Step 1: Delete old files
            deleted_count = self._clean_output_directory(output_dir)
            logger.info(f"Deleted {deleted_count} old files")

            if clean_only:
                return {
                    'status': 200,
                    'payload': {
                        'status': 'success',
                        'message': f'Cleaned {deleted_count} files',
                        'deleted_files': deleted_count
                    }
                }

            # Step 2: Build command
            cmd = [
                sys.executable or 'python3',
                script,
                f'--sources={sources}',
                f'--days={days}',
                f'--scenarios={scenarios}',
                f'--start-date={start_date}',
                f'--scale={scale}',
                f'--clients={clients}',
                f'--client-interval={client_interval}',
                f'--orders-per-day={orders_per_day}',
                f'--meraki-health-interval={meraki_health_interval}',
                f'--parallel={parallel}',
                '--no-test',
                '--quiet'
            ]

            # Add boolean flags
            if full_metrics:
                cmd.append('--full-metrics')
            if no_mr_health:
                cmd.append('--no-mr-health')
            if no_ms_health:
                cmd.append('--no-ms-health')

            logger.info(f"Running: {' '.join(cmd)}")

            # Step 3: Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                cwd=os.path.join(app_home, 'bin')
            )

            if result.returncode == 0:
                # Extract last few lines of output
                output_lines = []
                if result.stdout:
                    output_lines = result.stdout.strip().split('\n')[-10:]

                return {
                    'status': 200,
                    'payload': {
                        'status': 'success',
                        'message': f'Generated {days} days of logs for {sources}',
                        'deleted_files': deleted_count,
                        'output': '\n'.join(output_lines)
                    }
                }
            else:
                error_msg = result.stderr[:1000] if result.stderr else 'Unknown error'
                logger.error(f"Generation failed: {error_msg}")
                return {
                    'status': 200,  # Return 200 but with error in payload
                    'payload': {
                        'status': 'failed',
                        'error': error_msg,
                        'deleted_files': deleted_count
                    }
                }

        except subprocess.TimeoutExpired:
            logger.error("Generation timed out after 10 minutes")
            return {
                'status': 200,
                'payload': {
                    'status': 'timeout',
                    'error': 'Generation took longer than 10 minutes'
                }
            }

        except Exception as e:
            logger.exception("Unexpected error during generation")
            return {
                'status': 500,
                'payload': {
                    'status': 'error',
                    'error': str(e)
                }
            }

    def _parse_form(self, form_list):
        """
        Parse form data from request.

        Form data comes as list of [key, value] pairs.
        """
        if isinstance(form_list, dict):
            # Already a dict
            result = {}
            for k, v in form_list.items():
                result[k] = v[0] if isinstance(v, list) else v
            return result

        result = {}
        for item in form_list:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key, value = item[0], item[1]
                result[key] = value
        return result

    def _clean_output_directory(self, output_dir):
        """
        Delete all files in output subdirectories.

        Returns the number of files deleted.
        """
        subdirs = [
            'cloud', 'network', 'web', 'windows', 'linux',
            'retail', 'servicebus', 'itsm'
        ]
        deleted = 0

        for subdir in subdirs:
            path = os.path.join(output_dir, subdir)
            if os.path.exists(path):
                for f in glob.glob(os.path.join(path, '*')):
                    if os.path.isfile(f):
                        try:
                            os.remove(f)
                            deleted += 1
                        except OSError as e:
                            logger.warning(f"Could not delete {f}: {e}")

        return deleted
