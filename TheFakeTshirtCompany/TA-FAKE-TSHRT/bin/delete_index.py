#!/usr/bin/env python3
"""
REST handler for deleting and recreating the fake_tshrt index.

This handler uses PersistentServerConnectionApplication for proper REST support.

Endpoint: /services/ta_fake_tshrt/delete
Methods: GET (status), POST (delete/recreate)

POST Parameters:
  - confirm: Must be "true" to execute (safety check)
  - skip_inputs: If "true", don't disable/enable inputs (default: "false")
"""

import os
import sys
import json
import time
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
logger = logging.getLogger('delete_index')

# Splunk imports
try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
    import splunk.rest as rest
    HAS_SPLUNK = True
except ImportError:
    logger.warning("Running outside Splunk environment")
    HAS_SPLUNK = False
    PersistentServerConnectionApplication = object
    rest = None


class DeleteIndexHandler(PersistentServerConnectionApplication):
    """REST handler for index deletion and recreation using persistent connection."""

    INDEX_NAME = "fake_tshrt"
    APP_NAME = "TA-FAKE-TSHRT"

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
        Handle GET request - return current index status.
        """
        session_key = request.get('session', {}).get('authtoken')

        try:
            if rest and session_key:
                response, content = rest.simpleRequest(
                    f"/services/data/indexes/{self.INDEX_NAME}",
                    sessionKey=session_key,
                    method='GET',
                    getargs={'output_mode': 'json'}
                )

                if response.status == 200:
                    data = json.loads(content)
                    if data.get('entry'):
                        entry = data['entry'][0]
                        return {
                            'status': 200,
                            'payload': {
                                'status': 'exists',
                                'index_name': self.INDEX_NAME,
                                'total_event_count': entry.get('content', {}).get('totalEventCount', 0),
                                'current_db_size_mb': entry.get('content', {}).get('currentDBSizeMB', 0)
                            }
                        }

            return {
                'status': 200,
                'payload': {
                    'status': 'unknown',
                    'index_name': self.INDEX_NAME,
                    'message': 'Could not retrieve index info'
                }
            }

        except Exception as e:
            return {
                'status': 200,
                'payload': {
                    'status': 'error',
                    'error': str(e)
                }
            }

    def handle_post(self, request):
        """
        Handle POST request - delete and recreate index.
        """
        # Parse form data
        form_data = self._parse_form(request.get('form', []))

        # Safety check - must explicitly confirm
        confirm = form_data.get('confirm', 'false').lower()
        skip_inputs = form_data.get('skip_inputs', 'false').lower() == 'true'

        if confirm != 'true':
            return {
                'status': 200,
                'payload': {
                    'status': 'error',
                    'error': 'Must set confirm=true to delete index'
                }
            }

        session_key = request.get('session', {}).get('authtoken')

        if not session_key:
            return {
                'status': 401,
                'payload': {
                    'status': 'error',
                    'error': 'No session key available'
                }
            }

        result = {
            'inputs_disabled': 0,
            'inputs_enabled': 0
        }

        try:
            # Step 1: Disable inputs (optional)
            if not skip_inputs:
                disabled_count = self._toggle_inputs(session_key, disable=True)
                logger.info(f"Disabled {disabled_count} inputs")
                result['inputs_disabled'] = disabled_count

            # Step 2: Delete index
            delete_result = self._delete_index(session_key)
            if not delete_result:
                return {
                    'status': 200,
                    'payload': {
                        'status': 'failed',
                        'error': 'Failed to delete index'
                    }
                }

            logger.info(f"Deleted index {self.INDEX_NAME}")

            # Brief wait for deletion to complete
            time.sleep(2)

            # Step 3: Recreate index
            create_result = self._create_index(session_key)
            if not create_result:
                return {
                    'status': 200,
                    'payload': {
                        'status': 'failed',
                        'error': 'Failed to recreate index'
                    }
                }

            logger.info(f"Recreated index {self.INDEX_NAME}")

            # Step 4: Re-enable inputs (optional)
            if not skip_inputs:
                time.sleep(1)
                enabled_count = self._toggle_inputs(session_key, disable=False)
                logger.info(f"Re-enabled {enabled_count} inputs")
                result['inputs_enabled'] = enabled_count

            return {
                'status': 200,
                'payload': {
                    'status': 'success',
                    'message': f'Index {self.INDEX_NAME} deleted and recreated',
                    'inputs_disabled': result['inputs_disabled'],
                    'inputs_enabled': result['inputs_enabled']
                }
            }

        except Exception as e:
            logger.exception("Unexpected error during index deletion")
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

    def _toggle_inputs(self, session_key, disable=True):
        """Enable or disable all monitor inputs for this app.

        Returns the number of inputs toggled.
        """
        count = 0
        action = "disable" if disable else "enable"

        try:
            # Get list of monitor inputs for this app
            response, content = rest.simpleRequest(
                f"/servicesNS/nobody/{self.APP_NAME}/data/inputs/monitor",
                sessionKey=session_key,
                method='GET',
                getargs={'output_mode': 'json', 'count': 0}
            )

            if response.status != 200:
                logger.warning(f"Failed to get inputs list: {response.status}")
                return count

            data = json.loads(content)

            for entry in data.get('entry', []):
                input_name = entry.get('name', '')
                # Only toggle inputs that belong to our app
                if self.APP_NAME in input_name or 'output' in input_name:
                    try:
                        rest.simpleRequest(
                            f"/servicesNS/nobody/{self.APP_NAME}/data/inputs/monitor/{input_name}/{action}",
                            sessionKey=session_key,
                            method='POST'
                        )
                        count += 1
                    except Exception as e:
                        logger.warning(f"Failed to {action} input {input_name}: {e}")

        except Exception as e:
            logger.warning(f"Error toggling inputs: {e}")

        return count

    def _delete_index(self, session_key):
        """Delete the index.

        Returns True if successful or index doesn't exist.
        """
        try:
            response, _ = rest.simpleRequest(
                f"/services/data/indexes/{self.INDEX_NAME}",
                sessionKey=session_key,
                method='DELETE'
            )
            return response.status in [200, 404]  # 404 = already deleted
        except Exception as e:
            # Index might not exist, which is fine
            logger.warning(f"Delete index error (may be OK): {e}")
            return True

    def _create_index(self, session_key):
        """Recreate the index with default settings.

        Returns True if successful.
        """
        try:
            response, _ = rest.simpleRequest(
                "/services/data/indexes",
                sessionKey=session_key,
                method='POST',
                postargs={
                    'name': self.INDEX_NAME,
                    'homePath': f'$SPLUNK_DB/{self.INDEX_NAME}/db',
                    'coldPath': f'$SPLUNK_DB/{self.INDEX_NAME}/colddb',
                    'thawedPath': f'$SPLUNK_DB/{self.INDEX_NAME}/thaweddb',
                    'frozenTimePeriodInSecs': '2592000',  # 30 days
                    'maxDataSize': 'auto_high_volume'
                }
            )
            return response.status in [200, 201]
        except Exception as e:
            logger.error(f"Create index error: {e}")
            return False
