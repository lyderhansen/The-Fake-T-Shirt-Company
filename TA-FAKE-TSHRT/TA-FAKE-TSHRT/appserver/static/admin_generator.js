/**
 * Log Generator Dashboard JavaScript
 *
 *
 * This file handles all interactivity for the Log Generator dashboard.
 * Must be loaded via the dashboard script attribute, NOT inline <script> tags
 * (Splunk strips inline scripts from HTML panels).
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';

    console.log('[TA-FAKE-TSHRT] admin_generator.js loaded');

    var tokens = mvc.Components.get("default");

    // ========================================================================
    // Helper Functions
    // ========================================================================

    function setStatus(message, type) {
        var box = $('#status-box');
        box.removeClass('status-progress status-success status-error');
        box.addClass('status-' + type);
        box.text(message);
        box.show();
    }

    function setButtonsEnabled(enabled) {
        $('#generate-btn').prop('disabled', !enabled);
        $('#clean-btn').prop('disabled', !enabled);
    }

    function collectParams() {
        return {
            sources: tokens.get('sources') || 'all',
            days: tokens.get('days') || '14',
            scenarios: tokens.get('scenario_type') || 'exfil',
            start_date: tokens.get('start_date') || '2026-01-01',
            scale: tokens.get('scale') || '1.0',
            clients: $('#opt-clients').val() || '5',
            client_interval: $('#opt-client-interval').val() || '30',
            full_metrics: $('#opt-full-metrics').is(':checked') ? 'true' : 'false',
            orders_per_day: $('#opt-orders-per-day').val() || '224',
            meraki_health_interval: $('#opt-meraki-interval').val() || '5',
            no_mr_health: $('#opt-no-mr-health').is(':checked') ? 'true' : 'false',
            no_ms_health: $('#opt-no-ms-health').is(':checked') ? 'true' : 'false',
            parallel: $('#opt-parallel').val() || '4',
            output_mode: 'json'
        };
    }

    // ========================================================================
    // Generate Button Click Handler
    // ========================================================================

    $(document).on('click', '#generate-btn', function() {
        console.log('[TA-FAKE-TSHRT] Generate clicked');

        var params = collectParams();
        console.log('[TA-FAKE-TSHRT] Params:', params);

        var confirmMsg = 'This will:\n' +
            '1. Delete all existing log files\n' +
            '2. Generate ' + params.days + ' days of new logs\n' +
            '3. Sources: ' + params.sources + '\n' +
            '4. Scenarios: ' + params.scenarios + '\n\n' +
            'This may take several minutes. Continue?';

        if (!confirm(confirmMsg)) {
            console.log('[TA-FAKE-TSHRT] User cancelled');
            return;
        }

        setButtonsEnabled(false);
        setStatus('Starting log generation...\n\nSources: ' + params.sources +
                 '\nDays: ' + params.days +
                 '\nScenarios: ' + params.scenarios +
                 '\n\nPlease wait, this may take several minutes...', 'progress');

        var url = Splunk.util.make_url('/splunkd/__raw/services/ta_fake_tshrt/generate');
        console.log('[TA-FAKE-TSHRT] AJAX URL:', url);

        $.ajax({
            url: url,
            method: 'POST',
            data: params,
            timeout: 660000,  // 11 minute timeout
            success: function(response) {
                console.log('[TA-FAKE-TSHRT] Success:', response);
                var payload = response.payload || response;

                if (payload.status === 'success') {
                    setStatus('✅ SUCCESS!\n\n' +
                             'Message: ' + (payload.message || 'Logs generated') + '\n' +
                             'Files deleted: ' + (payload.deleted_files || 0) + '\n\n' +
                             'Output:\n' + (payload.output || '(none)'), 'success');
                } else {
                    setStatus('❌ FAILED\n\n' +
                             'Error: ' + (payload.error || 'Unknown error'), 'error');
                }
                setButtonsEnabled(true);
            },
            error: function(xhr, status, error) {
                console.log('[TA-FAKE-TSHRT] Error:', status, error, xhr.responseText);
                var errorMsg = 'Request failed';
                try {
                    var resp = JSON.parse(xhr.responseText);
                    errorMsg = resp.payload?.error || resp.messages?.[0]?.text || xhr.responseText;
                } catch(e) {
                    errorMsg = xhr.responseText || error || status;
                }
                setStatus('❌ ERROR\n\n' + errorMsg, 'error');
                setButtonsEnabled(true);
            }
        });
    });

    // ========================================================================
    // Clean Button Click Handler
    // ========================================================================

    $(document).on('click', '#clean-btn', function() {
        console.log('[TA-FAKE-TSHRT] Clean clicked');

        if (!confirm('This will delete all existing log files without generating new ones.\n\nContinue?')) {
            console.log('[TA-FAKE-TSHRT] User cancelled');
            return;
        }

        setButtonsEnabled(false);
        setStatus('Cleaning log files...', 'progress');

        var url = Splunk.util.make_url('/splunkd/__raw/services/ta_fake_tshrt/generate');

        $.ajax({
            url: url,
            method: 'POST',
            data: {
                clean_only: 'true',
                output_mode: 'json'
            },
            success: function(response) {
                console.log('[TA-FAKE-TSHRT] Clean success:', response);
                var payload = response.payload || response;
                if (payload.status === 'success') {
                    setStatus('✅ SUCCESS!\n\n' + (payload.message || 'Files cleaned'), 'success');
                } else {
                    setStatus('❌ FAILED\n\n' + (payload.error || 'Unknown error'), 'error');
                }
                setButtonsEnabled(true);
            },
            error: function(xhr, status, error) {
                console.log('[TA-FAKE-TSHRT] Clean error:', status, error);
                setStatus('❌ ERROR\n\n' + (xhr.responseText || error), 'error');
                setButtonsEnabled(true);
            }
        });
    });

    console.log('[TA-FAKE-TSHRT] Event handlers attached');
});
