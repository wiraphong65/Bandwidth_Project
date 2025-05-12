// JavaScript (bandwidth-control.js)

// --- State Management Object ---
const state = {
    activeView: "simple-queues", // Default view (can be set based on current page if needed)
    selectedItems: [],
    rules: [], // Will store rules fetched from API for the active interface
    searchQuery: "",
    currentBandwidth: { rx_bytes: 0, tx_bytes: 0 }, // For the active interface
    activeInterface: "", // Will be set by fetchInterfacesAndSetActive
    isEditingRule: false,
    editingRuleId: null,
    interfacesList: [] // Store the list of available interfaces
};

// --- DOM Elements (Global references, queried once after DOM is loaded) ---
let interfaceSelect, searchInput, rulesTableBody, selectAllCheckbox,
    downloadValueSpan, uploadValueSpan, noRulesMessageDiv,
    addRuleBtn, removeRulesBtn, enableRulesBtn, addFirstRuleBtn;

// Modal Elements
let ruleModal, modalTitle, ruleForm, closeModalBtn, cancelModalBtn,
    ruleIdInput, ruleDescriptionInput, ruleIpInput, ruleDirectionSelect,
    ruleRateValueInput, ruleRateUnitSelect,
    ruleBurstValueInput, ruleBurstUnitSelect, // For HTB Burst
    ruleCBurstValueInput, ruleCBurstUnitSelect, // For HTB Ceil (was Max Limit)
    ruleGroupNameInput, ruleProtocolSelect, ruleSourcePortInput,
    ruleDestinationPortInput, rulePriorityInput, ruleIsEnabledCheckbox,
    enableSchedulingCheckbox, schedulingOptionsDiv, ruleStartTimeInput,
    ruleEndTimeInput, ruleWeekdaysCheckboxes, ruleStartDateInput, ruleEndDateInput;

// User Message Area
let userMessageArea;


// --- Logging Helper (Simple Console Wrapper) ---
const appLogger = {
    debug: (...args) => console.debug("[BW_DEBUG]", ...args),
    info: (...args) => console.info("[BW_INFO]", ...args),
    warn: (...args) => console.warn("[BW_WARN]", ...args),
    error: (...args) => console.error("[BW_ERROR]", ...args),
};

// --- UI Message Function ---
function showUIMessage(message, type = "info", duration = 5000) {
    if (!userMessageArea) { // Fallback if userMessageArea is not found
        alert(`${type.toUpperCase()}: ${message}`);
        return;
    }
    userMessageArea.textContent = message;
    // Basic styling, can be enhanced with CSS classes for different types
    userMessageArea.className = `app-message alert alert-${type}`; // Assuming Bootstrap-like classes
    userMessageArea.style.display = 'block';
    userMessageArea.style.position = 'fixed';
    userMessageArea.style.top = '20px';
    userMessageArea.style.left = '50%';
    userMessageArea.style.transform = 'translateX(-50%)';
    userMessageArea.style.zIndex = '2000';
    userMessageArea.style.padding = '10px 20px';
    userMessageArea.style.borderRadius = '5px';
    userMessageArea.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';

    if (type === "success") userMessageArea.style.backgroundColor = "#d4edda";
    else if (type === "error") userMessageArea.style.backgroundColor = "#f8d7da";
    else if (type === "warning") userMessageArea.style.backgroundColor = "#fff3cd";
    else userMessageArea.style.backgroundColor = "#e2e3e5"; // info or default

    if (duration > 0) {
        setTimeout(() => {
            userMessageArea.style.display = 'none';
            userMessageArea.textContent = '';
            userMessageArea.className = 'app-message'; // Reset classes
        }, duration);
    }
}


// --- API Call Functions ---
async function fetchApi(url, options = {}) {
    appLogger.debug(`Workspaceing API: ${options.method || 'GET'} ${url}`, options.body ? JSON.parse(options.body) : '');
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            let errorText = `Server error: ${response.status} ${response.statusText}`;
            let errorJson = null;
            try {
                errorJson = await response.json();
                errorText = errorJson.error || errorJson.message || errorText;
            } catch (e) {
                const rawText = await response.text();
                console.error("Server returned non-JSON error content:", rawText.substring(0, 500));
                if (rawText.toLowerCase().includes("<!doctype html")) {
                    errorText = `Server error ${response.status}: Received HTML page instead of JSON. Check server logs.`;
                } else {
                    errorText = `Server error ${response.status}: ${rawText.substring(0,100)}...`;
                }
            }
            appLogger.error(`API Error for ${url}:`, errorText, errorJson);
            throw new Error(errorText);
        }
        // Handle cases where server responds with 204 No Content (e.g. DELETE)
        if (response.status === 204) {
            return null; // Or some other indicator of success with no body
        }
        return await response.json();
    } catch (error) {
        appLogger.error(`Workspace API Exception for ${url}:`, error);
        throw error; // Re-throw to be caught by the caller
    }
}


async function fetchInterfacesAndSetActive() {
    appLogger.info("Fetching interfaces and active interface...");
    try {
        const data = await fetchApi('/api/interfaces');
        appLogger.debug("Interfaces API Response:", data);

        if (!interfaceSelect) {
            appLogger.error("Interface select DOM element (#interface) not found.");
            state.activeInterface = ""; // Prevent further errors
        } else {
            interfaceSelect.innerHTML = ''; // Clear existing options
            state.interfacesList = data.interfaces || [];

            if (state.interfacesList.length > 0) {
                state.interfacesList.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    interfaceSelect.appendChild(option);
                });

                let newActiveInterface = null;
                if (data.active_interface && state.interfacesList.includes(data.active_interface)) {
                    newActiveInterface = data.active_interface;
                } else if (state.interfacesList.length > 0) {
                    newActiveInterface = state.interfacesList[0]; // Default to first if current active is invalid or none
                }

                if (newActiveInterface) {
                    state.activeInterface = newActiveInterface;
                    interfaceSelect.value = newActiveInterface; // Set dropdown to this value
                    // If backend's active_interface was null/invalid and we defaulted, inform backend
                    if (newActiveInterface !== data.active_interface) {
                        appLogger.info(`Active interface defaulted to '${newActiveInterface}', informing backend.`);
                        await setActiveInterfaceOnBackend(newActiveInterface);
                    }
                } else {
                    state.activeInterface = "";
                     const option = document.createElement('option');
                    option.value = "";
                    option.textContent = "No interfaces available";
                    interfaceSelect.appendChild(option);
                }
            } else {
                const option = document.createElement('option');
                option.value = "";
                option.textContent = "No interfaces found";
                interfaceSelect.appendChild(option);
                state.activeInterface = "";
            }
        }
    } catch (error) {
        appLogger.error("Error in fetchInterfacesAndSetActive:", error.message);
        showUIMessage(`Error loading interfaces: ${error.message}`, "error");
        if (interfaceSelect) interfaceSelect.innerHTML = '<option value="">Error loading</option>';
        state.activeInterface = "";
    } finally {
        // These should always run, and handle empty activeInterface gracefully
        await fetchRules(state.activeInterface);
        startBandwidthPolling();
        updateButtonStates(); // Ensure buttons reflect initial state
    }
}

async function setActiveInterfaceOnBackend(interfaceName) {
    appLogger.info(`Setting active interface on backend to: ${interfaceName}`);
    try {
        const result = await fetchApi('/api/set_active_interface', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface_name: interfaceName })
        });
        appLogger.debug("Backend setActiveInterface response:", result ? result.message : "No content");
    } catch (error) {
        appLogger.error("Error setting active interface on backend:", error.message);
        showUIMessage(`Could not switch interface on backend: ${error.message}`, "error");
        // Optionally revert dropdown if backend fails, or rely on next fetchInterfaces to correct
        if (interfaceSelect && state.interfacesList.length > 0) {
             interfaceSelect.value = state.activeInterface; // Revert to last known good active interface
        }
    }
}

async function fetchRules(interfaceName) {
    appLogger.info(`Workspaceing rules for interface: '${interfaceName || "none"}'`);
    if (!interfaceName) { // If interfaceName is empty, null, or undefined
        state.rules = [];
        renderRules(); // Will show "Please select an interface" or similar
        return;
    }
    if (noRulesMessageDiv) noRulesMessageDiv.style.display = 'none';
    const loadingMsg = document.getElementById('loading-rules-message');
    if (loadingMsg) loadingMsg.style.display = 'block';

    try {
        const data = await fetchApi(`/api/rules/${interfaceName}`);
        state.rules = Array.isArray(data) ? data : [];
        appLogger.debug(`Workspaceed ${state.rules.length} rules for ${interfaceName}:`, state.rules);
    } catch (error) {
        appLogger.error(`Error fetching rules for ${interfaceName}:`, error.message);
        showUIMessage(`Error fetching rules: ${error.message}`, "error");
        state.rules = [];
    } finally {
        if (loadingMsg) loadingMsg.style.display = 'none';
        renderRules();
        state.selectedItems = []; // Clear selection when rules are re-fetched
        if (selectAllCheckbox) selectAllCheckbox.checked = false;
        updateButtonStates();
    }
}

async function fetchBandwidthStats(interfaceName) {
    // appLogger.debug(`Workspaceing bandwidth stats for interface: ${interfaceName}`); // Can be too noisy
    if (!interfaceName) {
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        updateBandwidthDisplay();
        return;
    }
    try {
        const data = await fetchApi(`/api/bandwidth_usage/${interfaceName}`);
        state.currentBandwidth = {
            rx_bytes: data.rx_bytes || 0,
            tx_bytes: data.tx_bytes || 0
        };
    } catch (error) {
        // appLogger.warn(`Error fetching bandwidth for ${interfaceName}:`, error.message); // Also can be noisy
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 }; // Reset on error
    }
    updateBandwidthDisplay();
}

// --- Helper to Parse Rate Strings (e.g., "10Mbps" -> ["10", "Mbps"]) ---
function parseRateStringForForm(rateStr) {
    if (!rateStr || typeof rateStr !== 'string') return [null, null];
    const match = rateStr.match(/^(\d*\.?\d+)\s*([a-zA-Z/]+)$/); // Allow '/' for KB/s etc.
    if (match && match.length === 3) {
        return [match[1], match[2]]; // Value, Unit
    }
    return [rateStr, null]; // Fallback if no unit found, return original string as value
}


// --- Event Handlers & Modal Logic ---
function openRuleModal(ruleToEdit = null) {
    if (!ruleModal || !ruleForm) {
        appLogger.error("Modal elements not fully initialized. Cannot open modal.");
        showUIMessage("Error: Modal components are missing. Please refresh.", "error");
        return;
    }
    ruleForm.reset(); // Reset form for new or edit
    
    if (enableSchedulingCheckbox) enableSchedulingCheckbox.checked = false;
    if (schedulingOptionsDiv) schedulingOptionsDiv.style.display = 'none'; // Ensure it's hidden initially
    if (ruleWeekdaysCheckboxes) ruleWeekdaysCheckboxes.forEach(cb => cb.checked = false);

    if (ruleToEdit && typeof ruleToEdit === 'object') { // ruleToEdit is an object from state.rules
        state.isEditingRule = true;
        state.editingRuleId = String(ruleToEdit.id); // Ensure ID is string for consistency
        if (modalTitle) modalTitle.textContent = `Edit Rule (ID: ${ruleToEdit.id})`;
        if (ruleIdInput) ruleIdInput.value = ruleToEdit.id;

        if (ruleDescriptionInput) ruleDescriptionInput.value = ruleToEdit.name || ''; // 'name' from rule_model_to_dict
        if (ruleIpInput) ruleIpInput.value = ruleToEdit.target || '';
        if (ruleDirectionSelect) ruleDirectionSelect.value = ruleToEdit.direction || 'download';

        // Main Rate
        const [rateVal, rateUnit] = parseRateStringForForm(ruleToEdit.rate);
        if (ruleRateValueInput) ruleRateValueInput.value = rateVal || '';
        if (ruleRateUnitSelect && rateUnit) ruleRateUnitSelect.value = rateUnit.toLowerCase();
        else if (ruleRateUnitSelect) ruleRateUnitSelect.value = 'mbps'; // Default if no unit

        // Burst (Max Limit in old UI, now more specific) for HTB
        const [burstVal, burstUnit] = parseRateStringForForm(ruleToEdit.burst_str_db); // Use specific field from backend
        if (ruleBurstValueInput) ruleBurstValueInput.value = burstVal || '';
        if (ruleBurstUnitSelect && burstUnit) ruleBurstUnitSelect.value = burstUnit.toLowerCase();
        else if (ruleBurstUnitSelect) ruleBurstUnitSelect.value = ''; // Default to no unit for burst

        // Ceil (CBurst in old UI) for HTB
        const [ceilVal, ceilUnit] = parseRateStringForForm(ruleToEdit.ceil_str_db); // Use specific field
        if (ruleCBurstValueInput) ruleCBurstValueInput.value = ceilVal || '';
        if (ruleCBurstUnitSelect && ceilUnit) ruleCBurstUnitSelect.value = ceilUnit.toLowerCase();
        else if (ruleCBurstUnitSelect) ruleCBurstUnitSelect.value = ''; // Default to no unit

        if (ruleGroupNameInput) ruleGroupNameInput.value = ruleToEdit.group_name || '';
        if (ruleProtocolSelect) ruleProtocolSelect.value = ruleToEdit.protocol || '';
        if (ruleSourcePortInput) ruleSourcePortInput.value = ruleToEdit.source_port || '';
        if (ruleDestinationPortInput) ruleDestinationPortInput.value = ruleToEdit.destination_port || '';
        if (rulePriorityInput) rulePriorityInput.value = ruleToEdit.priority !== null ? ruleToEdit.priority : '';
        
        // Use raw_is_enabled_flag from backend to set the checkbox state
        if (ruleIsEnabledCheckbox) ruleIsEnabledCheckbox.checked = ruleToEdit.raw_is_enabled_flag !== undefined ? ruleToEdit.raw_is_enabled_flag : true;

        // Scheduling fields
        if (ruleToEdit.is_scheduled && enableSchedulingCheckbox && schedulingOptionsDiv) {
            enableSchedulingCheckbox.checked = true;
            schedulingOptionsDiv.style.display = 'block';
            if (ruleStartTimeInput) ruleStartTimeInput.value = ruleToEdit.start_time || '';
            if (ruleEndTimeInput) ruleEndTimeInput.value = ruleToEdit.end_time || '';
            if (ruleStartDateInput) ruleStartDateInput.value = ruleToEdit.start_date || '';
            if (ruleEndDateInput) ruleEndDateInput.value = ruleToEdit.end_date || '';
            const weekdays = (ruleToEdit.weekdays || "").split(',');
            if (ruleWeekdaysCheckboxes) {
                ruleWeekdaysCheckboxes.forEach(cb => {
                    cb.checked = weekdays.includes(cb.value);
                });
            }
        }
    } else { // Adding new rule
        state.isEditingRule = false;
        state.editingRuleId = null;
        if (modalTitle) modalTitle.textContent = 'Add New Rule';
        if (ruleIdInput) ruleIdInput.value = '';
        if (ruleIsEnabledCheckbox) ruleIsEnabledCheckbox.checked = true; // Default to enabled
        // Set default units if desired
        if (ruleRateUnitSelect) ruleRateUnitSelect.value = 'mbps';
        if (ruleBurstUnitSelect) ruleBurstUnitSelect.value = 'kbit'; // TC burst often uses kbit/mbit or k/m for bytes
        if (ruleCBurstUnitSelect) ruleCBurstUnitSelect.value = 'mbps'; // TC ceil like rate
    }
    if (ruleModal) ruleModal.style.display = 'block';
}


async function handleSaveRule(event) {
    event.preventDefault();
    if (!ruleForm) { appLogger.error("Rule form not found in handleSaveRule"); return; }
    if (!state.activeInterface || typeof state.activeInterface !== 'string' || state.activeInterface.trim() === '') {
        appLogger.error("handleSaveRule: Active interface is not set or invalid:", state.activeInterface);
        showUIMessage("Error: No active network interface selected. Please select an interface before saving a rule.", "error");
        return;
    }

    // --- Client-side basic validation ---
    const ipAddr = ruleIpInput ? ruleIpInput.value.trim() : '';
    const rateVal = ruleRateValueInput ? ruleRateValueInput.value.trim() : '';
    const rateUnit = ruleRateUnitSelect ? ruleRateUnitSelect.value : '';

    if (!ipAddr || !rateVal || !rateUnit) {
        showUIMessage('Target IP, Rate Value, and Rate Unit are required.', "error");
        return;
    }
    // Basic IP regex (more robust validation on backend)
    if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ipAddr) && !/^[0-9a-fA-F:]{3,}$/.test(ipAddr) /* Basic IPv6 check */) {
        showUIMessage('Invalid IP Address format.', "error");
        return;
    }
    if (isNaN(parseFloat(rateVal)) || parseFloat(rateVal) <= 0) {
        showUIMessage('Rate Value must be a positive number.', "error");
        return;
    }
    // --- End Client-side basic validation ---


    const selectedWeekdays = [];
    if (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleWeekdaysCheckboxes) {
        ruleWeekdaysCheckboxes.forEach(checkbox => {
            if (checkbox.checked) selectedWeekdays.push(checkbox.value);
        });
        // No longer making weekdays mandatory if scheduling is enabled, backend can decide default
    }

    // Construct payload based on backend expectations (app.py set_bandwidth_limit)
    const ruleDataPayload = {
        // Fields expected by set_bandwidth_limit in app.py
        ip: ipAddr,
        rate_value_form: rateVal,
        rate_unit_form: rateUnit,
        direction: ruleDirectionSelect ? ruleDirectionSelect.value : 'download',
        group_name: ruleGroupNameInput ? (ruleGroupNameInput.value.trim() || null) : null,
        protocol: ruleProtocolSelect ? (ruleProtocolSelect.value || null) : null,
        source_port: ruleSourcePortInput ? (ruleSourcePortInput.value.trim() || null) : null,
        destination_port: ruleDestinationPortInput ? (ruleDestinationPortInput.value.trim() || null) : null,
        description: ruleDescriptionInput ? ruleDescriptionInput.value.trim() : '',
        is_enabled: ruleIsEnabledCheckbox ? ruleIsEnabledCheckbox.checked : true,
        priority_form_str: rulePriorityInput && rulePriorityInput.value.trim() ? rulePriorityInput.value.trim() : null,
        
        burst_value_form: ruleBurstValueInput && ruleBurstValueInput.value.trim() ? ruleBurstValueInput.value.trim() : null,
        burst_unit_form: ruleBurstValueInput && ruleBurstValueInput.value.trim() && ruleBurstUnitSelect ? ruleBurstUnitSelect.value : null,
        
        cburst_value_form: ruleCBurstValueInput && ruleCBurstValueInput.value.trim() ? ruleCBurstValueInput.value.trim() : null,
        cburst_unit_form: ruleCBurstValueInput && ruleCBurstValueInput.value.trim() && ruleCBurstUnitSelect ? ruleCBurstUnitSelect.value : null,

        is_scheduled: enableSchedulingCheckbox ? enableSchedulingCheckbox.checked : false,
        start_time: (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleStartTimeInput) ? ruleStartTimeInput.value : null,
        end_time: (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleEndTimeInput) ? ruleEndTimeInput.value : null,
        weekdays: (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && selectedWeekdays.length > 0) ? selectedWeekdays.join(',') : null,
        start_date: (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleStartDateInput) ? (ruleStartDateInput.value || null) : null,
        end_date: (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleEndDateInput) ? (ruleEndDateInput.value || null) : null,
    };

    // Add existing_rule_id_to_update if editing
    if (state.isEditingRule && state.editingRuleId) {
        ruleDataPayload.existing_rule_id_to_update = state.editingRuleId;
        // `overwrite` flag in set_bandwidth_limit is used differently,
        // for new rules that might conflict. For updates, existing_rule_id_to_update signals an update.
        // Backend's set_bandwidth_limit needs to handle this.
        appLogger.info("Preparing to update rule:", ruleDataPayload);
    } else {
        appLogger.info("Preparing to add new rule:", ruleDataPayload);
        // For new rules, explicitly set overwrite if you want that behavior for conflicts
        // ruleDataPayload.overwrite = true; // Or false, depending on desired default
    }

    const apiUrl = `/api/rules/${state.activeInterface.trim()}`; // For add, this is POST
                                                                 // For update, your backend needs to handle POST to this URL with existing_rule_id_to_update
                                                                 // OR you might have a different URL for PUT e.g. /api/rules/<iface>/<rule_id>
    const apiMethod = 'POST'; // Assuming your backend /api/rules/<iface> POST handles both add and update based on payload.

    try {
        const data = await fetchApi(apiUrl, {
            method: apiMethod,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ruleDataPayload)
        });
        showUIMessage(data.message || (state.isEditingRule ? "Rule updated successfully!" : "Rule added successfully!"), "success");
        if (ruleModal) ruleModal.style.display = 'none';
        await fetchRules(state.activeInterface); // Refresh rules list
    } catch (error) {
        appLogger.error('Error saving/updating rule:', error.message);
        showUIMessage(`Error: ${error.message}`, "error");
    }
}

async function handleRemoveRules() {
    if (state.selectedItems.length === 0) {
        showUIMessage("No rules selected to remove.", "info");
        return;
    }
    if (!state.activeInterface) {
         showUIMessage("No active interface selected.", "error"); return;
    }
    if (!confirm(`Are you sure you want to remove ${state.selectedItems.length} selected rule(s)? This cannot be undone.`)) {
        return;
    }

    const originalButtonText = removeRulesBtn ? removeRulesBtn.innerHTML : 'Deleting...';
    if (removeRulesBtn) {
        removeRulesBtn.innerHTML = 'Deleting...';
        removeRulesBtn.disabled = true;
    }

    const deletionPromises = state.selectedItems.map(ruleId =>
        fetchApi(`/api/rules/${state.activeInterface}/${ruleId}`, { method: 'DELETE' })
            .then(data => ({ success: true, ruleId, message: data ? data.message : "Deleted" })) // data might be null on 204
            .catch(error => ({ success: false, ruleId, error: error.message || "Unknown error" }))
    );

    try {
        const results = await Promise.all(deletionPromises);
        const successfulDeletes = results.filter(r => r.success).length;
        const failedDeletes = results.filter(r => !r.success);

        if (failedDeletes.length > 0) {
            const errorMessages = failedDeletes.map(f => `Rule ID ${f.ruleId}: ${f.error}`).join('\n');
            showUIMessage(`Successfully deleted ${successfulDeletes} rule(s).\nFailed to delete ${failedDeletes.length} rule(s):\n${errorMessages}`, "warning");
        } else if (successfulDeletes > 0) {
            showUIMessage(`${successfulDeletes} rule(s) deleted successfully.`, "success");
        } else {
            showUIMessage("No rules were deleted (perhaps they were already gone or an unknown error occurred).", "info");
        }
        appLogger.info("Selected rules deletion process completed.");
    } catch (error) { // Should not be reached if individual promises catch
        appLogger.error("Unexpected error during batch rule deletion:", error);
        showUIMessage("An unexpected error occurred during batch deletion.", "error");
    } finally {
        if (removeRulesBtn) removeRulesBtn.innerHTML = originalButtonText;
        // Re-enable will be handled by updateButtonStates after fetching rules
        state.selectedItems = []; // Clear selection
        if (selectAllCheckbox) selectAllCheckbox.checked = false;
        await fetchRules(state.activeInterface); // Refresh and this will call updateButtonStates
    }
}

async function handleEnableRules() { // Toggle enabled state
    if (state.selectedItems.length === 0) {
        showUIMessage("No rules selected to toggle.", "info");
        return;
    }
     if (!state.activeInterface) {
         showUIMessage("No active interface selected.", "error"); return;
    }
    const originalButtonText = enableRulesBtn ? enableRulesBtn.innerHTML : 'Toggling...';
    if (enableRulesBtn) {
        enableRulesBtn.innerHTML = 'Toggling...';
        enableRulesBtn.disabled = true;
    }

    const togglePromises = state.selectedItems.map(ruleId =>
        fetchApi(`/api/rules/${state.activeInterface}/${ruleId}/toggle`, { method: 'POST' })
            .then(data => ({ success: true, ruleId, updatedRule: data }))
            .catch(error => ({ success: false, ruleId, error: error.message || "Unknown error" }))
    );
    try {
        const results = await Promise.all(togglePromises);
        const successfulToggles = results.filter(r => r.success).length;
        const failedToggles = results.filter(r => !r.success);

        if (failedToggles.length > 0) {
             const errorMessages = failedToggles.map(f => `Rule ID ${f.ruleId}: ${f.error}`).join('\n');
            showUIMessage(`Successfully toggled ${successfulToggles} rule(s).\nFailed to toggle ${failedToggles.length} rule(s):\n${errorMessages}`, "warning");
        } else if (successfulToggles > 0) {
            showUIMessage(`${successfulToggles} rule(s) toggled successfully.`, "success");
        } else {
            showUIMessage("No rules were toggled (perhaps an unknown error occurred).", "info");
        }
        appLogger.info("Selected rules toggle process completed.");
    } catch (error) {
        appLogger.error("Error during batch rule toggle:", error);
        showUIMessage("An unexpected error occurred during batch toggle.", "error");
    } finally {
        if (enableRulesBtn) enableRulesBtn.innerHTML = originalButtonText;
        await fetchRules(state.activeInterface); // Refresh to show new statuses
    }
}

async function handleInterfaceChange(e) {
    const newInterface = e.target.value;
    if (newInterface === state.activeInterface) return; // No change if same or still empty
    
    appLogger.info(`Interface selection changed to: '${newInterface}'`);
    if (!newInterface) { // User selected "No interfaces found" or an empty option
        state.activeInterface = "";
        state.rules = [];
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        renderRules();
        updateBandwidthDisplay();
        updateButtonStates();
        stopBandwidthPolling();
        return;
    }
    // Set on backend, then update state and fetch data
    await setActiveInterfaceOnBackend(newInterface); 
    state.activeInterface = newInterface; // Update local state after successful backend update (or assume success for now)
    await fetchRules(state.activeInterface);
    startBandwidthPolling();
}

function handleSearch(e) {
    state.searchQuery = e.target.value.toLowerCase().trim();
    renderRules();
}

function handleSelectAll(e) {
    if (!rulesTableBody) return;
    const isChecked = e.target.checked;
    const visibleRuleCheckboxes = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox');
    
    state.selectedItems = []; // Reset before re-populating if selecting all
    visibleRuleCheckboxes.forEach(checkbox => {
        checkbox.checked = isChecked;
        if (isChecked) {
            state.selectedItems.push(checkbox.value); // value should be rule.id
        }
    });
    updateButtonStates();
    appLogger.debug("Selected items after Select All/None:", state.selectedItems);
}

function handleRuleSelect(e) {
    const ruleIdStr = String(e.target.value); // Assuming checkbox value is rule.id
    if (e.target.checked) {
        if (!state.selectedItems.includes(ruleIdStr)) {
            state.selectedItems.push(ruleIdStr);
        }
    } else {
        state.selectedItems = state.selectedItems.filter(id => id !== ruleIdStr);
    }

    if (selectAllCheckbox && rulesTableBody) {
        const allVisibleCheckboxes = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox');
        const allVisibleAndChecked = Array.from(allVisibleCheckboxes).every(cb => cb.checked);
        selectAllCheckbox.checked = allVisibleCheckboxes.length > 0 && allVisibleAndChecked;
    }
    updateButtonStates();
    appLogger.debug("Selected items:", state.selectedItems);
}

function toggleSchedulingOptions() {
    if (enableSchedulingCheckbox && schedulingOptionsDiv) {
        schedulingOptionsDiv.style.display = enableSchedulingCheckbox.checked ? 'block' : 'none';
    } else {
        appLogger.warn("Scheduling toggle elements not found in toggleSchedulingOptions.");
    }
}

// --- Rendering Functions ---
function renderRules() {
    if (!rulesTableBody) {
        appLogger.error("Rules table body (#rules-body) not found. Cannot render rules.");
        if (noRulesMessageDiv) {
             noRulesMessageDiv.textContent = "Error: Table body component not found on page.";
             noRulesMessageDiv.style.display = 'block';
        }
        if (addFirstRuleBtn) addFirstRuleBtn.style.display = 'none';
        return;
    }
    rulesTableBody.innerHTML = '';

    const filteredRules = state.rules.filter(rule => {
        const search = state.searchQuery;
        if (!search) return true;
        // Ensure all fields being searched actually exist on the rule object
        return (rule.name && rule.name.toLowerCase().includes(search)) ||
               (rule.target && rule.target.toLowerCase().includes(search)) ||
               (rule.rate && rule.rate.toLowerCase().includes(search)) ||
               (rule.direction && rule.direction.toLowerCase().includes(search)) ||
               (rule.group_name && rule.group_name.toLowerCase().includes(search)) ||
               (rule.protocol && rule.protocol.toLowerCase().includes(search)) ||
               (rule.source_port && String(rule.source_port).includes(search)) ||
               (rule.destination_port && String(rule.destination_port).includes(search));
    });

    if (noRulesMessageDiv) noRulesMessageDiv.style.display = 'none';
    if (addFirstRuleBtn) addFirstRuleBtn.style.display = 'none';

    if (filteredRules.length === 0) {
        if (noRulesMessageDiv) {
            let msg = "Please select an interface to view or add rules.";
            if (state.activeInterface) {
                msg = state.searchQuery ? "No rules match your search criteria." : "No rules defined for this interface. Click 'Add Rule' to get started!";
                if (!state.searchQuery && addFirstRuleBtn) {
                    addFirstRuleBtn.style.display = 'inline-block';
                }
            }
            noRulesMessageDiv.innerHTML = `<img src="https://cdn.builder.io/api/v1/image/assets/TEMP/empty-box-placeholder.png?placeholder=true" alt="No rules" class="empty-state-icon"><p class="empty-state-text">${msg}</p>`;
            noRulesMessageDiv.style.display = 'block';
        }
    } else {
        filteredRules.forEach(rule => { // rule is an object from API (based on rule_model_to_dict_for_frontend)
            const row = rulesTableBody.insertRow();
            row.dataset.ruleId = rule.id; // rule.id should be a string already from backend
            if (!rule.enabled) { // 'enabled' is the *functional* status from backend
                row.classList.add('rule-disabled-visual'); // For visual styling
            }

            // Checkbox
            const checkboxCell = row.insertCell();
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'rule-checkbox';
            checkbox.value = String(rule.id); // Ensure value is string
            checkbox.checked = state.selectedItems.includes(String(rule.id));
            checkbox.addEventListener('change', handleRuleSelect); // Pass event, ruleId derived from e.target.value
            checkboxCell.appendChild(checkbox);
            checkboxCell.classList.add("checkbox-column");

            row.insertCell().textContent = rule.name || 'N/A';
            row.insertCell().textContent = rule.target || 'N/A';
            row.insertCell().textContent = rule.direction ? rule.direction.charAt(0).toUpperCase() + rule.direction.slice(1) : 'N/A';
            row.insertCell().textContent = rule.rate || 'N/A';
            // Use specific ceil/max limit field if available from backend
            row.insertCell().textContent = rule.ceil_str_db || rule.maxLimit || rule.rate || 'N/A';
            row.insertCell().textContent = rule.group_name || '-';
            
            const statusCell = row.insertCell();
            const statusIndicator = document.createElement('span');
            statusIndicator.className = `status-indicator ${rule.enabled ? 'status-enabled' : 'status-disabled'}`;
            statusIndicator.title = rule.enabled ? 'Active' : 'Inactive';
            statusCell.appendChild(statusIndicator);
            statusCell.appendChild(document.createTextNode(rule.enabled ? ' Active' : ' Inactive'));
            
            // Adding more details about disabled status based on raw_is_enabled_flag
            if (rule.raw_is_enabled_flag === false) {
                const disabledByUserText = document.createElement('span');
                disabledByUserText.textContent = ' (User Disabled)';
                disabledByUserText.style.fontSize = '0.8em';
                disabledByUserText.style.color = '#7f8c8d';
                statusCell.appendChild(disabledByUserText);
            } else if (rule.is_scheduled && !rule.enabled) { // Scheduled but currently outside active time
                const scheduledOffText = document.createElement('span');
                scheduledOffText.textContent = ' (Scheduled Off)';
                scheduledOffText.style.fontSize = '0.8em';
                scheduledOffText.style.color = '#7f8c8d';
                statusCell.appendChild(scheduledOffText);
            }


            const scheduledInfoCell = row.insertCell();
            if (rule.is_scheduled) {
                let schText = `${rule.start_time || '?'} - ${rule.end_time || '?'}`;
                if (rule.weekdays) schText += ` (${rule.weekdays.split(',').map(d=>d.substring(0,3)).join(',')})`;
                else schText += ` (Daily)`;
                if (rule.start_date || rule.end_date) {
                     schText += ` [${rule.start_date || '*'} to ${rule.end_date || '*'}]`;
                }
                scheduledInfoCell.textContent = schText.substring(0, 30) + (schText.length > 30 ? '...' : ''); // Truncate
                scheduledInfoCell.title = `Scheduled: ${rule.start_time}-${rule.end_time}, Days: ${rule.weekdays || 'Any'}, Dates: ${rule.start_date || 'Always'} to ${rule.end_date || 'Always'}`;
            } else {
                scheduledInfoCell.textContent = '-';
            }

            const actionsCell = row.insertCell();
            actionsCell.classList.add("actions-column");
            const editButton = document.createElement('button');
            editButton.textContent = 'Edit';
            editButton.className = 'button button-secondary button-sm action-button-inline edit-rule-btn-inline';
            editButton.title = `Edit rule: ${rule.name || rule.target}`;
            editButton.addEventListener('click', () => openRuleModal(rule)); // Pass the whole rule object
            actionsCell.appendChild(editButton);
        });
    }

    if (selectAllCheckbox) {
        const allVisibleCheckboxes = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox');
        const allVisibleAndChecked = allVisibleCheckboxes.length > 0 && Array.from(allVisibleCheckboxes).every(cb => cb.checked);
        selectAllCheckbox.checked = allVisibleAndChecked;
    }
    updateButtonStates();
}

function updateButtonStates() {
    const hasSelection = state.selectedItems.length > 0;
    if (removeRulesBtn) removeRulesBtn.disabled = !hasSelection;
    if (enableRulesBtn) enableRulesBtn.disabled = !hasSelection;
    // AddRuleBtn is always enabled if an interface is selected
    if (addRuleBtn) addRuleBtn.disabled = !state.activeInterface;
    if (addFirstRuleBtn) addFirstRuleBtn.disabled = !state.activeInterface;
}

function updateBandwidthDisplay() {
    if (downloadValueSpan) {
        downloadValueSpan.textContent = formatBytesForBandwidth(state.currentBandwidth.rx_bytes, 2, true) + "/s";
    }
    if (uploadValueSpan) {
        uploadValueSpan.textContent = formatBytesForBandwidth(state.currentBandwidth.tx_bytes, 2, true) + "/s";
    }
}

function formatBytesForBandwidth(bytes, decimals = 2, isRate = false) {
    if (bytes === null || bytes === undefined || isNaN(parseFloat(bytes)) || !isFinite(bytes)) return '0 ' + (isRate ? 'bps' : 'B');
    if (bytes === 0) return '0 ' + (isRate ? 'bps' : 'B');

    const k = isRate ? 1000 : 1024; // Use 1000 for network speeds (kbps, Mbps), 1024 for storage (KB, MB)
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = isRate ? ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'] : ['B', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(Math.abs(bytes * (isRate ? 8 : 1))) / Math.log(k)); // Convert to bits for rate calculation if 'bytes' is in bytes
    const value = parseFloat(((bytes * (isRate ? 8 : 1)) / Math.pow(k, i)).toFixed(dm));
    
    return value + ' ' + sizes[i];
}


// --- Bandwidth Polling ---
let bandwidthIntervalId = null;
const POLLING_INTERVAL = 5000; // 5 seconds

function startBandwidthPolling() {
    stopBandwidthPolling(); // Clear existing before starting new
    if (state.activeInterface) {
        appLogger.info(`Starting bandwidth polling for interface: ${state.activeInterface}`);
        fetchBandwidthStats(state.activeInterface); // Initial fetch
        bandwidthIntervalId = setInterval(() => {
            if (state.activeInterface) {
                fetchBandwidthStats(state.activeInterface);
            } else {
                stopBandwidthPolling(); // Interface became invalid/none
            }
        }, POLLING_INTERVAL);
    } else {
        appLogger.info("No active interface; bandwidth polling not started.");
        updateBandwidthDisplay(); // Ensure display is reset
    }
}

function stopBandwidthPolling() {
    if (bandwidthIntervalId !== null) {
        clearInterval(bandwidthIntervalId);
        bandwidthIntervalId = null;
        appLogger.info("Stopped bandwidth polling.");
    }
}


// --- Initialization ---
function queryGlobalDOMElements() {
    interfaceSelect = document.getElementById('interface');
    searchInput = document.getElementById('search-input');
    rulesTableBody = document.getElementById('rules-body');
    selectAllCheckbox = document.getElementById('select-all');
    downloadValueSpan = document.getElementById('download-value');
    uploadValueSpan = document.getElementById('upload-value');
    noRulesMessageDiv = document.getElementById('no-rules-message');
    addRuleBtn = document.getElementById('add-rule-btn');
    addFirstRuleBtn = document.getElementById('add-first-rule-btn');
    removeRulesBtn = document.getElementById('remove-rules-btn');
    enableRulesBtn = document.getElementById('enable-rules-btn');
    userMessageArea = document.getElementById('user-messages'); // Assuming you add this div to your HTML

    // Modal elements
    ruleModal = document.getElementById('rule-modal');
    modalTitle = document.getElementById('modal-title-text'); // Corrected ID if used
    ruleForm = document.getElementById('rule-form');
    closeModalBtn = document.getElementById('close-modal-btn');
    cancelModalBtn = document.getElementById('cancel-modal-btn');
    ruleIdInput = document.getElementById('rule-id-input');
    ruleDescriptionInput = document.getElementById('rule-description');
    ruleIpInput = document.getElementById('rule-ip');
    ruleDirectionSelect = document.getElementById('rule-direction');
    ruleRateValueInput = document.getElementById('rule-rate-value');
    ruleRateUnitSelect = document.getElementById('rule-rate-unit');
    ruleBurstValueInput = document.getElementById('rule-burst-value');
    ruleBurstUnitSelect = document.getElementById('rule-burst-unit');
    ruleCBurstValueInput = document.getElementById('rule-cburst-value');
    ruleCBurstUnitSelect = document.getElementById('rule-cburst-unit');
    ruleGroupNameInput = document.getElementById('rule-group-name');
    ruleProtocolSelect = document.getElementById('rule-protocol');
    ruleSourcePortInput = document.getElementById('rule-source-port');
    ruleDestinationPortInput = document.getElementById('rule-destination-port');
    rulePriorityInput = document.getElementById('rule-priority');
    ruleIsEnabledCheckbox = document.getElementById('rule-is-enabled');
    enableSchedulingCheckbox = document.getElementById('enable-scheduling');
    schedulingOptionsDiv = document.getElementById('scheduling-options');
    ruleStartTimeInput = document.getElementById('rule-start-time');
    ruleEndTimeInput = document.getElementById('rule-end-time');
    ruleWeekdaysCheckboxes = document.querySelectorAll('#scheduling-options .weekdays-selector input[name="weekdays"]');
    ruleStartDateInput = document.getElementById('rule-start-date');
    ruleEndDateInput = document.getElementById('rule-end-date');
}

function setupEventListeners() {
    appLogger.info("Setting up event listeners...");
    queryGlobalDOMElements(); // Query all DOM elements needed

    // Attach event listeners only if elements exist
    if (interfaceSelect) interfaceSelect.addEventListener('change', handleInterfaceChange);
    else appLogger.error("DOM Element #interface not found for event listener.");

    if (searchInput) searchInput.addEventListener('input', handleSearch);
    else appLogger.error("DOM Element #search-input not found.");

    if (selectAllCheckbox) selectAllCheckbox.addEventListener('change', handleSelectAll);
    else appLogger.error("DOM Element #select-all not found.");

    if (addRuleBtn) addRuleBtn.addEventListener('click', () => openRuleModal());
    else appLogger.error("DOM Element #add-rule-btn not found.");
    
    if (addFirstRuleBtn) addFirstRuleBtn.addEventListener('click', () => openRuleModal());
    // else appLogger.warn("DOM Element #add-first-rule-btn not found (this is optional).");


    if (removeRulesBtn) removeRulesBtn.addEventListener('click', handleRemoveRules);
    else appLogger.error("DOM Element #remove-rules-btn not found.");

    if (enableRulesBtn) enableRulesBtn.addEventListener('click', handleEnableRules);
    else appLogger.error("DOM Element #enable-rules-btn not found.");

    // Modal related listeners
    if (ruleForm) ruleForm.addEventListener('submit', handleSaveRule);
    else appLogger.error("DOM Element #rule-form not found for submit listener.");

    if (closeModalBtn) closeModalBtn.addEventListener('click', () => { if (ruleModal) ruleModal.style.display = 'none'; });
    else appLogger.error("DOM Element #close-modal-btn not found.");
    
    if (cancelModalBtn) cancelModalBtn.addEventListener('click', () => { if (ruleModal) ruleModal.style.display = 'none'; });
    else appLogger.error("DOM Element #cancel-modal-btn not found.");
    
    if (enableSchedulingCheckbox) enableSchedulingCheckbox.addEventListener('change', toggleSchedulingOptions);
    else app.logger.warn("DOM Element #enable-scheduling for scheduling toggle not found (modal might not fully work).");


    window.addEventListener('click', (event) => { // Close modal if clicked outside
        if (ruleModal && event.target === ruleModal) {
            ruleModal.style.display = 'none';
        }
    });
    appLogger.info("Event listeners setup complete.");
}

async function init() {
    appLogger.info("Initializing Bandwidth Control UI (bandwidth-control.js)...");
    setupEventListeners(); // This now also queries all global DOM elements
    await fetchInterfacesAndSetActive(); // Fetches interfaces, sets active, then fetches rules and starts polling
    // renderRules() and updateButtonStates() are called within the above flow.
    appLogger.info("Initialization complete (bandwidth-control.js).");
}

document.addEventListener('DOMContentLoaded', init);