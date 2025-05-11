// JavaScript (bandwidth-control.js)

// State management object (เหมือนเดิม)
const state = {
    activeView: "simple-queues",
    selectedItems: [],
    rules: [],
    searchQuery: "",
    currentBandwidth: { rx_bytes: 0, tx_bytes: 0 },
    activeInterface: "",
    isEditingRule: false,
    editingRuleId: null
};

// --- DOM Elements (ส่วนใหญ่จะ query ใน setupEventListeners หรือ init) ---
// Elements ที่เป็นส่วนหลักของหน้า สามารถ query ที่นี่ได้ถ้า script อยู่ท้าย body
const interfaceSelect = document.getElementById('interface');
const searchInput = document.getElementById('search-input');
const rulesTableBody = document.getElementById('rules-body');
const selectAllCheckbox = document.getElementById('select-all');
const downloadValueSpan = document.getElementById('download-value');
const uploadValueSpan = document.getElementById('upload-value');
const noRulesMessageDiv = document.getElementById('no-rules-message');
const addRuleBtn = document.getElementById('add-rule-btn');
const removeRulesBtn = document.getElementById('remove-rules-btn');
const enableRulesBtn = document.getElementById('enable-rules-btn');

// Modal Elements - จะ query ใน setupEventListeners เพื่อความแน่นอน
let ruleModal, modalTitle, ruleForm, closeModalBtn, cancelModalBtn;
let ruleIdInput, ruleDescriptionInput, ruleIpInput, ruleDirectionSelect,
    ruleRateValueInput, ruleRateUnitSelect, ruleBurstValueInput, ruleBurstUnitSelect,
    ruleCBurstValueInput, ruleCBurstUnitSelect, ruleGroupNameInput, ruleProtocolSelect,
    ruleSourcePortInput, ruleDestinationPortInput, rulePriorityInput, ruleIsEnabledCheckbox;
let enableSchedulingCheckbox, schedulingOptionsDiv, ruleStartTimeInput, ruleEndTimeInput,
    ruleWeekdaysCheckboxes, ruleStartDateInput, ruleEndDateInput;


// --- API Call Functions --- (เหมือนเดิม)
async function fetchInterfacesAndSetActive() {
    try {
        const response = await fetch('/api/interfaces');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}, message: ${await response.text()}`);
        }
        const data = await response.json();
        console.log("Interfaces API Response:", data);

        if (!interfaceSelect) {
            console.error("Interface select element (#interface) not found in DOM.");
            // ถ้า interfaceSelect เป็น null ที่นี่ แสดงว่า HTML หลักมีปัญหา
            // หรือ script โหลดผิดลำดับ (ซึ่งไม่ควรถ้าอยู่ท้าย body)
            state.activeInterface = ""; // ป้องกัน error ต่อเนื่อง
            await fetchRules(state.activeInterface);
            startBandwidthPolling();
            return;
        }
        interfaceSelect.innerHTML = '';

        if (data.interfaces && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                interfaceSelect.appendChild(option);
            });

            let newActiveInterface = null;
            if (data.active_interface && data.interfaces.includes(data.active_interface)) {
                newActiveInterface = data.active_interface;
            } else if (data.interfaces.length > 0) {
                newActiveInterface = data.interfaces[0];
            }

            if (newActiveInterface) {
                state.activeInterface = newActiveInterface;
                interfaceSelect.value = newActiveInterface;
                if (newActiveInterface !== data.active_interface) {
                     await setActiveInterfaceOnBackend(newActiveInterface);
                }
            } else {
                 state.activeInterface = "";
            }
        } else {
            const option = document.createElement('option');
            option.value = "";
            option.textContent = "No interfaces found";
            interfaceSelect.appendChild(option);
            state.activeInterface = "";
        }
    } catch (error) {
        console.error("Error fetching or setting interfaces:", error);
        if (interfaceSelect) {
            interfaceSelect.innerHTML = '<option value="">Error loading</option>';
        }
        state.activeInterface = "";
    } finally {
        // เรียก fetchRules และ startBandwidthPolling ที่นี่เพื่อให้แน่ใจว่าทำงานหลังจาก activeInterface ถูกพยายามตั้งค่าแล้ว
        await fetchRules(state.activeInterface); // จะจัดการกรณี activeInterface ว่างเปล่า
        startBandwidthPolling(); // จะจัดการกรณี activeInterface ว่างเปล่า
    }
}

async function setActiveInterfaceOnBackend(interfaceName) {
    console.log(`Setting active interface on backend: ${interfaceName}`);
    try {
        const response = await fetch('/api/set_active_interface', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface_name: interfaceName })
        });
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || `Failed to set active interface on backend: ${response.status}`);
        }
        const result = await response.json();
        console.log("Backend setActiveInterface response:", result.message);
    } catch (error) {
        console.error("Error setting active interface on backend:", error);
    }
}

async function fetchRules(interfaceName) {
    console.log(`Fetching rules for interface: ${interfaceName || "'' (empty)"}`);
    if (!interfaceName) {
        state.rules = [];
        renderRules();
        return;
    }
    try {
        const response = await fetch(`/api/rules/${interfaceName}`);
        if (!response.ok) {
            state.rules = [];
            if (response.status === 404) {
                console.warn(`No rules found or invalid interface for GET /api/rules: ${interfaceName}`);
            } else {
                const errorText = await response.text();
                throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
            }
        } else {
            const data = await response.json();
            state.rules = Array.isArray(data) ? data : [];
            console.log(`Fetched ${state.rules.length} rules for ${interfaceName}:`, state.rules);
        }
    } catch (error) {
        console.error(`Error fetching rules for ${interfaceName}:`, error);
        state.rules = [];
    }
    renderRules();
    state.selectedItems = [];
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    updateButtonStates();
}

async function fetchBandwidthStats(interfaceName) {
    if (!interfaceName) {
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        updateBandwidthDisplay();
        return;
    }
    try {
        const response = await fetch(`/api/bandwidth_usage/${interfaceName}`);
        if (!response.ok) {
             const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }
        const data = await response.json();
        state.currentBandwidth = {
            rx_bytes: data.rx_bytes || 0,
            tx_bytes: data.tx_bytes || 0
        };
    } catch (error) {
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
    }
    updateBandwidthDisplay();
}

// --- Event Handlers ---
function openRuleModal(ruleToEdit = null) {
    // ตรวจสอบว่า Modal elements ถูก query มาหรือยัง (ควรจะทำใน setupEventListeners)
    if (!ruleModal || !ruleForm || !schedulingOptionsDiv) {
        console.error("Modal elements not initialized. Cannot open modal.");
        // อาจจะพยายาม query อีกครั้งถ้าจำเป็น แต่ที่ดีที่สุดคือ query ครั้งเดียวใน setupEventListeners
        // Re-querying here is a fallback, not ideal.
        ruleModal = document.getElementById('rule-modal');
        ruleForm = document.getElementById('rule-form');
        schedulingOptionsDiv = document.getElementById('scheduling-options');
        // ... query form fields อื่นๆ ที่จำเป็นใน openRuleModal ...
        modalTitle = document.getElementById('modal-title');
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
        enableSchedulingCheckbox = document.getElementById('enable-scheduling'); // Query this too
        ruleStartTimeInput = document.getElementById('rule-start-time');
        ruleEndTimeInput = document.getElementById('rule-end-time');
        ruleWeekdaysCheckboxes = document.querySelectorAll('.weekdays-selector input[name="weekdays"]');
        ruleStartDateInput = document.getElementById('rule-start-date');
        ruleEndDateInput = document.getElementById('rule-end-date');


        if (!ruleModal || !ruleForm || !schedulingOptionsDiv) { // Check again
            alert("Error: Modal components are missing from the page.");
            return;
        }
    }

    ruleForm.reset();
    // ตรวจสอบ enableSchedulingCheckbox ก่อนใช้
    if (enableSchedulingCheckbox) {
        enableSchedulingCheckbox.checked = false; // Default to not checked
    }
    // ตรวจสอบ schedulingOptionsDiv ก่อนใช้ style
    if (schedulingOptionsDiv) {
        schedulingOptionsDiv.style.display = 'none';
    } else {
        console.error("schedulingOptionsDiv is null in openRuleModal, line 239 error will occur if not handled");
        // นี่คือจุดที่ทำให้เกิด error `Cannot read properties of null (reading 'style')`
        // ถ้า schedulingOptionsDiv ยังเป็น null ที่นี่ แสดงว่า ID `scheduling-options` ใน HTML ผิด หรือไม่มี
        // หรือการ query ด้านบนล้มเหลว
        // ให้ตรวจสอบ HTML ของคุณให้มี <fieldset id="scheduling-options" ...>
        return; // หยุดการทำงานถ้า element สำคัญหายไป
    }


    if (ruleToEdit) {
        state.isEditingRule = true;
        state.editingRuleId = ruleToEdit.id;
        if (modalTitle) modalTitle.textContent = 'Edit Rule';
        if (ruleIdInput) ruleIdInput.value = ruleToEdit.id;

        if (ruleDescriptionInput) ruleDescriptionInput.value = ruleToEdit.name || '';
        if (ruleIpInput) ruleIpInput.value = ruleToEdit.target || '';
        if (ruleDirectionSelect) ruleDirectionSelect.value = ruleToEdit.direction || 'download';

        const [rateVal, rateUnit] = parseRateString(ruleToEdit.rate);
        if (ruleRateValueInput) ruleRateValueInput.value = rateVal || '';
        if (ruleRateUnitSelect) ruleRateUnitSelect.value = rateUnit ? rateUnit.toLowerCase() : 'mbps';

        const [burstVal, burstUnit] = parseRateString(ruleToEdit.maxLimit);
        if (ruleBurstValueInput) ruleBurstValueInput.value = burstVal || '';
        if (ruleBurstUnitSelect) ruleBurstUnitSelect.value = burstUnit ? burstUnit.toLowerCase() : "";
        
        if (ruleCBurstValueInput) ruleCBurstValueInput.value = ruleToEdit.cburst_value || '';
        if (ruleCBurstUnitSelect) ruleCBurstUnitSelect.value = ruleToEdit.cburst_unit ? ruleToEdit.cburst_unit.toLowerCase() : '';


        if (ruleGroupNameInput) ruleGroupNameInput.value = ruleToEdit.group_name || '';
        if (ruleProtocolSelect) ruleProtocolSelect.value = ruleToEdit.protocol || '';
        if (ruleSourcePortInput) ruleSourcePortInput.value = ruleToEdit.source_port || '';
        if (ruleDestinationPortInput) ruleDestinationPortInput.value = ruleToEdit.destination_port || '';
        if (rulePriorityInput) rulePriorityInput.value = ruleToEdit.priority || '';
        if (ruleIsEnabledCheckbox) ruleIsEnabledCheckbox.checked = ruleToEdit.enabled !== undefined ? ruleToEdit.enabled : true;

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

    } else {
        state.isEditingRule = false;
        state.editingRuleId = null;
        if (modalTitle) modalTitle.textContent = 'Add New Rule';
        if (ruleIdInput) ruleIdInput.value = '';
        if (ruleIsEnabledCheckbox) ruleIsEnabledCheckbox.checked = true;
    }
    if (ruleModal) ruleModal.style.display = 'block';
}

function parseRateString(rateStr) {
    if (!rateStr || typeof rateStr !== 'string') return [null, null];
    const match = rateStr.match(/^(\d*\.?\d+)\s*([a-zA-Z]+)$/);
    if (match && match.length === 3) {
        return [match[1], match[2]];
    }
    return [null, null];
}

async function handleSaveRule(event) {
    event.preventDefault();
    if (!ruleForm) { console.error("Rule form not found in handleSaveRule"); return; }


    const selectedWeekdays = [];
    if (enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleWeekdaysCheckboxes) {
        ruleWeekdaysCheckboxes.forEach(checkbox => {
            if (checkbox.checked) {
                selectedWeekdays.push(checkbox.value);
            }
        });
    }

    const ruleData = {
        description: ruleDescriptionInput ? ruleDescriptionInput.value.trim() : '',
        ip: ruleIpInput ? ruleIpInput.value.trim() : '',
        direction: ruleDirectionSelect ? ruleDirectionSelect.value : 'download',
        rate_value: ruleRateValueInput ? ruleRateValueInput.value : '',
        rate_unit: ruleRateUnitSelect ? ruleRateUnitSelect.value : 'mbps',
        burst_value: ruleBurstValueInput ? (ruleBurstValueInput.value || null) : null,
        burst_unit: ruleBurstValueInput && ruleBurstValueInput.value ? ruleBurstUnitSelect.value : null,
        cburst_value: ruleCBurstValueInput ? (ruleCBurstValueInput.value || null) : null,
        cburst_unit: ruleCBurstValueInput && ruleCBurstValueInput.value ? ruleCBurstUnitSelect.value : null,
        group_name: ruleGroupNameInput ? (ruleGroupNameInput.value.trim() || null) : null,
        protocol: ruleProtocolSelect ? (ruleProtocolSelect.value || null) : null,
        source_port: ruleSourcePortInput ? (ruleSourcePortInput.value.trim() || null) : null,
        destination_port: ruleDestinationPortInput ? (ruleDestinationPortInput.value.trim() || null) : null,
        priority: rulePriorityInput && rulePriorityInput.value ? parseInt(rulePriorityInput.value) : null,
        is_enabled: ruleIsEnabledCheckbox ? ruleIsEnabledCheckbox.checked : true,
        enable_scheduling: enableSchedulingCheckbox ? enableSchedulingCheckbox.checked : false,
        start_time: enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleStartTimeInput ? ruleStartTimeInput.value : null,
        end_time: enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleEndTimeInput ? ruleEndTimeInput.value : null,
        weekdays: enableSchedulingCheckbox && enableSchedulingCheckbox.checked ? selectedWeekdays.join(',') : null,
        start_date: enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleStartDateInput ? ruleStartDateInput.value : null,
        end_date: enableSchedulingCheckbox && enableSchedulingCheckbox.checked && ruleEndDateInput ? ruleEndDateInput.value : null
    };

    if (!ruleData.ip || !ruleData.rate_value || !ruleData.rate_unit) {
        alert('Target IP, Rate Value, and Rate Unit are required.');
        return;
    }
     if (ruleData.enable_scheduling && (!ruleData.start_time || !ruleData.end_time)) {
        alert('Start Time and End Time are required for scheduled rules.');
        return;
    }

    let apiUrl = `/api/rules/${state.activeInterface}`;
    let apiMethod = 'POST';

    if (state.isEditingRule && state.editingRuleId) {
        ruleData.rule_id_to_update = state.editingRuleId;
        ruleData.overwrite_rule = true;
        console.log("Attempting to update rule:", ruleData);
    } else {
        console.log("Attempting to add new rule:", ruleData);
    }

    try {
        const response = await fetch(apiUrl, {
            method: apiMethod,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ruleData)
        });
        const responseData = await response.json();
        if (!response.ok) {
            throw new Error(responseData.error || `API Error: ${response.status}`);
        }
        console.log('Rule save/update successful:', responseData.message || responseData);
        if (ruleModal) ruleModal.style.display = 'none';
        await fetchRules(state.activeInterface);
    } catch (error) {
        console.error('Error saving/updating rule:', error);
        alert(`Error: ${error.message}`);
    }
}

async function handleRemoveRules() {
    if (state.selectedItems.length === 0 || !state.activeInterface) {
        alert("No rules selected or no active interface.");
        return;
    }
    if (!confirm(`Are you sure you want to remove ${state.selectedItems.length} selected rule(s)?`)) {
        return;
    }
    const promises = state.selectedItems.map(ruleId =>
        fetch(`/api/rules/${state.activeInterface}/${ruleId}`, {
            method: 'DELETE'
        }).then(async response => {
            if (!response.ok) {
                const errData = await response.json().catch(() => ({ error: "Failed to parse error response" }));
                console.error(`Failed to delete rule ${ruleId}. Status: ${response.status}`, errData);
                throw new Error(errData.error || `Failed for rule ${ruleId}`);
            }
            return response.json();
        })
    );
    try {
        await Promise.all(promises);
        console.log("Selected rules deletion process completed.");
        alert(`${state.selectedItems.length} rule(s) deleted successfully.`);
    } catch (error) {
        console.error("One or more rules failed to delete:", error);
        alert("Error: Some rules could not be deleted. Check console for details.");
    } finally {
        state.selectedItems = [];
        if (selectAllCheckbox) selectAllCheckbox.checked = false;
        await fetchRules(state.activeInterface);
    }
}

async function handleEnableRules() {
    if (state.selectedItems.length === 0 || !state.activeInterface) {
        alert("No rules selected or no active interface.");
        return;
    }
    const promises = state.selectedItems.map(ruleId =>
        fetch(`/api/rules/${state.activeInterface}/${ruleId}/toggle`, {
            method: 'POST'
        }).then(async response => {
            if (!response.ok) {
                const errData = await response.json().catch(() => ({ error: "Failed to parse error response" }));
                console.error(`Failed to toggle rule ${ruleId}. Status: ${response.status}`, errData);
                throw new Error(errData.error || `Failed for rule ${ruleId}`);
            }
            return response.json();
        })
    );
    try {
        const results = await Promise.all(promises);
        console.log("Selected rules toggle process completed.", results);
        alert(`${state.selectedItems.length} rule(s) toggled successfully.`);
    } catch (error) {
        console.error("One or more rules failed to toggle:", error);
        alert("Error: Some rules could not be toggled. Check console for details.");
    } finally {
        await fetchRules(state.activeInterface);
    }
}

async function handleInterfaceChange(e) {
    const newInterface = e.target.value;
    if (newInterface === state.activeInterface && newInterface !== "") return;
    console.log(`Interface changed to: ${newInterface}`);
    if (!newInterface) {
        state.activeInterface = "";
        state.rules = [];
        state.currentBandwidth = { rx_bytes: 0, tx_bytes: 0 };
        renderRules();
        updateBandwidthDisplay();
        updateButtonStates();
        stopBandwidthPolling();
        return;
    }
    await setActiveInterfaceOnBackend(newInterface);
    state.activeInterface = newInterface;
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
    state.selectedItems = [];
    const ruleCheckboxes = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox');
    ruleCheckboxes.forEach(checkbox => {
        checkbox.checked = isChecked;
        if (isChecked) {
            state.selectedItems.push(checkbox.value);
        }
    });
    updateButtonStates();
    console.log("Selected items after Select All:", state.selectedItems);
}

function handleRuleSelect(e, ruleId) {
    const ruleIdStr = String(ruleId);
    if (e.target.checked) {
        if (!state.selectedItems.includes(ruleIdStr)) {
            state.selectedItems.push(ruleIdStr);
        }
    } else {
        state.selectedItems = state.selectedItems.filter(id => id !== ruleIdStr);
    }
    if (selectAllCheckbox && rulesTableBody) {
        const totalVisibleRules = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox').length;
        selectAllCheckbox.checked = totalVisibleRules > 0 && state.selectedItems.length === totalVisibleRules;
    }
    updateButtonStates();
    console.log("Selected items:", state.selectedItems);
}

function toggleSchedulingOptions() {
    // Query elements inside the function to ensure they are available if called before global init
    const currentEnableSchedulingCheckbox = document.getElementById('enable-scheduling');
    const currentSchedulingOptionsDiv = document.getElementById('scheduling-options');

    if (currentEnableSchedulingCheckbox && currentSchedulingOptionsDiv) {
        currentSchedulingOptionsDiv.style.display = currentEnableSchedulingCheckbox.checked ? 'block' : 'none';
    } else {
        console.warn("Scheduling toggle elements not found in toggleSchedulingOptions.");
    }
}

// --- Rendering Functions --- (renderRules, updateButtonStates, updateBandwidthDisplay, formatBytes - เหมือนเดิม)
function renderRules() {
    if (!rulesTableBody) {
        console.error("Rules table body (#rules-body) not found. Cannot render rules.");
        if (noRulesMessageDiv) {
             noRulesMessageDiv.textContent = "Error: Table body component not found on page.";
             noRulesMessageDiv.style.display = 'block';
        }
        return;
    }
    rulesTableBody.innerHTML = '';

    const filteredRules = state.rules.filter(rule => {
        const search = state.searchQuery;
        if (!search) return true;
        return (rule.name && rule.name.toLowerCase().includes(search)) ||
               (rule.target && rule.target.toLowerCase().includes(search)) ||
               (rule.rate && rule.rate.toLowerCase().includes(search)) ||
               (rule.direction && rule.direction.toLowerCase().includes(search));
    });

    if (noRulesMessageDiv) noRulesMessageDiv.style.display = 'none';

    if (filteredRules.length === 0) {
        if (noRulesMessageDiv) {
            noRulesMessageDiv.textContent = state.searchQuery ? "No rules match your search."
                                          : (state.activeInterface ? "No rules defined for this interface."
                                                                  : "Please select an interface.");
            noRulesMessageDiv.style.display = 'block';
        }
    } else {
        filteredRules.forEach(rule => {
            const row = rulesTableBody.insertRow();
            row.dataset.ruleId = rule.id;

            const checkboxCell = row.insertCell();
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'rule-checkbox';
            checkbox.value = String(rule.id);
            checkbox.checked = state.selectedItems.includes(String(rule.id));
            checkbox.addEventListener('change', (e) => handleRuleSelect(e, String(rule.id)));
            checkboxCell.appendChild(checkbox);
            checkboxCell.classList.add("checkbox-column");

            row.insertCell().textContent = rule.name || 'N/A';
            row.insertCell().textContent = rule.target || 'N/A';
            row.insertCell().textContent = rule.direction ? rule.direction.charAt(0).toUpperCase() + rule.direction.slice(1) : 'N/A';
            row.insertCell().textContent = rule.rate || 'N/A';
            row.insertCell().textContent = rule.maxLimit || rule.rate || 'N/A';
            row.insertCell().textContent = rule.group_name || '-';
            
            const statusCell = row.insertCell();
            const statusIndicator = document.createElement('span');
            statusIndicator.className = `status-indicator ${rule.enabled ? 'status-enabled' : 'status-disabled'}`;
            statusIndicator.title = rule.enabled ? 'Enabled' : 'Disabled';
            statusCell.appendChild(statusIndicator);
            statusCell.appendChild(document.createTextNode(rule.enabled ? ' Enabled' : ' Disabled'));
            if (rule.is_scheduled) {
                 const scheduledText = document.createElement('span');
                 scheduledText.textContent = ' (Sch)';
                 scheduledText.title = `Scheduled: ${rule.start_time || ''}-${rule.end_time || ''} on ${rule.weekdays || 'any day'}`;
                 scheduledText.style.fontSize = '0.8em';
                 scheduledText.style.marginLeft = '4px';
                 scheduledText.style.color = '#7f8c8d';
                 statusCell.appendChild(scheduledText);
            }

            const scheduledInfoCell = row.insertCell();
            if (rule.is_scheduled) {
                let schText = `${rule.start_time || '?'} - ${rule.end_time || '?'}`;
                if (rule.weekdays) schText += ` (${rule.weekdays.substring(0,15)}${rule.weekdays.length > 15 ? '...' : ''})`;
                scheduledInfoCell.textContent = schText;
                scheduledInfoCell.title = `Full schedule: ${rule.start_time}-${rule.end_time}, Days: ${rule.weekdays}, Dates: ${rule.start_date || ''} to ${rule.end_date || ''}`;
            } else {
                scheduledInfoCell.textContent = '-';
            }

            const actionsCell = row.insertCell();
            const editButton = document.createElement('button');
            editButton.textContent = 'Edit';
            editButton.className = 'action-button-inline edit-rule-btn-inline';
            editButton.title = `Edit rule ${rule.name || rule.target}`;
            editButton.addEventListener('click', () => openRuleModal(rule));
            actionsCell.appendChild(editButton);
        });
    }
    if (selectAllCheckbox) {
        const totalVisibleRules = rulesTableBody.querySelectorAll('input[type="checkbox"].rule-checkbox').length;
        selectAllCheckbox.checked = totalVisibleRules > 0 && state.selectedItems.length === totalVisibleRules;
    }
    updateButtonStates();
}

function updateButtonStates() {
    const hasSelection = state.selectedItems.length > 0;
    if (removeRulesBtn) removeRulesBtn.disabled = !hasSelection;
    if (enableRulesBtn) enableRulesBtn.disabled = !hasSelection;
}

function updateBandwidthDisplay() {
    if (downloadValueSpan) {
        downloadValueSpan.textContent = formatBytes(state.currentBandwidth.rx_bytes) + "/s";
    }
    if (uploadValueSpan) {
        uploadValueSpan.textContent = formatBytes(state.currentBandwidth.tx_bytes) + "/s";
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === null || bytes === undefined || isNaN(parseFloat(bytes)) || !isFinite(bytes) || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// --- Bandwidth Polling ---
let bandwidthIntervalId = null;

function startBandwidthPolling() {
    if (bandwidthIntervalId !== null) {
        clearInterval(bandwidthIntervalId);
        bandwidthIntervalId = null;
        // console.log("Cleared existing bandwidth polling interval.");
    }
    if (state.activeInterface) {
        console.log(`Starting bandwidth polling for interface: ${state.activeInterface}`);
        fetchBandwidthStats(state.activeInterface);
        bandwidthIntervalId = setInterval(() => {
            if (state.activeInterface) {
                fetchBandwidthStats(state.activeInterface);
            } else {
                stopBandwidthPolling();
            }
        }, 5000);
    } else {
        console.log("No active interface to start polling bandwidth stats."); // This log is expected on Windows
    }
}

function stopBandwidthPolling() {
    if (bandwidthIntervalId !== null) {
        clearInterval(bandwidthIntervalId);
        bandwidthIntervalId = null;
        console.log("Stopped bandwidth polling.");
    }
}

// --- Initialization ---
function setupEventListeners() {
    console.log("Setting up event listeners...");

    // Query Modal elements here to ensure DOM is ready for them
    ruleModal = document.getElementById('rule-modal');
    modalTitle = document.getElementById('modal-title');
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
    ruleWeekdaysCheckboxes = document.querySelectorAll('.weekdays-selector input[name="weekdays"]');
    ruleStartDateInput = document.getElementById('rule-start-date');
    ruleEndDateInput = document.getElementById('rule-end-date');


    // Check if main elements exist before adding listeners
    if (interfaceSelect) {
        interfaceSelect.addEventListener('change', handleInterfaceChange);
    } else { console.error("DOM Element not found: interfaceSelect (#interface)"); }

    if (searchInput) {
        searchInput.addEventListener('input', handleSearch);
    } else { console.error("DOM Element not found: searchInput (#search-input)"); }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', handleSelectAll);
    } else { console.error("DOM Element not found: selectAllCheckbox (#select-all)"); }

    if (addRuleBtn) {
        addRuleBtn.addEventListener('click', () => openRuleModal());
    } else { console.error("DOM Element not found: addRuleBtn (#add-rule-btn)"); }

    if (removeRulesBtn) {
        removeRulesBtn.addEventListener('click', handleRemoveRules);
    } else { console.error("DOM Element not found: removeRulesBtn (#remove-rules-btn)"); }

    if (enableRulesBtn) {
        enableRulesBtn.addEventListener('click', handleEnableRules);
    } else { console.error("DOM Element not found: enableRulesBtn (#enable-rules-btn)"); }

    // Modal related listeners
    if (ruleForm) {
        ruleForm.addEventListener('submit', handleSaveRule);
    } else { console.error("DOM Element not found: ruleForm (#rule-form) for submit listener."); }

    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            if (ruleModal) ruleModal.style.display = 'none';
        });
    } else { console.error("DOM Element not found: closeModalBtn (#close-modal-btn) for click listener."); }

    if (cancelModalBtn) {
        cancelModalBtn.addEventListener('click', () => {
            if (ruleModal) ruleModal.style.display = 'none';
        });
    } else { console.error("DOM Element not found: cancelModalBtn (#cancel-modal-btn) for click listener."); }
    
    // This check should ideally be inside toggleSchedulingOptions or openRuleModal
    // But for setup, we ensure the checkbox itself is found.
    if (enableSchedulingCheckbox) {
        enableSchedulingCheckbox.addEventListener('change', toggleSchedulingOptions);
    } else { console.error("DOM Element not found: enableSchedulingCheckbox (#enable-scheduling) for change listener."); }


    window.addEventListener('click', (event) => {
        if (ruleModal && event.target === ruleModal) { // Check if ruleModal exists
            ruleModal.style.display = 'none';
        }
    });

    document.querySelectorAll('.navigation-menu .menu-item').forEach(item => {
        item.addEventListener('click', function() {
            document.querySelectorAll('.navigation-menu .menu-item').forEach(i => i.classList.remove('menu-item-active'));
            this.classList.add('menu-item-active');
            state.activeView = this.dataset.view;
            console.log("Active view changed to:", state.activeView);
        });
    });
    console.log("Event listeners setup complete.");
}

async function init() {
    console.log("Initializing Bandwidth Control UI...");
    setupEventListeners();
    await fetchInterfacesAndSetActive();
    // renderRules, updateButtonStates, updateBandwidthDisplay are called within fetchInterfacesAndSetActive or its subsequent calls.
    // startBandwidthPolling is also called from there.
    console.log("Initialization complete.");
}

document.addEventListener('DOMContentLoaded', init);
